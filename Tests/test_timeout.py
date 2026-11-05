#!/usr/bin/env python3
"""Test the real PAM entry point without changing PAM policy or displaying UI.

Only LocalAuthentication and OS session observations are simulated. PAM handles,
user lookup, module loading, deadlines and cancellation run real code.
"""

import ctypes
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent

MOCK = r'''
@_exported import Foundation

public enum LAPolicy {
    case deviceOwnerAuthenticationWithBiometricsOrWatch
    case deviceOwnerAuthenticationWithBiometricsOrCompanion
}

public class LAContext {
    public init() {}
    private var reply: ((Bool, Error?) -> Void)?
    public func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        return ProcessInfo.processInfo.environment["AUTH_TEST"] != "unavailable"
    }
    public func evaluatePolicy(_ policy: LAPolicy, localizedReason: String,
                               reply: @escaping (Bool, Error?) -> Void) {
        print("evaluated")
        self.reply = reply
        switch ProcessInfo.processInfo.environment["AUTH_TEST"] {
        case "success": reply(true, nil)
        case "failure": reply(false, nil)
        case "error": reply(false, NSError(domain: "test", code: 1))
        case "inconsistent-success": reply(true, NSError(domain: "test", code: 1))
        case "late-success":
            DispatchQueue.global().asyncAfter(deadline: .now() + 6) {
                reply(true, nil)
            }
        default: break
        }
    }
    public func invalidate() {
        print("invalidated")
        if ProcessInfo.processInfo.environment["AUTH_TEST"] == "cancel-reply" {
            reply?(false, NSError(domain: "cancel", code: 1))
        }
    }
}
'''


def invoke(library_path):
    # Each call gets its own process so Foundation's process environment and
    # the fixture counters cannot leak between cases.
    import _ctypes

    pam = ctypes.CDLL('/usr/lib/libpam.2.dylib')
    pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                              ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_set_data.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
                                 ctypes.c_void_p]
    pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    handle = ctypes.c_void_p()
    user = os.environ.get('PAM_TEST_USER', pwd.getpwuid(os.getuid()).pw_name)
    service = os.environ.get('PAM_TEST_SERVICE', 'sudo')
    status = pam.pam_start(service.encode(), user.encode(), None, ctypes.byref(handle))
    assert status == 0, f'pam_start failed: {status}'
    if os.environ.get('PAM_TEST_ASKPASS'):
        assert pam.pam_set_data(handle, b'askpass-enabled', ctypes.c_void_p(1), None) == 0
    library = ctypes.CDLL(library_path)
    auth = library.pam_sm_authenticate
    auth.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                     ctypes.POINTER(ctypes.c_char_p)]
    auth.restype = ctypes.c_int
    arguments = (ctypes.c_char_p * 1)(b'unused')
    start = time.monotonic()
    try:
        result = auth(handle, -(2**31), 0, arguments)
        print(f'result={result}', flush=True)
        print(f'elapsed={time.monotonic() - start}', flush=True)
    finally:
        pam.pam_end(handle, 0)
    if os.environ.get('AUTH_TEST') == 'late-success':
        _ctypes.dlclose(library._handle)
        time.sleep(2)
        print('survived late reply after pam_end and dlclose', flush=True)


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        temporary = Path(cls.directory.name)
        (temporary / 'LocalAuthentication.swift').write_text(MOCK)
        subprocess.run([
            'swiftc', '-emit-library', '-emit-module', '-module-name',
            'LocalAuthentication', str(temporary / 'LocalAuthentication.swift'),
            '-o', str(temporary / 'libLocalAuthentication.dylib'),
        ], check=True)
        arguments = []
        support = ROOT / 'Sources/PAMSupport'
        if support.exists():
            obj = temporary / 'support.o'
            subprocess.run([
                'clang', '-Wall', '-Wextra', '-Werror', '-c', '-fPIC',
                '-I', str(support / 'include'), '-include', str(ROOT / 'Tests/session_fixture.h'),
                str(support / 'support.c'), '-o', str(obj),
            ], check=True)
            fixture = temporary / 'fixture.o'
            subprocess.run([
                'clang', '-Wall', '-Wextra', '-Werror', '-c', '-fPIC',
                str(ROOT / 'Tests/session_fixture.c'), '-o', str(fixture),
            ], check=True)
            arguments = ['-I', str(support / 'include'), str(obj), str(fixture), '-lpam', '-lbsm']
        cls.library = temporary / 'test-pam.dylib'
        subprocess.run([
            'swiftc', '-emit-library', '-I', str(temporary), '-L', str(temporary),
            '-lLocalAuthentication', '-Xlinker', '-rpath', '-Xlinker', str(temporary),
            str(ROOT / 'Sources/pam-watchid/pam_watchid.swift'), *arguments,
            '-o', str(cls.library),
        ], check=True)

    def authenticate(self, mode='success', expected=25, timed_out=False, **environment):
        try:
            result = subprocess.run(
                [sys.executable, __file__, '--invoke', str(self.library)],
                capture_output=True, text=True,
                env={**os.environ, 'AUTH_TEST': mode, **environment}, timeout=10,
            )
        except subprocess.TimeoutExpired:
            self.fail('PAM did not return within 10 seconds for ' + mode)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'result={expected}\n', result.stdout)
        elapsed = float(next(line.split('=', 1)[1] for line in
                             result.stdout.splitlines() if line.startswith('elapsed=')))
        if timed_out:
            self.assertGreaterEqual(elapsed, 4.5)
            self.assertLess(elapsed, 8)
            self.assertIn('invalidated', result.stdout)
        else:
            self.assertLess(elapsed, 2)
        return result.stdout

    def assert_skipped(self, **environment):
        output = self.authenticate(**environment)
        self.assertNotIn('evaluated', output)

    def test_unanswered_prompt_falls_through(self):
        self.authenticate('no-reply', timed_out=True)

    def test_success_authenticates_matching_user(self):
        self.authenticate(expected=0)

    def test_different_pam_user_cannot_authenticate(self):
        self.assert_skipped(PAM_TEST_USER='root')

    def test_unknown_pam_user_cannot_authenticate(self):
        self.assert_skipped(PAM_TEST_USER='watchid-user-that-does-not-exist')

    def test_real_uid_mismatch_cannot_authenticate(self):
        self.assert_skipped(SESSION_TEST='real-mismatch')

    def test_root_authenticator_can_authenticate_matching_session_user(self):
        self.authenticate(expected=0, SESSION_TEST='root-authenticator')

    def test_non_graphical_session_cannot_authenticate(self):
        self.assert_skipped(SESSION_TEST='non-graphical')

    def test_audit_uid_mismatch_cannot_authenticate(self):
        self.assert_skipped(SESSION_TEST='audit-mismatch')

    def test_console_uid_mismatch_cannot_authenticate(self):
        self.assert_skipped(SESSION_TEST='console-mismatch')

    def test_audit_failure_cannot_authenticate(self):
        self.assert_skipped(SESSION_TEST='audit-error')

    def test_console_failure_cannot_authenticate(self):
        self.assert_skipped(SESSION_TEST='console-error')

    def test_module_pin_failure_cannot_authenticate(self):
        self.assert_skipped(SESSION_TEST='pin-error')

    def test_askpass_skips_biometrics(self):
        self.assert_skipped(PAM_TEST_ASKPASS='1')

    def test_other_pam_service_skips_biometrics(self):
        self.assert_skipped(PAM_TEST_SERVICE='login')

    def test_console_switch_during_authentication_falls_through(self):
        self.authenticate(SESSION_TEST='console-switch')

    def test_rejected_authentication_fails(self):
        self.authenticate('failure', expected=9)

    def test_error_falls_through(self):
        self.authenticate('error')

    def test_inconsistent_success_with_error_falls_through(self):
        self.authenticate('inconsistent-success')

    def test_unavailable_biometrics_falls_through(self):
        self.authenticate('unavailable')

    def test_cancellation_callback_cannot_authenticate(self):
        self.authenticate('cancel-reply', timed_out=True)

    def test_late_success_after_pam_end_and_dlclose_cannot_authenticate(self):
        output = self.authenticate('late-success', timed_out=True)
        self.assertIn('survived late reply after pam_end and dlclose', output)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--invoke':
        invoke(sys.argv[2])
    else:
        unittest.main()
