import LocalAuthentication
import ObjectiveC
import PAMSupport

// MARK: (Re)define PAM constants here so we don't need to import .h files.

private let PAM_SUCCESS = CInt(0)
private let PAM_AUTH_ERR = CInt(9)
private let PAM_IGNORE = CInt(25)
private let PAM_SILENT = CInt(bitPattern: 0x80000000)

public typealias vchar = UnsafePointer<UnsafeMutablePointer<CChar>>
public typealias pam_handle_t = UnsafeRawPointer?

private final class AuthenticationReply {
    let semaphore = DispatchSemaphore(value: 0)
    let deadline = DispatchTime.now() + .seconds(5)
    private let lock = NSLock()
    private var status: CInt?

    func receive(_ value: CInt) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard status == nil else { return false }
        status = DispatchTime.now() < deadline ? value : PAM_IGNORE
        semaphore.signal()
        return true
    }

    func result(timedOut: Bool) -> CInt {
        lock.lock()
        defer { lock.unlock() }
        // Seal before invalidate(): late or duplicate replies cannot authorize
        // a transaction that has already fallen through to password.
        if timedOut { status = PAM_IGNORE }
        return status ?? PAM_IGNORE
    }
}

private func bindUser(_ uid: UInt32, to context: LAContext) -> Bool {
    let setter = NSSelectorFromString("setOptionUserId:")
    let getter = NSSelectorFromString("optionUserId")
    guard context.responds(to: setter), context.responds(to: getter),
          let setMethod = class_getInstanceMethod(type(of: context), setter),
          let getMethod = class_getInstanceMethod(type(of: context), getter),
          method_getNumberOfArguments(setMethod) == 3,
          method_getNumberOfArguments(getMethod) == 2 else {
        return false
    }
    guard let argument = method_copyArgumentType(setMethod, 2) else { return false }
    defer { free(argument) }
    let setReturn = method_copyReturnType(setMethod)
    defer { free(setReturn) }
    let getReturn = method_copyReturnType(getMethod)
    defer { free(getReturn) }
    guard String(cString: argument).hasPrefix("@"),
          String(cString: setReturn) == "v",
          String(cString: getReturn).hasPrefix("@") else {
        return false
    }

    // Apple's pam_tid supplies this private user-ID option. Checking our PAM
    // caller alone does not bind root's LAContext to that user's fingerprints.
    // Feature-detect the object-valued accessor rather than guessing SPI keys.
    let expected = NSNumber(value: uid)
    context.setValue(expected, forKey: "optionUserId")
    return (context.value(forKey: "optionUserId") as? NSNumber) == expected
}

// MARK: UID-bound Touch ID and Watch authentication

@_cdecl("pam_sm_authenticate")
public func pam_sm_authenticate(pamh: pam_handle_t, flags: CInt, argc: CInt, argv: vchar) -> CInt {
    let sudoArguments = ProcessInfo.processInfo.arguments
    if sudoArguments.contains("-A") || sudoArguments.contains("--askpass") {
        return PAM_IGNORE
    }
    var uid: UInt32 = 0
    guard watchid_session_user(pamh, &uid) != 0,
          watchid_pin_module() != 0 else {
        return PAM_IGNORE
    }

    let context = LAContext()
    defer { context.invalidate() }
    guard bindUser(uid, to: context) else { return PAM_IGNORE }
    context.touchIDAuthenticationAllowableReuseDuration = 0
    let policy = LAPolicy.biometricsOrWatch
    guard context.canEvaluatePolicy(policy, error: nil) else { return PAM_IGNORE }

    let reply = AuthenticationReply()
    context.evaluatePolicy(policy, localizedReason: "authenticate sudo") { success, error in
        let result = error != nil ? PAM_IGNORE : (success ? PAM_SUCCESS : PAM_AUTH_ERR)
        if reply.receive(result), let error = error, flags & PAM_SILENT == 0 {
            fputs("\(error.localizedDescription)\n", stderr)
        }
    }
    let timedOut = reply.semaphore.wait(timeout: reply.deadline) == .timedOut
    let result = reply.result(timedOut: timedOut)
    if result == PAM_SUCCESS && watchid_session_matches_pam_user(pamh) == 0 {
        return PAM_IGNORE
    }
    return result
}

private extension LAPolicy {
    static var biometricsOrWatch: LAPolicy {
#if canImport(CoreHID)
        if #available(macOS 15, *) {
            return .deviceOwnerAuthenticationWithBiometricsOrCompanion
        } else {
            return .deviceOwnerAuthenticationWithBiometricsOrWatch
        }
#else
        return .deviceOwnerAuthenticationWithBiometricsOrWatch
#endif
    }
}

// MARK: - Ignored (unhandled) PAM events

@_cdecl("pam_sm_chauthtok")
public func pam_sm_chauthtok(pamh: pam_handle_t, flags: CInt, argc: CInt, argv: vchar) -> CInt {
    return PAM_IGNORE
}

@_cdecl("pam_sm_setcred")
public func pam_sm_setcred(pamh: pam_handle_t, flags: CInt, argc: CInt, argv: vchar) -> CInt {
    return PAM_IGNORE
}

@_cdecl("pam_sm_acct_mgmt")
public func pam_sm_acct_mgmt(pamh: pam_handle_t, flags: CInt, argc: CInt, argv: vchar) -> CInt {
    return PAM_IGNORE
}
