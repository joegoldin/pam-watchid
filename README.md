# pam-watchid

A Swift PAM module for Touch ID or Apple Watch authentication of the local
console user running sudo, with one shared five-second authentication window.

This fork adds explicit user binding and deadline handling to
[upstream pam-watchid](https://github.com/mostpinkest/pam-watchid). The UID-bound
backend needs live validation on each supported macOS version; passing the
automated tests alone does not establish that both methods are offered.

## Authentication

Before presenting UI, the module verifies that the non-root PAM account matches
the process's audit identity and console owner, and that the audit session has
graphical access. Only the `sudo` and `sudo-i` PAM services are accepted. Askpass
requests and uncertain identity checks fall through to the remaining PAM stack.

Apple's `pam_tid` passes a private user-ID option to LocalAuthentication. This
fork uses the corresponding `LAContext.optionUserId` accessor to bind the
verified PAM UID explicitly, including when sudo has become real-UID root.
It checks that the accessor exists, has the expected Objective-C signature,
and returns the UID that was set. Unsupported or rejected binding falls through
without requesting authentication. This is private API and may change with macOS.

One fresh context requests the combined biometric/Watch policy, with Touch ID
reuse disabled. An unanswered request is invalidated after five seconds. The
result is sealed before invalidation so late or duplicate callbacks cannot
change a completed PAM transaction. Successful authentication is followed by
another identity check. The module is kept mapped until process exit because
cancellation callbacks can outlive the PAM handle.

The module does not patch Apple's binaries, change authorization-database rules,
clear shared authorization credentials, or disable macOS protections.

## Build and test

Xcode or the matching command-line tools are required.

```fish
swift build -c release
python3 Tests/test_timeout.py
```

The automated suite calls the real PAM entry point with real Apple PAM handles.
It substitutes the UI service and session observations to exercise user binding,
identity mismatches, deadlines, cancellation, and callbacks after `pam_end` and
`dlclose`. Live tests must separately verify Touch ID, Watch, and unattended
password fallback.

## Installation

This fork is consumed by the `pam-watchid-src` input in
[joegoldin/dotfiles](https://github.com/joegoldin/dotfiles), with an explicit Nix
package override. The ordinary nixpkgs package does not automatically use this
fork. In that dotfiles checkout, update the pinned revision with:

```fish
nix flake update pam-watchid-src
```

Keep the module `sufficient` and preserve the following password-authentication
rules. Do not enable the stock Touch ID module ahead of it: that would introduce
another authentication request outside the shared deadline.

The inherited `install.sh` downloads upstream code, not this fork's hardened
build. Do not use that script to install this fork.
