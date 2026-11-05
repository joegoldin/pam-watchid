#include "PAMSupport.h"

#include <bsm/audit.h>
#include <dlfcn.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int watchid_session_matches_pam_user(const void *handle)
{
    const pam_handle_t *pamh = handle;
    const void *item = NULL;
    const void *askpass = NULL;
    struct passwd account, *found = NULL;
    struct stat console;
    auditinfo_addr_t audit;
    uid_t real_uid = getuid();
    char buffer[16384];

    if (pamh == NULL)
        return 0;

    // A GUI approval must not replace the caller's requested askpass flow.
    if (pam_get_data(pamh, "askpass-enabled", &askpass) != PAM_NO_MODULE_DATA)
        return 0;
    if (pam_get_item(pamh, PAM_SERVICE, &item) != PAM_SUCCESS || item == NULL ||
        (strcmp(item, "sudo") != 0 && strcmp(item, "sudo-i") != 0))
        return 0;
    if (pam_get_item(pamh, PAM_USER, &item) != PAM_SUCCESS || item == NULL)
        return 0;

    // Public LocalAuthentication authenticates the session's device owner,
    // not an arbitrary PAM_USER. Any uncertainty must leave password auth in
    // charge, including an oversized directory-service record (ERANGE).
    // sudo may become real-UID root before calling PAM. The immutable audit
    // identity below, not root's process UID, binds that call to its user.
    if (getpwnam_r(item, &account, buffer, sizeof(buffer), &found) != 0 ||
        found == NULL || account.pw_uid == 0 ||
        (real_uid != 0 && account.pw_uid != real_uid))
        return 0;
    if (getaudit_addr(&audit, sizeof(audit)) != 0 ||
        audit.ai_auid != account.pw_uid ||
        !(audit.ai_flags & AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS))
        return 0;
    if (stat("/dev/console", &console) != 0 || console.st_uid != account.pw_uid)
        return 0;
    return 1;
}

int watchid_pin_module(void)
{
    Dl_info info;
    void *handle;

    // invalidate() delivers its reply asynchronously. PAM may dlclose us as
    // soon as authentication returns; keep callback code mapped until exit.
    if (dladdr((const void *)&watchid_pin_module, &info) == 0)
        return 0;
    handle = dlopen(info.dli_fname, RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE);
    if (handle == NULL)
        return 0;
    dlclose(handle);
    return 1;
}
