#define WATCHID_FIXTURE_IMPLEMENTATION
#include "session_fixture.h"

#include <stdlib.h>
#include <string.h>

static int mode(const char *expected)
{
    const char *value = getenv("SESSION_TEST");
    return value != NULL && strcmp(value, expected) == 0;
}

uid_t watchid_test_getuid(void)
{
    return mode("root-authenticator") ? 0 : getuid() + mode("real-mismatch");
}

int watchid_test_getaudit_addr(auditinfo_addr_t *info, int size)
{
    if (mode("audit-error") || size != sizeof(*info))
        return -1;
    memset(info, 0, sizeof(*info));
    info->ai_auid = getuid() + mode("audit-mismatch");
    if (!mode("non-graphical"))
        info->ai_flags = AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS;
    return 0;
}

int watchid_test_stat(const char *path, struct stat *info)
{
    static int observations;
    observations++;
    if (mode("console-error") || strcmp(path, "/dev/console") != 0)
        return -1;
    memset(info, 0, sizeof(*info));
    info->st_uid = getuid() + mode("console-mismatch") +
        (mode("console-switch") && observations > 1);
    return 0;
}

void *watchid_test_dlopen(const char *path, int flags)
{
    return mode("pin-error") ? NULL : dlopen(path, flags);
}
