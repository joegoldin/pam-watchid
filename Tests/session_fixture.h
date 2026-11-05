#ifndef PAM_WATCHID_SESSION_FIXTURE_H
#define PAM_WATCHID_SESSION_FIXTURE_H

#include <bsm/audit.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>

uid_t watchid_test_getuid(void);
int watchid_test_getaudit_addr(auditinfo_addr_t *info, int size);
int watchid_test_stat(const char *path, struct stat *info);
void *watchid_test_dlopen(const char *path, int flags);

#ifndef WATCHID_FIXTURE_IMPLEMENTATION
#define getuid() watchid_test_getuid()
#define getaudit_addr(...) watchid_test_getaudit_addr(__VA_ARGS__)
#define stat(...) watchid_test_stat(__VA_ARGS__)
#define dlopen(...) watchid_test_dlopen(__VA_ARGS__)
#endif

#endif
