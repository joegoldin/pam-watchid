#ifndef PAM_WATCHID_SUPPORT_H
#define PAM_WATCHID_SUPPORT_H

#include <stdint.h>

int watchid_session_user(const void *handle, uint32_t *uid);
int watchid_session_matches_pam_user(const void *handle);
int watchid_pin_module(void);

#endif
