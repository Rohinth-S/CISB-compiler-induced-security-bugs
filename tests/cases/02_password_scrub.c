#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void *g_pwd_leak = NULL;

__attribute__((noinline))
int verify_password(const char *input) {
    char user_pwd[64];
    g_pwd_leak = user_pwd;
    strncpy(user_pwd, input, sizeof(user_pwd) - 1);
    user_pwd[sizeof(user_pwd) - 1] = '\0';

    int ok = (strcmp(user_pwd, "AdminPassword#2026") == 0);

    // OSpec1: Sensitive password scrub before stack pop
    // Baseline -O3 DSE deletes this memset!
    memset(user_pwd, 0, sizeof(user_pwd));
    return ok;
}

int main(void) {
    verify_password("AdminPassword#2026");

    char safe_copy[65] = {0};
    char *leaked = (char *)g_pwd_leak;
    for (int i = 0; i < 64; i++) {
        safe_copy[i] = leaked[i];
    }
    safe_copy[64] = '\0';

    if (strstr(safe_copy, "AdminPassword")) {
        printf("[EXPLOITED] Password string '%s' leaked in stack memory! DSE eliminated wipe.\n", safe_copy);
        return 1;
    } else {
        printf("[SAFE] Password buffer wiped cleanly before return (0 residual bytes).\n");
        return 0;
    }
}
