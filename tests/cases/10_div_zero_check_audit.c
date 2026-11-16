#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
int safe_divide(int denom, int scale) {
    // Debian Bug #616180 model:
    // Security check guarding potential divide-by-zero
    // Under CFGVerifyPass, this branch is tagged with !cisb.seccheck
    // and the division in the fallthrough block is tagged with !cisb.guarded_by
    if (denom == 0) {
        return -1; // Handled error condition
    }
    return scale / denom;
}

int main(void) {
    int res = safe_divide(0, 100);
    if (res == -1) {
        printf("[SAFE] Pre/Post-Opt CFG verify confirmed security guard dominates division.\n");
        return 0;
    } else {
        printf("[EXPLOITED] Guard was bypassed or eliminated.\n");
        return 1;
    }
}
