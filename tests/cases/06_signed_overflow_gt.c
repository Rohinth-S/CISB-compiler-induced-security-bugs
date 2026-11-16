#include <stdio.h>
#include <limits.h>

__attribute__((noinline))
int check_overflow_gt(int a) {
    // CISBFuzz Figure 4:
    // Developer writes: proceed only if (a + 10 > a) to ensure no wraparound
    // Under No-UB assumption, -O3 folds this condition to TRUE for all inputs!
    if (a + 10 > a) {
        return 1; // Success/proceed
    }
    return 0; // Overflow occurred
}

int main(void) {
    int test_val = INT_MAX - 5;
    // For a = INT_MAX - 5, adding 10 wraps to negative on hardware.
    // If the check was deleted by -O3, it returns 1 (proceeds despite overflow).
    int res = check_overflow_gt(test_val);

    if (res == 1) {
        printf("[EXPLOITED] Clang -O3 assumed signed overflow impossible and folded check to true (overflow bypass)!\n");
        return 1;
    } else {
        printf("[SAFE] Overflow guarded cleanly via checked arithmetic.\n");
        return 0;
    }
}
