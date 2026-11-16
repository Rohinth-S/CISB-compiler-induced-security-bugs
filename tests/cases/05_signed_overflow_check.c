#include <stdio.h>
#include <limits.h>

__attribute__((noinline))
int check_buffer_offset(int offset) {
    // Under standard C (No-UB assumption), signed overflow is undefined.
    // Clang -O3 infers (offset + 100 > offset) is ALWAYS TRUE.
    // Therefore the defensive check (offset + 100 < offset) is deleted!
    if (offset + 100 < offset) {
        return -1; // Blocked: integer wrapping detected
    }
    return 0; // Allowed
}

int main(void) {
    int input_val = INT_MAX - 10;
    int res = check_buffer_offset(input_val);

    if (res == 0) {
        printf("[EXPLOITED] Signed integer overflow check was eliminated by -O3 optimizer!\n");
        return 1;
    } else {
        printf("[SAFE] Bound check preserved via safe checked arithmetic.\n");
        return 0;
    }
}
