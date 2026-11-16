#include <stdio.h>
#include <stdint.h>

__attribute__((noinline))
int check_u8_overflow(uint8_t u8) {
    // GCC Bugzilla #87060:
    // Developer expects u8 + 1 to wrap around to 0 when u8 == 255.
    // Under C standard integer promotion rules, u8 is promoted to signed int (32-bit).
    // Therefore (255 + 1 == 256 != 0), so this condition is NEVER met!
    // The optimizer deletes the wraparound handling block entirely!
    if (u8 + 1 == 0) {
        return 1; // Overflow caught
    }
    return 0; // Allowed
}

int main(void) {
    uint8_t max_val = 255;
    int res = check_u8_overflow(max_val);

    if (res == 0) {
        printf("[EXPLOITED] Implicit integer promotion bypassed wraparound guard (255+1 evaluated as int 256 != 0)!\n");
        return 1;
    } else {
        printf("[SAFE] Modular wraparound check preserved via explicit narrowing cast.\n");
        return 0;
    }
}
