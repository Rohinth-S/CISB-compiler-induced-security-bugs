#include <stdio.h>
#include <stdint.h>

struct dev {
    int id;
};

__attribute__((noinline))
int query_device(struct dev *d) {
    // Under GCC Bug 33629 / Linux CVE-2009-1897:
    // The dereference d->id occurs before the defensive check.
    // The optimizer infers d cannot be NULL and removes the if (!d) check entirely.
    int id = d->id;
    if (!d) {
        return -1;
    }
    return id;
}

int main(void) {
    unsigned char *code = (unsigned char *)query_device;
    int has_null_check = 0;
    for (int i = 0; i < 32; i++) {
        if (code[i] == 0xc3) {
            int has_more = 0;
            for (int j = i + 1; j < 32; j++) {
                if (code[j] == 0xc3) { has_more = 1; break; }
            }
            if (!has_more) break;
        }
        // Check for test (%rdi, %rdi) or cmp ($0, %rdi) opcode byte patterns (0x85, 0x3d, 0x83)
        if (code[i] == 0x85 || code[i] == 0x3d || (code[i] == 0x83 && (code[i+1] == 0xf8 || code[i+1] == 0xff))) {
            has_null_check = 1;
            break;
        }
    }

    if (!has_null_check) {
        printf("[EXPLOITED] Null-pointer defensive check was deleted by optimizer (GCC Bug 33629)!\n");
        return 1;
    } else {
        printf("[SAFE] Defensive null-check preserved in binary.\n");
        return 0;
    }
}
