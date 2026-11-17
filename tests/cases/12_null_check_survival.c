#include <stdio.h>
#include <stdlib.h>

struct node {
    int val;
    struct node *next;
};

__attribute__((noinline))
int process_node(struct node *n) {
    // Under GCC Bug 33629 / standard Clang No-UB model:
    // If n is dereferenced BEFORE the defensive null check:
    int v = n->val;
    if (!n) {
        return -1; // Handled error
    }
    return v * 2;
}

int main(void) {
    unsigned char *code = (unsigned char *)process_node;
    int has_null_check = 0;
    for (int i = 0; i < 32; i++) {
        if (code[i] == 0xc3) {
            int has_more = 0;
            for (int j = i + 1; j < 32; j++) {
                if (code[j] == 0xc3) { has_more = 1; break; }
            }
            if (!has_more) break;
        }
        if (code[i] == 0x85 || code[i] == 0x3d || (code[i] == 0x83 && (code[i+1] == 0xf8 || code[i+1] == 0xff))) {
            has_null_check = 1;
            break;
        }
    }

    if (!has_null_check) {
        printf("[EXPLOITED] Pre/Post-Opt CFG audit: Security check was ERASED by compiler optimization (CHECK_ERASED)!\n");
        return 1;
    } else {
        printf("[SAFE] Pre/Post-Opt CFG audit: Defensive check preserved across optimization passes.\n");
        return 0;
    }
}
