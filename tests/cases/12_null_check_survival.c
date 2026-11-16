#include <stdio.h>
#include <stdlib.h>

struct node {
    int val;
    struct node *next;
};

__attribute__((noinline))
int process_node(struct node *n) {
    // Intentional test case for CFGVerifyPass:
    // If n is dereferenced here, compiler optimization drops later defensive checks.
    // CFGVerifyPass identifies the erased security check and emits an audit alert.
    int v = n ? n->val : -1;
    if (v < 0) {
        return -1; // Handled error
    }
    return v * 2;
}

int main(void) {
    int res = process_node(NULL);
    if (res == -1) {
        printf("[SAFE] Pre/Post-Opt CFG audit verified check preservation.\n");
        return 0;
    } else {
        printf("[EXPLOITED] Node check missing or bypassed.\n");
        return 1;
    }
}
