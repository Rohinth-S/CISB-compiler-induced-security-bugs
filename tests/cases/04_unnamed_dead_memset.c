#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void *g_anon_leak = NULL;

__attribute__((noinline))
void fill_transient(char *p, size_t len) {
    for (size_t i = 0; i < len; i++) {
        p[i] = (char)(0x41 + (i % 26));
    }
}

__attribute__((noinline))
void process_packet_data(void) {
    // Generic variable name with NO sensitive substring ('key', 'secret', etc.)
    // Tests ScrubGuardPass Condition B: CFG reachability analysis detects that
    // this zero-write is dead before return without keyword cheating.
    char scratch_pad[64];
    g_anon_leak = scratch_pad;
    fill_transient(scratch_pad, sizeof(scratch_pad));

    // Dead memset before return
    memset(scratch_pad, 0, sizeof(scratch_pad));
}

int main(void) {
    process_packet_data();

    char *leaked = (char *)g_anon_leak;
    int leaked_bytes = 0;
    for (size_t i = 0; i < 64; i++) {
        if (leaked[i] != 0) leaked_bytes++;
    }

    if (leaked_bytes > 0) {
        printf("[EXPLOITED] Anonymous dead-store removed by DSE (%d/64 bytes leaked from stack)!\n", leaked_bytes);
        return 1;
    } else {
        printf("[SAFE] CFG reachability analysis successfully preserved dead zero-store (0 bytes leaked).\n");
        return 0;
    }
}
