#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

void *g_hash_leak = NULL;

__attribute__((noinline))
void extract_entropy(uint8_t *out, size_t n) {
    // Linux kernel drivers/char/random.c model:
    // Computes intermediate entropy hash on stack
    uint8_t hash[32];
    g_hash_leak = hash;
    for (int i = 0; i < 32; i++) {
        hash[i] = (uint8_t)(0xAA ^ i);
    }
    memcpy(out, hash, n < 32 ? n : 32);

    // Security boundary: wipe intermediate hash so entropy state cannot be read
    // Under baseline -O3, compiler drops memset as dead store
    memset(hash, 0, sizeof(hash));
}

int main(void) {
    uint8_t out[16];
    extract_entropy(out, 16);

    uint8_t *leaked = (uint8_t *)g_hash_leak;
    int residue = 0;
    for (int i = 0; i < 32; i++) {
        if (leaked[i] != 0) residue++;
    }

    if (residue > 0) {
        printf("[EXPLOITED] Linux random.c extract_buf() entropy hash leaked (%d/32 bytes on stack)!\n", residue);
        return 1;
    } else {
        printf("[SAFE] Entropy hash wiped cleanly via ScrubGuardPass volatile store.\n");
        return 0;
    }
}
