#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

void *g_leak_ptr = NULL;

__attribute__((noinline))
void use_crypto_key(const char *key) {
    asm volatile("" : : "r"(key) : "memory");
    printf("[App] Authenticated session with key.\n");
}

__attribute__((noinline))
void authenticate(void) {
    char secret_key[64];
    g_leak_ptr = (void *)secret_key;
    snprintf(secret_key, sizeof(secret_key), "TOP_SECRET_AES256_KEY_99481");
    use_crypto_key(secret_key);

    // Security Property (OSpec1): Scrub key from stack before returning.
    // Under standard clang -O3, Dead Store Elimination (DSE) silently DELETES this line!
    memset(secret_key, 0, sizeof(secret_key));
}

__attribute__((noinline))
void inspect_memory(char *buf, size_t len) {
    asm volatile("" : "+r"(buf) : : "memory");
    char safe_copy[65];
    if (len > 64) len = 64;
    memcpy(safe_copy, buf, len);
    safe_copy[len] = '\0';

    if (strstr(safe_copy, "TOP_SECRET")) {
        printf("[EXPLOITED] SECRET LEAKED FROM RAM: \"%s\"\n", safe_copy);
        exit(1);
    } else {
        printf("[SAFE] Memory properly scrubbed! Stack bytes successfully sanitized.\n");
        exit(0);
    }
}

__attribute__((noinline))
void attacker_read_uninit_stack(void) {
    char *uninit_buf = (char *)g_leak_ptr;
    inspect_memory(uninit_buf, 64);
}

int main(void) {
    authenticate();
    attacker_read_uninit_stack();
    return 0;
}
