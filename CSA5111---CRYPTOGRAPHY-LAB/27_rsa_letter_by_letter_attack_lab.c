/*
 * Program 27 : Alice encrypts each letter (A=0 ... Z=25) separately with Bob's RSA
 * public key (large e, large n).  Is this secure?   NO.
 *
 * There are only 26 possible plaintexts, and RSA (without padding) is
 * deterministic: the same letter always gives the same ciphertext number.
 * Most efficient attack (no factoring needed): a DICTIONARY / table attack.
 * Eve encrypts all 26 numbers 0..25 with Bob's PUBLIC key, builds a table
 * cipher -> letter and simply looks up every intercepted ciphertext block.
 * (It is also a substitution cipher over 26 symbols, so letter frequencies
 * would work too.)  Fix: pad/pack many letters into one block and add random padding.
 * Compile : gcc 27_rsa_letter_by_letter_attack.c -o rsadict
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

typedef unsigned long long u64;

static u64 gcd(u64 a, u64 b) { return b ? gcd(b, a % b) : a; }
static u64 powmod(u64 b, u64 e, u64 m) {
    u64 r = 1;
    b %= m;
    while (e) { if (e & 1) r = r * b % m; b = b * b % m; e >>= 1; }
    return r;
}
static u64 next_prime(u64 x) {
    for (;; x++) { u64 i; int ok = x > 1; for (i = 2; i * i <= x; i++) if (x % i == 0) { ok = 0; break; } if (ok) return x; }
}

int main(void) {
    u64 p = next_prime(40000), q = next_prime(50000), n = p * q, phi = (p - 1) * (q - 1), e = 65537, table[26];
    const char *msg = "MEET ME AT THE LIBRARY";
    u64 cip[100];
    int cnt = 0, i, j;

    while (gcd(e, phi) != 1) e += 2;
    printf("Bob's public key: n = %llu, e = %llu\n\n", n, e);

    printf("Alice encrypts \"%s\" letter by letter:\n", msg);
    for (i = 0; msg[i]; i++) if (isalpha((unsigned char)msg[i])) cip[cnt++] = powmod((u64)(msg[i] - 'A'), e, n);
    for (i = 0; i < cnt; i++) printf("%llu ", cip[i]);
    printf("\n\nEve (knows only n and e) builds a table by encrypting 0..25:\n");
    for (i = 0; i < 26; i++) { table[i] = powmod((u64)i, e, n); if (i < 5) printf("  E(%c) = %llu\n", 'A' + i, table[i]); }
    printf("  ...\n\nEve looks up each intercepted block:\n  ");
    for (i = 0; i < cnt; i++) {
        char found = '?';
        for (j = 0; j < 26; j++) if (table[j] == cip[i]) found = (char)('A' + j);
        putchar(found);
    }
    printf("\n\nThe message is recovered without factoring n - the scheme is NOT secure.\n");
    return 0;
}
