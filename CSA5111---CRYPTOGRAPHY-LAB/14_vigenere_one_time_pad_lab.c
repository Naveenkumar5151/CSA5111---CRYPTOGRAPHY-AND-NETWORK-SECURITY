/*
 * Program 14 : One-time-pad version of the Vigenere cipher
 * The key is a stream of random numbers 0..25; letter i is shifted by key[i].
 *   a. Encrypt "send more money" with key stream 9 0 1 7 23 15 21 14 11 11 2 8 9
 *   b. Using that ciphertext find a key so that it decrypts to "cash not needed"
 *      key[i] = (C[i] - P[i]) mod 26      (a one-time pad can "decrypt" to ANY
 *      message of the same length - that is why it is perfectly secret)
 * Compile : gcc 14_vigenere_one_time_pad.c -o otp
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main(void) {
    const char *plain = "send more money";
    int key[] = {9, 0, 1, 7, 23, 15, 21, 14, 11, 11, 2, 8, 9};
    const char *target = "cash not needed";
    char p[64], t[64], c[64];
    int n = 0, i, m = 0, k2[64];

    for (i = 0; plain[i]; i++) if (isalpha((unsigned char)plain[i])) p[n++] = (char)toupper((unsigned char)plain[i]);
    p[n] = 0;
    for (i = 0; target[i]; i++) if (isalpha((unsigned char)target[i])) t[m++] = (char)toupper((unsigned char)target[i]);
    t[m] = 0;

    printf("a. Encryption\n   Plaintext : %s\n   Key stream: ", p);
    for (i = 0; i < n; i++) printf("%d ", key[i]);
    printf("\n   Calculation (P + K mod 26):\n");
    for (i = 0; i < n; i++) {
        c[i] = (char)('A' + ((p[i] - 'A') + key[i]) % 26);
        printf("     %c(%2d) + %2d = %2d mod 26 = %2d -> %c\n", p[i], p[i] - 'A', key[i], (p[i] - 'A') + key[i], ((p[i] - 'A') + key[i]) % 26, c[i]);
    }
    c[n] = 0;
    printf("   Ciphertext: %s\n\n", c);

    printf("b. Find the key that decrypts %s to \"%s\"  (K = C - P mod 26)\n", c, target);
    if (m != n) { printf("Lengths differ!\n"); return 1; }
    for (i = 0; i < n; i++) {
        k2[i] = ((c[i] - 'A') - (t[i] - 'A') + 26) % 26;
        printf("     %c(%2d) - %c(%2d) = %2d mod 26 -> key %2d\n", c[i], c[i] - 'A', t[i], t[i] - 'A', (c[i] - 'A') - (t[i] - 'A'), k2[i]);
    }
    printf("   Key stream: ");
    for (i = 0; i < n; i++) printf("%d ", k2[i]);
    printf("\n   Check (C - K): ");
    for (i = 0; i < n; i++) printf("%c", 'a' + ((c[i] - 'A') - k2[i] + 26) % 26);
    printf("\n");
    return 0;
}
