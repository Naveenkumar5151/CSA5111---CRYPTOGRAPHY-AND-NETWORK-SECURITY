/*
 * Program 1 : Caesar cipher
 * Each letter is replaced by the letter k places further down the alphabet,
 * for k in the range 1 through 25.   C = (p + k) mod 26 ,  p = (C - k) mod 26
 * Compile : gcc 01_caesar_cipher.c -o caesar
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}

static void caesar(const char *in, char *out, int k) {
    int i;
    for (i = 0; in[i]; i++) {
        char c = in[i];
        if (isupper((unsigned char)c))      out[i] = (char)('A' + ((c - 'A' + k) % 26 + 26) % 26);
        else if (islower((unsigned char)c)) out[i] = (char)('a' + ((c - 'a' + k) % 26 + 26) % 26);
        else                                out[i] = c;
    }
    out[i] = '\0';
}

int main(void) {
    char buf[64], text[1000], res[1000];
    int ch, k;

    printf("CAESAR CIPHER\n1. Encrypt\n2. Decrypt\n3. Brute-force (try all 25 keys)\n");
    rd("Choice: ", buf, sizeof buf);
    ch = atoi(buf);
    rd("Enter text: ", text, sizeof text);

    if (ch == 3) {
        for (k = 1; k <= 25; k++) {
            caesar(text, res, -k);
            printf("k = %2d : %s\n", k, res);
        }
        return 0;
    }
    rd("Enter key k (1-25): ", buf, sizeof buf);
    k = atoi(buf);
    if (k < 1 || k > 25) { printf("Key must be between 1 and 25.\n"); return 1; }

    if (ch == 1) { caesar(text, res, k);  printf("Cipher text : %s\n", res); }
    else         { caesar(text, res, -k); printf("Plain text  : %s\n", res); }
    return 0;
}
