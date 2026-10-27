/*
 * Program 4 : Polyalphabetic substitution cipher (Vigenere)
 * A separate Caesar (monoalphabetic) shift is used for each successive
 * plaintext letter, selected by the corresponding letter of the repeating key.
 *   C_i = (P_i + K_(i mod m)) mod 26      P_i = (C_i - K_(i mod m)) mod 26
 * Compile : gcc 04_polyalphabetic_vigenere.c -o vigenere
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

int main(void) {
    char buf[64], key[200], k[200], text[1000], res[1000];
    int i, j = 0, m = 0, ch;

    rd("1. Encrypt  2. Decrypt : ", buf, sizeof buf);
    ch = atoi(buf);
    rd("Enter key (letters only): ", key, sizeof key);
    for (i = 0; key[i]; i++) if (isalpha((unsigned char)key[i])) k[m++] = (char)(toupper((unsigned char)key[i]) - 'A');
    if (m == 0) { printf("Key must contain letters.\n"); return 1; }
    rd("Enter text: ", text, sizeof text);

    for (i = 0; text[i]; i++) {
        char c = text[i];
        int shift = (ch == 1) ? k[j % m] : 26 - k[j % m];
        if (isupper((unsigned char)c))      { res[i] = (char)('A' + (c - 'A' + shift) % 26); j++; }
        else if (islower((unsigned char)c)) { res[i] = (char)('a' + (c - 'a' + shift) % 26); j++; }
        else res[i] = c;
    }
    res[i] = 0;
    printf("%s : %s\n", ch == 1 ? "Cipher text" : "Plain text ", res);
    return 0;
}
