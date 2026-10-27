/*
 * Program 2 : Monoalphabetic substitution cipher
 * Every plaintext letter maps to ONE unique ciphertext letter
 * (the key is a permutation of the 26 letters).
 * Compile : gcc 02_monoalphabetic_substitution.c -o mono
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}

static int valid_key(const char *k) {
    int seen[26] = {0}, i;
    if (strlen(k) != 26) return 0;
    for (i = 0; i < 26; i++) {
        int c;
        if (!isalpha((unsigned char)k[i])) return 0;
        c = toupper((unsigned char)k[i]) - 'A';
        if (seen[c]) return 0;
        seen[c] = 1;
    }
    return 1;
}

int main(void) {
    char buf[64], key[64], text[1000], res[1000];
    int enc[26], dec[26], i, ch;

    printf("MONOALPHABETIC SUBSTITUTION CIPHER\n1. Encrypt\n2. Decrypt\n3. Generate a random key\n");
    rd("Choice: ", buf, sizeof buf);
    ch = atoi(buf);

    if (ch == 3) {
        char a[27] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        srand((unsigned)time(NULL));
        for (i = 25; i > 0; i--) { int j = rand() % (i + 1); char t = a[i]; a[i] = a[j]; a[j] = t; }
        printf("Random key (plain A..Z -> cipher): %s\n", a);
        return 0;
    }
    rd("Enter 26-letter cipher alphabet (permutation of A-Z): ", key, sizeof key);
    if (!valid_key(key)) { printf("Invalid key: need 26 distinct letters.\n"); return 1; }
    for (i = 0; i < 26; i++) {
        int c = toupper((unsigned char)key[i]) - 'A';
        enc[i] = c;      /* plain i  -> cipher c */
        dec[c] = i;      /* cipher c -> plain i  */
    }
    rd("Enter text: ", text, sizeof text);
    for (i = 0; text[i]; i++) {
        char c = text[i];
        int *m = (ch == 1) ? enc : dec;
        if (isupper((unsigned char)c))      res[i] = (char)('A' + m[c - 'A']);
        else if (islower((unsigned char)c)) res[i] = (char)('a' + m[c - 'a']);
        else                                res[i] = c;
    }
    res[i] = 0;
    printf("%s : %s\n", ch == 1 ? "Cipher text" : "Plain text ", res);
    return 0;
}
