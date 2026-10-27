/*
 * Program 3 : Playfair cipher
 * Uses a 5x5 matrix built from a keyword (I and J share one cell).
 * Plaintext is encrypted two letters at a time.
 *   same row    -> letter to the right
 *   same column -> letter below
 *   rectangle   -> letter in own row, column of the other letter
 * Compile : gcc 03_playfair_cipher.c -o playfair
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static char M[5][5];

static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}

static void build(const char *key) {
    int used[26] = {0}, n = 0, i;
    char all[300];
    snprintf(all, sizeof all, "%sABCDEFGHIKLMNOPQRSTUVWXYZ", key);
    for (i = 0; all[i]; i++) {
        int c;
        if (!isalpha((unsigned char)all[i])) continue;
        c = toupper((unsigned char)all[i]);
        if (c == 'J') c = 'I';
        if (used[c - 'A']) continue;
        used[c - 'A'] = 1;
        M[n / 5][n % 5] = (char)c;
        n++;
    }
}

static void find(char c, int *r, int *k) {
    int i, j;
    for (i = 0; i < 5; i++)
        for (j = 0; j < 5; j++)
            if (M[i][j] == c) { *r = i; *k = j; return; }
}

/* clean text, J->I, split into digraphs, put X between equal letters, pad with X */
static int prepare(const char *in, char *out) {
    char t[1000];
    int tn = 0, n = 0, i = 0;
    for (; *in; in++)
        if (isalpha((unsigned char)*in)) {
            char c = (char)toupper((unsigned char)*in);
            t[tn++] = (c == 'J') ? 'I' : c;
        }
    while (i < tn) {
        char a = t[i], b = (i + 1 < tn) ? t[i + 1] : 'X';
        if (a == b) { out[n++] = a; out[n++] = 'X'; i++; }
        else        { out[n++] = a; out[n++] = b;   i += 2; }
    }
    out[n] = 0;
    return n;
}

static void crypt_pairs(char *s, int n, int dir) {   /* dir = +1 encrypt, -1 decrypt */
    int i;
    for (i = 0; i < n; i += 2) {
        int r1, c1, r2, c2;
        find(s[i], &r1, &c1);
        find(s[i + 1], &r2, &c2);
        if (r1 == r2)      { c1 = (c1 + dir + 5) % 5; c2 = (c2 + dir + 5) % 5; }
        else if (c1 == c2) { r1 = (r1 + dir + 5) % 5; r2 = (r2 + dir + 5) % 5; }
        else               { int t = c1; c1 = c2; c2 = t; }
        s[i] = M[r1][c1];
        s[i + 1] = M[r2][c2];
    }
}

int main(void) {
    char buf[64], key[200], text[1000], work[2000];
    int i, j, n, ch;

    rd("Enter keyword: ", key, sizeof key);
    build(key);
    printf("\n5 x 5 Playfair matrix:\n");
    for (i = 0; i < 5; i++) {
        for (j = 0; j < 5; j++) printf("%c ", M[i][j]);
        printf("\n");
    }
    rd("\n1. Encrypt  2. Decrypt : ", buf, sizeof buf);
    ch = atoi(buf);
    rd("Enter text: ", text, sizeof text);
    n = prepare(text, work);
    printf("Digraphs : ");
    for (i = 0; i < n; i += 2) printf("%c%c ", work[i], work[i + 1]);
    crypt_pairs(work, n, ch == 1 ? 1 : -1);
    printf("\n%s : ", ch == 1 ? "Cipher text" : "Plain text ");
    for (i = 0; i < n; i += 2) printf("%c%c ", work[i], work[i + 1]);
    printf("\n");
    return 0;
}
