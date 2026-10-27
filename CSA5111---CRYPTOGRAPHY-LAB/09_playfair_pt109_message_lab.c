/*
 * Program 9 : Decrypt the PT-109 Playfair message
 * The message received at the Australian wireless station (about Lt. John F.
 * Kennedy's PT-109) was sent in Playfair code.  The key used by the Royal
 * Australian Navy was  "royal new zealand navy".
 * Compile : gcc 09_playfair_pt109_message.c -o pt109
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static char M[5][5];

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
    for (i = 0; i < 5; i++) for (j = 0; j < 5; j++) if (M[i][j] == c) { *r = i; *k = j; return; }
}

int main(void) {
    const char *key = "royal new zealand navy";
    const char *cipher =
        "KXJEY UREBE ZWEHE WRYTU HEYFS "
        "KREHE GOYFI WTTTU OLKSY CAJPO "
        "BOTEI ZONTX BYBNT GONEY CUZWR "
        "GDSON SXBOU YWRHE BAAHY USEDQ";
    char c[200], p[200];
    int n = 0, i, j;

    for (i = 0; cipher[i]; i++) if (isalpha((unsigned char)cipher[i])) c[n++] = cipher[i];
    c[n] = 0;

    build(key);
    printf("Key : %s\nPlayfair matrix:\n", key);
    for (i = 0; i < 5; i++) { for (j = 0; j < 5; j++) printf("%c ", M[i][j]); printf("\n"); }

    for (i = 0; i < n; i += 2) {
        int r1, c1, r2, c2;
        find(c[i], &r1, &c1);
        find(c[i + 1], &r2, &c2);
        if (r1 == r2)      { c1 = (c1 + 4) % 5; c2 = (c2 + 4) % 5; }
        else if (c1 == c2) { r1 = (r1 + 4) % 5; r2 = (r2 + 4) % 5; }
        else               { int t = c1; c1 = c2; c2 = t; }
        p[i] = M[r1][c1];
        p[i + 1] = M[r2][c2];
    }
    p[n] = 0;
    printf("\nCipher text : %s\n", cipher);
    printf("Plain text  : ");
    for (i = 0; i < n; i++) { printf("%c", p[i]); if (i % 5 == 4) printf(" "); }
    printf("\n\n(Remove the filler letters X and read it as English.)\n");
    return 0;
}
