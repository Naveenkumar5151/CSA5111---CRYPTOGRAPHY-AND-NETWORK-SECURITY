/*
 * Program 10 : Encrypt a message with a given Playfair matrix
 *       M F H I/J K
 *       U N O P  Q
 *       Z V W X  Y
 *       E L A R  G
 *       D S T B  C
 * Message : "Must see you over Cadogan West. Coming at once."
 * Compile : gcc 10_playfair_encrypt_matrix.c -o pfmatrix
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static const char M[5][5] = {
    {'M','F','H','I','K'},
    {'U','N','O','P','Q'},
    {'Z','V','W','X','Y'},
    {'E','L','A','R','G'},
    {'D','S','T','B','C'}
};

static void find(char c, int *r, int *k) {
    int i, j;
    for (i = 0; i < 5; i++) for (j = 0; j < 5; j++) if (M[i][j] == c) { *r = i; *k = j; return; }
}

int main(void) {
    const char *msg = "Must see you over Cadogan West. Coming at once.";
    char t[200], d[400];
    int tn = 0, n = 0, i = 0, j;

    for (; *msg; msg++)
        if (isalpha((unsigned char)*msg)) {
            char c = (char)toupper((unsigned char)*msg);
            t[tn++] = (c == 'J') ? 'I' : c;
        }
    t[tn] = 0;
    while (i < tn) {                         /* build digraphs */
        char a = t[i], b = (i + 1 < tn) ? t[i + 1] : 'X';
        if (a == b) { d[n++] = a; d[n++] = 'X'; i++; }
        else        { d[n++] = a; d[n++] = b;   i += 2; }
    }
    d[n] = 0;

    printf("Playfair matrix:\n");
    for (i = 0; i < 5; i++) { for (j = 0; j < 5; j++) printf("%c ", M[i][j]); printf("\n"); }
    printf("\nPlain text  : %s\nDigraphs    : ", t);
    for (i = 0; i < n; i += 2) printf("%c%c ", d[i], d[i + 1]);

    printf("\nCipher text : ");
    for (i = 0; i < n; i += 2) {
        int r1, c1, r2, c2;
        find(d[i], &r1, &c1);
        find(d[i + 1], &r2, &c2);
        if (r1 == r2)      { c1 = (c1 + 1) % 5; c2 = (c2 + 1) % 5; }
        else if (c1 == c2) { r1 = (r1 + 1) % 5; r2 = (r2 + 1) % 5; }
        else               { int x = c1; c1 = c2; c2 = x; }
        printf("%c%c ", M[r1][c1], M[r2][c2]);
    }
    printf("\n");
    return 0;
}
