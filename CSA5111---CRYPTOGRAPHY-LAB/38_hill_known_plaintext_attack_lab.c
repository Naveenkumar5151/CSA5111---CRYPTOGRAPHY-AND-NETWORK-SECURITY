/*
 * Program 38 : Known-plaintext and chosen-plaintext attack on the Hill cipher
 * Hill (m x m):  C = K P mod 26  (columns of P and C are m-letter blocks)
 * If we know m plaintext blocks and their ciphertext blocks, form the matrices
 * P and C (one block per column).  If P is invertible mod 26 then
 *                      K = C * P^-1  mod 26
 * Chosen plaintext attack: choose P = identity (blocks BAA.., ABA.., ..), then
 * C = K, i.e. the ciphertext blocks ARE the columns of the key.
 * Compile : gcc 38_hill_known_plaintext_attack.c -o hillattack
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MX 4
typedef int Mat[MX][MX];

static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}
static int md(int x) { return ((x % 26) + 26) % 26; }
static int inv26(int a) { int i; a = md(a); for (i = 1; i < 26; i++) if ((a * i) % 26 == 1) return i; return 0; }

static int mat_inv(int n, Mat A, Mat R) {            /* Gauss-Jordan mod 26 */
    int M[MX][2 * MX], i, j, c, r;
    for (i = 0; i < n; i++) for (j = 0; j < n; j++) { M[i][j] = md(A[i][j]); M[i][n + j] = (i == j); }
    for (c = 0; c < n; c++) {
        int piv = -1, iv;
        for (r = c; r < n; r++) if (inv26(M[r][c])) { piv = r; break; }
        if (piv < 0) return 0;
        if (piv != c) for (j = 0; j < 2 * n; j++) { int t = M[c][j]; M[c][j] = M[piv][j]; M[piv][j] = t; }
        iv = inv26(M[c][c]);
        for (j = 0; j < 2 * n; j++) M[c][j] = md(M[c][j] * iv);
        for (r = 0; r < n; r++) if (r != c) { int f = M[r][c]; for (j = 0; j < 2 * n; j++) M[r][j] = md(M[r][j] - f * M[c][j]); }
    }
    for (i = 0; i < n; i++) for (j = 0; j < n; j++) R[i][j] = M[i][n + j];
    return 1;
}
static void mat_mul(int n, Mat A, Mat B, Mat R) {
    int i, j, k;
    for (i = 0; i < n; i++) for (j = 0; j < n; j++) { int s = 0; for (k = 0; k < n; k++) s += A[i][k] * B[k][j]; R[i][j] = md(s); }
}
static void print_mat(int n, Mat A) {
    int i, j;
    for (i = 0; i < n; i++) { printf("   "); for (j = 0; j < n; j++) printf("%3d", A[i][j]); printf("\n"); }
}
static void blocks_to_mat(int n, const char *s, Mat M) {      /* block j -> column j */
    int i, j;
    for (j = 0; j < n; j++) for (i = 0; i < n; i++) M[i][j] = toupper((unsigned char)s[j * n + i]) - 'A';
}
static void encrypt_blocks(int n, Mat K, const char *p, char *c) {
    Mat P, C;
    blocks_to_mat(n, p, P);
    mat_mul(n, K, P, C);
    {
        int i, j;
        for (j = 0; j < n; j++) for (i = 0; i < n; i++) c[j * n + i] = (char)('A' + C[i][j]);
        c[n * n] = 0;
    }
}

static void attack(int n, const char *p, const char *c) {
    Mat P, C, Pi, K;
    blocks_to_mat(n, p, P);
    blocks_to_mat(n, c, C);
    printf("\nPlaintext matrix P (blocks as columns):\n"); print_mat(n, P);
    printf("Ciphertext matrix C:\n"); print_mat(n, C);
    if (!mat_inv(n, P, Pi)) { printf("P is not invertible mod 26 - choose other plaintext blocks.\n"); return; }
    printf("P^-1 mod 26:\n"); print_mat(n, Pi);
    mat_mul(n, C, Pi, K);
    printf("Recovered key K = C * P^-1 mod 26:\n"); print_mat(n, K);
}

int main(void) {
    char buf[64], p[64], c[64];
    int mode, n;

    printf("HILL CIPHER - KNOWN / CHOSEN PLAINTEXT ATTACK\n1. Demo with secret key [9 4; 5 7]\n2. Enter your own plaintext/ciphertext blocks\n");
    rd("Choice: ", buf, sizeof buf);
    mode = atoi(buf);
    if (mode == 1) {
        Mat K = {{9, 4}, {5, 7}};
        n = 2;
        printf("\n--- Known plaintext attack ---\nAttacker knows plaintext HELP:\n");
        strcpy(p, "HELP");
        encrypt_blocks(n, K, p, c);
        printf("Plaintext HELP  ->  ciphertext %s\n", c);
        attack(n, p, c);
        printf("\n--- Chosen plaintext attack ---\nAttacker chooses blocks BA and AB (identity matrix):\n");
        strcpy(p, "BAAB");
        encrypt_blocks(n, K, p, c);
        printf("Plaintext BAAB  ->  ciphertext %s\n", c);
        attack(n, p, c);
        printf("Here the ciphertext blocks are directly the columns of K.\n");
    } else {
        rd("Block size m (2-4): ", buf, sizeof buf);
        n = atoi(buf);
        if (n < 2 || n > MX) { printf("m must be 2..4\n"); return 1; }
        rd("Enter m*m known plaintext letters (m blocks): ", p, sizeof p);
        rd("Enter the corresponding m*m ciphertext letters : ", c, sizeof c);
        if ((int)strlen(p) != n * n || (int)strlen(c) != n * n) { printf("Need exactly m*m letters each.\n"); return 1; }
        attack(n, p, c);
    }
    return 0;
}
