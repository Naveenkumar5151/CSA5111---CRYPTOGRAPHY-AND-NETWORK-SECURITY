/*
 * Program 12 : Hill cipher (2x2) - encryption AND decryption with calculations
 * Key K = | 9 4 |   Plaintext: "meet me at the usual place at ten rather than eight oclock"
 *         | 5 7 |
 * Convention 1 (Stallings, later editions):  C = K * P mod 26  (column vectors)
 * Convention 2 (earlier editions)         :  C = P * K mod 26  (row vectors)
 * Decryption uses K^-1 = (det K)^-1 * adj(K) mod 26.
 * Compile : gcc 12_hill_cipher_encrypt_decrypt.c -o hill
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static int K[2][2] = {{9, 4}, {5, 7}};
static int conv = 1;

static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}
static int md(int x) { return ((x % 26) + 26) % 26; }
static int inv26(int a) { int i; a = md(a); for (i = 1; i < 26; i++) if ((a * i) % 26 == 1) return i; return 0; }

static void block(int M[2][2], int p0, int p1, int *c0, int *c1, int show, const char *name) {
    if (conv == 1) {
        int s0 = M[0][0] * p0 + M[0][1] * p1, s1 = M[1][0] * p0 + M[1][1] * p1;
        if (show) printf("  %s0 = %d*%d + %d*%d = %d mod 26 = %d,  %s1 = %d*%d + %d*%d = %d mod 26 = %d\n", name,
                         M[0][0], p0, M[0][1], p1, s0, md(s0), name, M[1][0], p0, M[1][1], p1, s1, md(s1));
        *c0 = md(s0); *c1 = md(s1);
    } else {
        int s0 = p0 * M[0][0] + p1 * M[1][0], s1 = p0 * M[0][1] + p1 * M[1][1];
        if (show) printf("  %s0 = %d*%d + %d*%d = %d mod 26 = %d,  %s1 = %d*%d + %d*%d = %d mod 26 = %d\n", name,
                         p0, M[0][0], p1, M[1][0], s0, md(s0), name, p0, M[0][1], p1, M[1][1], s1, md(s1));
        *c0 = md(s0); *c1 = md(s1);
    }
}

int main(void) {
    char buf[64], in[500], p[500], c[500], d[500];
    int n = 0, i, det, di, Ki[2][2];

    rd("Convention 1: C = K*P (column vectors)  2: C = P*K (row vectors)  [1]: ", buf, sizeof buf);
    if (atoi(buf) == 2) conv = 2;
    rd("Enter plaintext (Enter = the given message): ", in, sizeof in);
    if (!in[0]) strcpy(in, "meet me at the usual place at ten rather than eight oclock");
    for (i = 0; in[i]; i++) if (isalpha((unsigned char)in[i])) p[n++] = (char)toupper((unsigned char)in[i]);
    if (n % 2) p[n++] = 'X';
    p[n] = 0;

    det = md(K[0][0] * K[1][1] - K[0][1] * K[1][0]);
    di = inv26(det);
    printf("\nKey K = [%d %d; %d %d]\ndet K = %d*%d - %d*%d = %d mod 26 = %d\n", K[0][0], K[0][1], K[1][0], K[1][1],
           K[0][0], K[1][1], K[0][1], K[1][0], K[0][0] * K[1][1] - K[0][1] * K[1][0], det);
    if (!di) { printf("det K has no inverse mod 26 - invalid key.\n"); return 1; }
    printf("(det K)^-1 mod 26 = %d  (since %d*%d = %d = 1 mod 26)\n", di, det, di, det * di);
    Ki[0][0] = md(di * K[1][1]);  Ki[0][1] = md(-di * K[0][1]);
    Ki[1][0] = md(-di * K[1][0]); Ki[1][1] = md(di * K[0][0]);
    printf("K^-1 = %d * [%d %d; %d %d] = [%d %d; %d %d] mod 26\n", di, K[1][1], -K[0][1], -K[1][0], K[0][0],
           Ki[0][0], Ki[0][1], Ki[1][0], Ki[1][1]);

    printf("\nPlaintext (padded) : %s\n\n--- ENCRYPTION ---\n", p);
    for (i = 0; i < n; i += 2) {
        int c0, c1;
        printf("Block %c%c = (%d,%d):\n", p[i], p[i + 1], p[i] - 'A', p[i + 1] - 'A');
        block(K, p[i] - 'A', p[i + 1] - 'A', &c0, &c1, 1, "c");
        c[i] = (char)('A' + c0); c[i + 1] = (char)('A' + c1);
        printf("  -> %c%c\n", c[i], c[i + 1]);
    }
    c[n] = 0;
    printf("\nCipher text : %s\n\n--- DECRYPTION ---\n", c);
    for (i = 0; i < n; i += 2) {
        int p0, p1;
        printf("Block %c%c = (%d,%d):\n", c[i], c[i + 1], c[i] - 'A', c[i + 1] - 'A');
        block(Ki, c[i] - 'A', c[i + 1] - 'A', &p0, &p1, 1, "p");
        d[i] = (char)('A' + p0); d[i + 1] = (char)('A' + p1);
        printf("  -> %c%c\n", d[i], d[i + 1]);
    }
    d[n] = 0;
    printf("\nRecovered plaintext : %s\n", d);
    return 0;
}
