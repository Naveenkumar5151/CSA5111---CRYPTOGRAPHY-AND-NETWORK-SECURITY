/*
 * Program 23 : Encrypt and decrypt in Counter (CTR) mode using S-DES
 *   C_i = P_i XOR E(K, Counter_i)      P_i = C_i XOR E(K, Counter_i)
 *   (encryption and decryption are the SAME operation; counter is incremented by 1)
 * Test data : counter starts at 0000 0000, key = 01111 11101,
 *   plaintext 0000 0001 0000 0010 0000 0100 -> ciphertext 0011 1000 0100 1111 0011 0010
 * Press Enter at the first prompt to use the test data.
 * Compile : gcc 23_sdes_counter_mode.c -o sdesctr
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ===================== S-DES core (Simplified DES, 8-bit block, 10-bit key) ===================== */
static const int P10[10] = {3,5,2,7,4,10,1,9,8,6};
static const int P8[8]   = {6,3,7,4,8,5,10,9};
static const int IPS[8]  = {2,6,3,1,4,8,5,7};
static const int IPI[8]  = {4,1,3,5,7,2,8,6};
static const int EPS[8]  = {4,1,2,3,2,3,4,1};
static const int P4[4]   = {2,4,3,1};
static const int S0[4][4] = {{1,0,3,2},{3,2,1,0},{0,2,1,3},{3,1,3,2}};
static const int S1[4][4] = {{0,1,2,3},{2,0,1,3},{3,0,1,0},{2,1,0,3}};

static int K1[8], K2[8];

static void perm(const int *in, int *out, const int *t, int n) { int i; for (i = 0; i < n; i++) out[i] = in[t[i] - 1]; }
static void rotl5(int *h, int s) { int i, t; while (s--) { t = h[0]; for (i = 0; i < 4; i++) h[i] = h[i + 1]; h[4] = t; } }

/* key: 10 bits, key[0] is the leftmost bit */
static void sdes_keygen(const int key[10]) {
    int p[10], r[10];
    perm(key, p, P10, 10);
    rotl5(p, 1); rotl5(p + 5, 1);
    perm(p, K1, P8, 8);
    rotl5(p, 2); rotl5(p + 5, 2);
    perm(p, K2, P8, 8);
    (void)r;
}
static void fk(int *L, int *R, const int *K) {
    int e[8], x[8], i, o[4], p4[4];
    perm(R, e, EPS, 8);
    for (i = 0; i < 8; i++) x[i] = e[i] ^ K[i];
    { int v = S0[(x[0] << 1) | x[3]][(x[1] << 1) | x[2]]; o[0] = v >> 1; o[1] = v & 1; }
    { int v = S1[(x[4] << 1) | x[7]][(x[5] << 1) | x[6]]; o[2] = v >> 1; o[3] = v & 1; }
    perm(o, p4, P4, 4);
    for (i = 0; i < 4; i++) L[i] ^= p4[i];
}
/* encrypt (dec=0) / decrypt (dec=1) one byte */
static int sdes_block(int byte, int dec) {
    int b[8], ip[8], L[4], R[4], t[4], pre[8], out[8], i, v = 0;
    for (i = 0; i < 8; i++) b[i] = (byte >> (7 - i)) & 1;
    perm(b, ip, IPS, 8);
    for (i = 0; i < 4; i++) { L[i] = ip[i]; R[i] = ip[4 + i]; }
    fk(L, R, dec ? K2 : K1);
    for (i = 0; i < 4; i++) { t[i] = L[i]; L[i] = R[i]; R[i] = t[i]; }        /* switch */
    fk(L, R, dec ? K1 : K2);
    for (i = 0; i < 4; i++) { pre[i] = L[i]; pre[4 + i] = R[i]; }
    perm(pre, out, IPI, 8);
    for (i = 0; i < 8; i++) v = (v << 1) | out[i];
    return v;
}
/* read bits from a string ('0'/'1', other characters ignored); returns count */
static int read_bits(const char *s, int *bits, int max) {
    int n = 0;
    for (; *s && n < max; s++) if (*s == '0' || *s == '1') bits[n++] = *s - '0';
    return n;
}
static void print_bin(int v) { int i; for (i = 7; i >= 0; i--) printf("%d", (v >> i) & 1); }
static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}
/* =================== end of S-DES core ===================== */


int main(void) {
    char buf[300];
    int key[10], cb[8], data[256], nb, i, j, ctr = 0, v;

    rd("Press Enter for the test data, or type any text to enter your own: ", buf, sizeof buf);
    if (!buf[0]) {
        int kb[10], P[3] = {0x01, 0x02, 0x04}, C[3];
        read_bits("0111111101", kb, 10); sdes_keygen(kb);
        printf("TEST: key 01111 11101, counter starts 0000 0000\nEncrypted: ");
        for (i = 0; i < 3; i++) { C[i] = P[i] ^ sdes_block(i, 0); print_bin(C[i]); printf(" "); }
        printf("  (expected 0011 1000 0100 1111 0011 0010)\nDecrypted: ");
        for (i = 0; i < 3; i++) { print_bin(C[i] ^ sdes_block(i, 0)); printf(" "); }
        printf("\n");
        return 0;
    }
    rd("Enter 10-bit key (e.g. 01111 11101): ", buf, sizeof buf);
    if (read_bits(buf, key, 10) != 10) { printf("Key must have 10 bits.\n"); return 1; }
    rd("Enter 8-bit starting counter (e.g. 0000 0000): ", buf, sizeof buf);
    if (read_bits(buf, cb, 8) != 8) { printf("Counter must have 8 bits.\n"); return 1; }
    for (i = 0; i < 8; i++) ctr = (ctr << 1) | cb[i];
    rd("Enter plaintext (or ciphertext) bits, multiple of 8: ", buf, sizeof buf);
    nb = read_bits(buf, data, 256);
    if (nb == 0 || nb % 8) { printf("Data length must be a positive multiple of 8 bits.\n"); return 1; }
    sdes_keygen(key);
    printf("Output : ");
    for (i = 0; i < nb / 8; i++) {
        v = 0;
        for (j = 0; j < 8; j++) v = (v << 1) | data[i * 8 + j];
        print_bin(v ^ sdes_block((ctr + i) & 0xFF, 0));
        printf(" ");
    }
    printf("\n(same operation encrypts and decrypts)\n");
    return 0;
}
