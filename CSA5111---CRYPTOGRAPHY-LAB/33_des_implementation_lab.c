/*
 * Program 33 : Data Encryption Standard (DES) in C
 * DES is a block cipher: 64-bit plaintext block + 56-bit key (8 bytes given,
 * every 8th bit is parity) -> 64-bit ciphertext block, 16 Feistel rounds.
 * The same algorithm and key are used for encryption and decryption; only the
 * ORDER of the 16 subkeys is reversed.
 *   Steps : initial permutation IP -> 16 rounds  L(i)=R(i-1),
 *           R(i)=L(i-1) XOR f(R(i-1),K(i))  -> swap -> final permutation IP^-1.
 *   f     : expand R to 48 bits (E), XOR subkey, 8 S-boxes (48->32), permute (P).
 * Text is processed in ECB mode with PKCS#7-style padding.
 * Compile : gcc 33_des_implementation.c -o des
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* ===================== DES core (tables from FIPS 46-3) ===================== */
typedef unsigned char u8;

static const int IP_T[64] = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
                             57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
static const int FP_T[64] = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
                             36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
static const int E_T[48]  = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
                             16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
static const int P_T[32]  = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
static const int PC1_T[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
                              63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
static const int PC2_T[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
                              41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
static const int SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static const int SB[8][64] = {
 {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
 {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
 {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
 {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
 {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
 {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
 {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
 {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
};

static int getbit(const u8 *b, int pos) { return (b[(pos - 1) / 8] >> (7 - ((pos - 1) % 8))) & 1; }   /* pos is 1-based */
static void setbit(u8 *b, int pos, int v) {
    if (v) b[(pos - 1) / 8] |= (u8)(1 << (7 - ((pos - 1) % 8)));
    else   b[(pos - 1) / 8] &= (u8)~(1 << (7 - ((pos - 1) % 8)));
}

/* 16 subkeys of 48 bits each (one bit per int) */
static void des_keysched(const u8 key[8], int sk[16][48]) {
    int cd[56], i, r, s, t;
    for (i = 0; i < 56; i++) cd[i] = getbit(key, PC1_T[i]);
    for (r = 0; r < 16; r++) {
        for (s = 0; s < SHIFTS[r]; s++) {
            t = cd[0];  for (i = 0; i < 27; i++) cd[i] = cd[i + 1];  cd[27] = t;
            t = cd[28]; for (i = 28; i < 55; i++) cd[i] = cd[i + 1]; cd[55] = t;
        }
        for (i = 0; i < 48; i++) sk[r][i] = cd[PC2_T[i] - 1];
    }
}

/* encrypt (dec = 0) or decrypt (dec = 1) one 64-bit block using the subkeys sk */
static void des_block(const u8 in[8], u8 out[8], int sk[16][48], int dec) {
    int b[64], L[32], R[32], t[48], f[32], tmp[32], pre[64], i, j, r, s;
    for (i = 0; i < 64; i++) b[i] = getbit(in, IP_T[i]);
    for (i = 0; i < 32; i++) { L[i] = b[i]; R[i] = b[32 + i]; }
    for (r = 0; r < 16; r++) {
        int *k = sk[dec ? 15 - r : r];
        for (i = 0; i < 48; i++) t[i] = R[E_T[i] - 1] ^ k[i];
        for (s = 0; s < 8; s++) {
            int row = (t[6 * s] << 1) | t[6 * s + 5];
            int col = (t[6 * s + 1] << 3) | (t[6 * s + 2] << 2) | (t[6 * s + 3] << 1) | t[6 * s + 4];
            int v = SB[s][row * 16 + col];
            for (j = 0; j < 4; j++) f[4 * s + j] = (v >> (3 - j)) & 1;
        }
        for (i = 0; i < 32; i++) tmp[i] = f[P_T[i] - 1] ^ L[i];
        for (i = 0; i < 32; i++) { L[i] = R[i]; R[i] = tmp[i]; }
    }
    for (i = 0; i < 32; i++) { pre[i] = R[i]; pre[32 + i] = L[i]; }
    memset(out, 0, 8);
    for (i = 0; i < 64; i++) setbit(out, i + 1, pre[FP_T[i] - 1]);
}

/* small helpers */
static int hex2bytes(const char *h, u8 *out, int maxn) {
    int n = 0;
    while (h[0] && h[1] && n < maxn) {
        int a, b;
        if (h[0] == ' ') { h++; continue; }
        a = (h[0] >= '0' && h[0] <= '9') ? h[0] - '0' : (h[0] | 32) - 'a' + 10;
        b = (h[1] >= '0' && h[1] <= '9') ? h[1] - '0' : (h[1] | 32) - 'a' + 10;
        if (a < 0 || a > 15 || b < 0 || b > 15) break;
        out[n++] = (u8)(a * 16 + b);
        h += 2;
    }
    return n;
}
static void print_hex(const u8 *b, int n) { int i; for (i = 0; i < n; i++) printf("%02X", b[i]); }
static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}
/* =================== end of DES core ===================== */


int main(void) {
    char buf[600], keyhex[64];
    u8 key[8], blk[8], out[8], data[600];
    static int sk[16][48];
    int ch, n, i, len;

    printf("DES\n1. Self-test (standard test vector)\n2. Encrypt text\n3. Decrypt hex cipher text\n");
    rd("Choice: ", buf, sizeof buf);
    ch = atoi(buf);

    if (ch == 1) {
        hex2bytes("133457799BBCDFF1", key, 8);
        hex2bytes("0123456789ABCDEF", blk, 8);
        des_keysched(key, sk);
        des_block(blk, out, sk, 0);
        printf("Key 133457799BBCDFF1, plaintext 0123456789ABCDEF\nEncrypted : "); print_hex(out, 8);
        printf("   (expected 85E813540F0AB405)\n");
        des_block(out, blk, sk, 1);
        printf("Decrypted : "); print_hex(blk, 8); printf("\n");
        return 0;
    }
    rd("Enter 64-bit key as 16 hex digits (Enter = 133457799BBCDFF1): ", keyhex, sizeof keyhex);
    if (!keyhex[0]) strcpy(keyhex, "133457799BBCDFF1");
    if (hex2bytes(keyhex, key, 8) != 8) { printf("Key must be 16 hex digits.\n"); return 1; }
    des_keysched(key, sk);

    if (ch == 2) {
        rd("Enter plaintext: ", buf, sizeof buf);
        len = (int)strlen(buf);
        n = (len / 8 + 1) * 8;                      /* always pad (1..8 bytes) */
        memcpy(data, buf, (size_t)len);
        for (i = len; i < n; i++) data[i] = (u8)(n - len);
        printf("Cipher text (hex): ");
        for (i = 0; i < n; i += 8) { des_block(data + i, out, sk, 0); print_hex(out, 8); }
        printf("\n");
    } else {
        rd("Enter cipher text in hex: ", buf, sizeof buf);
        n = hex2bytes(buf, data, sizeof data);
        if (n == 0 || n % 8) { printf("Cipher text must be a multiple of 16 hex digits.\n"); return 1; }
        for (i = 0; i < n; i += 8) { des_block(data + i, out, sk, 1); memcpy(data + i, out, 8); }
        if (data[n - 1] >= 1 && data[n - 1] <= 8) n -= data[n - 1];
        data[n] = 0;
        printf("Plain text: %s\n", data);
    }
    return 0;
}
