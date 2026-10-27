/*
 * Program 36 : Affine Caesar cipher   C = E([a,b],p) = (a*p + b) mod 26
 * A basic requirement of any encryption algorithm is that it is ONE-TO-ONE:
 * if p != q then E(k,p) != E(k,q).  The affine cipher is not one-to-one for all
 * a.  Example: a = 2, b = 3 gives E([2,3],0) = E([2,3],13) = 3.
 * This program checks the one-to-one property for any (a,b) by listing all 26
 * outputs, finds every pair of letters that collide, shows which values of a
 * are usable (gcd(a,26) = 1) and then encrypts / decrypts text.
 * Compile : gcc 36_affine_caesar_cipher.c -o affinecheck
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
static int gcd(int a, int b) { return b ? gcd(b, a % b) : a; }
static int inv(int a) { int i; for (i = 1; i < 26; i++) if ((a * i) % 26 == 1) return i; return 0; }

int main(void) {
    char buf[1000], res[1000];
    int a, b, i, j, ch, collisions = 0, ainv;

    printf("AFFINE CAESAR CIPHER  C = (a*p + b) mod 26\n");
    printf("Valid a (gcd(a,26)=1): ");
    for (a = 1; a < 26; a++) if (gcd(a, 26) == 1) printf("%d ", a);
    printf("\n\n");
    rd("Enter a (e.g. 2): ", buf, sizeof buf); a = atoi(buf);
    rd("Enter b (e.g. 3): ", buf, sizeof buf); b = atoi(buf);
    a = ((a % 26) + 26) % 26; b = ((b % 26) + 26) % 26;

    printf("\nE([%d,%d], p) for p = 0..25:\n", a, b);
    for (i = 0; i < 26; i++) printf("%2d->%2d%s", i, (a * i + b) % 26, (i % 6 == 5) ? "\n" : "  ");
    printf("\n");
    for (i = 0; i < 26; i++)
        for (j = i + 1; j < 26; j++)
            if ((a * i + b) % 26 == (a * j + b) % 26) { printf("Collision: E(%d) = E(%d) = %d\n", i, j, (a * i + b) % 26); collisions++; }
    if (collisions) {
        printf("\nThe cipher is NOT one-to-one for a = %d (gcd(%d,26) = %d): decryption is impossible.\n", a, a, gcd(a, 26));
        return 0;
    }
    printf("No collisions: the cipher is one-to-one (gcd(%d,26) = 1).\n\n", a);
    ainv = inv(a);
    rd("1. Encrypt  2. Decrypt : ", buf, sizeof buf); ch = atoi(buf);
    rd("Enter text: ", buf, sizeof buf);
    for (i = 0; buf[i]; i++) {
        char c = buf[i], base = isupper((unsigned char)c) ? 'A' : 'a';
        if (isalpha((unsigned char)c)) {
            int x = c - base;
            res[i] = (char)(base + ((ch == 1) ? (a * x + b) % 26 : (ainv * ((x - b + 26) % 26)) % 26));
        } else res[i] = c;
    }
    res[i] = 0;
    printf("%s : %s\n", ch == 1 ? "Cipher text" : "Plain text ", res);
    return 0;
}
