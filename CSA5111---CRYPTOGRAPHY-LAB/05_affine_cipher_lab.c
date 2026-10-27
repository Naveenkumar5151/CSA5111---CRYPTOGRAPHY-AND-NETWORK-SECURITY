/*
 * Program 5 : Affine Caesar cipher       C = E([a,b],p) = (a*p + b) mod 26
 *                                        p = a^-1 (C - b) mod 26
 * a. Are there any limitations on the value of b?
 *      NO. b can be any integer 0..25 (it is only a shift, so it never
 *      destroys the one-to-one property).  b = 0 gives a pure multiplicative
 *      cipher; a = 1 gives the ordinary Caesar cipher.
 * b. Which values of a are not allowed?
 *      The map must be one-to-one, so gcd(a,26) must be 1.
 *      Not allowed: all even a and a = 13  (a shares a factor 2 or 13 with 26).
 *      Allowed: 1,3,5,7,9,11,15,17,19,21,23,25  (12 values)
 * Compile : gcc 05_affine_cipher.c -o affine
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
static int modinv(int a) { int i; for (i = 1; i < 26; i++) if ((a * i) % 26 == 1) return i; return 0; }

int main(void) {
    char buf[64], text[1000], res[1000];
    int a, b, i, ch, ainv;

    printf("AFFINE CIPHER   C = (a*p + b) mod 26\n\n");
    printf("a. Limitation on b : none - any b in 0..25 is allowed.\n");
    printf("b. Values of a NOT allowed (gcd(a,26) != 1): ");
    for (a = 1; a < 26; a++) if (gcd(a, 26) != 1) printf("%d ", a);
    printf("\n   Values of a allowed                    : ");
    for (a = 1; a < 26; a++) if (gcd(a, 26) == 1) printf("%d ", a);
    printf("\n\n");

    rd("1. Encrypt  2. Decrypt : ", buf, sizeof buf);
    ch = atoi(buf);
    rd("Enter a : ", buf, sizeof buf); a = atoi(buf);
    rd("Enter b : ", buf, sizeof buf); b = atoi(buf);
    if (gcd(((a % 26) + 26) % 26, 26) != 1) {
        printf("a = %d is NOT allowed: gcd(a,26) != 1, so the cipher is not one-to-one.\n", a);
        return 1;
    }
    a = ((a % 26) + 26) % 26; b = ((b % 26) + 26) % 26;
    ainv = modinv(a);
    rd("Enter text: ", text, sizeof text);
    for (i = 0; text[i]; i++) {
        char c = text[i];
        char base = isupper((unsigned char)c) ? 'A' : 'a';
        if (isalpha((unsigned char)c)) {
            int x = c - base;
            int y = (ch == 1) ? (a * x + b) % 26 : (ainv * ((x - b + 26) % 26)) % 26;
            res[i] = (char)(base + y);
        } else res[i] = c;
    }
    res[i] = 0;
    printf("%s : %s\n", ch == 1 ? "Cipher text" : "Plain text ", res);
    return 0;
}
