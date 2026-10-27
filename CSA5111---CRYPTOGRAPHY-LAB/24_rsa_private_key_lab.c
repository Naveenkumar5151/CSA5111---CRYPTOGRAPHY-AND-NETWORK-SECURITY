/*
 * Program 24 : RSA - find the private key from the public key e = 31, n = 3599
 *  1. Trial and error: find p and q with p*q = n         (n = 3599 = 59 * 61)
 *  2. phi(n) = (p-1)(q-1) = 58 * 60 = 3480
 *  3. d = e^-1 mod phi(n)  by the extended Euclidean algorithm  ->  d = 3031
 * Compile : gcc 24_rsa_private_key.c -o rsakey
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}
/* extended Euclid: returns g = gcd(a,b) and x,y with a*x + b*y = g; prints the steps */
static long long egcd(long long a, long long b, long long *x, long long *y, int show) {
    long long x0 = 1, y0 = 0, x1 = 0, y1 = 1;
    if (show) printf("  q      r        x       y\n");
    while (b) {
        long long q = a / b, t;
        t = a - q * b; a = b; b = t;
        t = x0 - q * x1; x0 = x1; x1 = t;
        t = y0 - q * y1; y0 = y1; y1 = t;
        if (show) printf("  %-5lld %-8lld %-7lld %-7lld\n", q, a, x0, y0);
    }
    *x = x0; *y = y0;
    return a;
}
static long long powmod(long long b, long long e, long long m) {
    long long r = 1;
    b %= m;
    while (e) { if (e & 1) r = r * b % m; b = b * b % m; e >>= 1; }
    return r;
}

int main(void) {
    char buf[64];
    long long e = 31, n = 3599, p = 0, q, phi, d, x, y, g, i;

    rd("Public exponent e (Enter = 31): ", buf, sizeof buf);
    if (buf[0]) e = atoll(buf);
    rd("Modulus n (Enter = 3599): ", buf, sizeof buf);
    if (buf[0]) n = atoll(buf);

    for (i = 2; i * i <= n; i++) if (n % i == 0) { p = i; break; }          /* trial division */
    if (!p) { printf("n is prime - not a valid RSA modulus.\n"); return 1; }
    q = n / p;
    phi = (p - 1) * (q - 1);
    printf("\nStep 1: trial and error gives p = %lld, q = %lld  (p*q = %lld)\n", p, q, p * q);
    printf("Step 2: phi(n) = (p-1)(q-1) = %lld * %lld = %lld\n", p - 1, q - 1, phi);
    printf("Step 3: extended Euclidean algorithm for gcd(%lld, %lld):\n", e, phi);
    g = egcd(e, phi, &x, &y, 1);
    if (g != 1) { printf("gcd(e,phi) = %lld != 1, e has no inverse.\n", g); return 1; }
    d = ((x % phi) + phi) % phi;
    printf("  %lld*(%lld) + %lld*(%lld) = 1   =>   d = %lld mod %lld = %lld\n", e, x, phi, y, x, phi, d);
    printf("\nPrivate key d = %lld   (check: e*d mod phi = %lld)\n", d, e * d % phi);
    printf("Public key  (e, n) = (%lld, %lld)\nPrivate key (d, n) = (%lld, %lld)\n", e, n, d, n);
    {
        long long m = 1234 % n, c = powmod(m, e, n);
        printf("\nTest: message %lld -> ciphertext %lld -> decrypted %lld\n", m, c, powmod(c, d, n));
    }
    return 0;
}
