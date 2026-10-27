/*
 * Program 25 : RSA blocks where one plaintext block shares a factor with n
 * Question: we have blocks encrypted with RSA, no private key; n = pq, e public.
 * Someone tells us one plaintext block has a common factor with n.  Does it help?
 *
 * YES.  If gcd(m, n) = p (a prime factor of n) then c = m^e mod n is also a
 * multiple of p (c = m^e - k*n, both terms divisible by p), so
 *            gcd(c, n) = p
 * Euclid's algorithm finds p quickly, q = n/p, then phi(n) and the private key
 * d = e^-1 mod phi(n): the WHOLE system is broken, not just that block.
 * The program runs the attack on a demo (n = 3599, e = 31) or on your own data.
 * Compile : gcc 25_rsa_common_factor_attack.c -o rsagcd
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}
static long long gcd(long long a, long long b) { return b ? gcd(b, a % b) : a; }
static long long powmod(long long b, long long e, long long m) {
    long long r = 1;
    b %= m;
    while (e) { if (e & 1) r = r * b % m; b = b * b % m; e >>= 1; }
    return r;
}
static long long modinv(long long a, long long m) {
    long long t = 0, nt = 1, r = m, nr = a % m;
    while (nr) { long long q = r / nr, x = t - q * nt; t = nt; nt = x; x = r - q * nr; r = nr; nr = x; }
    return (t % m + m) % m;
}

int main(void) {
    char buf[200];
    long long n = 3599, e = 31, c[50], p = 0, q, phi, d;
    int cnt = 0, i;

    rd("Modulus n (Enter = demo: n=3599, e=31, special block m=118): ", buf, sizeof buf);
    if (buf[0]) {
        char *tok;
        n = atoll(buf);
        rd("Public exponent e: ", buf, sizeof buf); e = atoll(buf);
        rd("Ciphertext blocks separated by spaces: ", buf, sizeof buf);
        for (tok = strtok(buf, " ,"); tok && cnt < 50; tok = strtok(NULL, " ,")) c[cnt++] = atoll(tok);
    } else {
        long long m[5] = {1000, 2042, 118, 77, 3001};      /* 118 = 2*59 shares the factor 59 with n */
        cnt = 5;
        printf("Demo plaintext blocks :");
        for (i = 0; i < cnt; i++) { c[i] = powmod(m[i], e, n); printf(" %lld", m[i]); }
        printf("   (118 = 2*59 shares factor 59 with n)\n");
        printf("Demo ciphertext blocks:");
        for (i = 0; i < cnt; i++) printf(" %lld", c[i]);
        printf("\n");
    }
    printf("\nAttack: compute gcd(c_i, n) for every ciphertext block\n");
    for (i = 0; i < cnt; i++) {
        long long g = gcd(c[i], n);
        printf("  gcd(%lld, %lld) = %lld%s\n", c[i], n, g, (g > 1 && g < n) ? "   <-- FACTOR OF n FOUND" : "");
        if (g > 1 && g < n && !p) p = g;
    }
    if (!p) { printf("No block shares a factor with n.\n"); return 0; }
    q = n / p;
    phi = (p - 1) * (q - 1);
    d = modinv(e, phi);
    printf("\nn = %lld * %lld,  phi(n) = %lld,  private key d = %lld\n", p, q, phi, d);
    printf("All blocks decrypted with d:");
    for (i = 0; i < cnt; i++) printf(" %lld", powmod(c[i], d, n));
    printf("\nConclusion: the knowledge DOES help - it factors n and breaks the whole cryptosystem.\n");
    return 0;
}
