/*
 * Program 28 : Diffie-Hellman, and what happens if x*a is sent instead of a^x mod q
 *
 * Standard DH : Alice sends  a^x mod q , Bob sends  a^y mod q ,
 *               key K = a^(xy) mod q.  Eve would have to solve a DISCRETE LOG.
 *
 * Variant     : the participants send  x*a mod q  and  y*a mod q  (a public).
 *  Method to agree on a key (at least one):  Alice receives Y = y*a and computes
 *        K = x * Y = x*y*a mod q ;  Bob receives X = x*a and computes
 *        K = y * X = x*y*a mod q.      Both get the same key.
 *  Can Eve break it WITHOUT finding the secret numbers?  YES:
 *        K = X * Y * a^-1 mod q  (= x a * y a / a), needs only one modular inverse.
 *  Can Eve find the secret numbers?  YES:  x = X * a^-1 mod q ,  y = Y * a^-1 mod q.
 *  (multiplication mod q is easily reversed, unlike exponentiation).
 *
 * Compile : gcc 28_diffie_hellman_variant.c -o dhvariant
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long long u64;

static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}
static u64 powmod(u64 b, u64 e, u64 m) {
    u64 r = 1;
    b %= m;
    while (e) { if (e & 1) r = r * b % m; b = b * b % m; e >>= 1; }
    return r;
}
static u64 modinv(u64 a, u64 m) {
    long long t = 0, nt = 1, r = (long long)m, nr = (long long)(a % m);
    while (nr) { long long q = r / nr, x = t - q * nt; t = nt; nt = x; x = r - q * nr; r = nr; nr = x; }
    return (u64)((t % (long long)m + (long long)m) % (long long)m);
}

int main(void) {
    char buf[64];
    u64 q = 7919, a = 7, x = 1234, y = 4321, X, Y, ka, kb, ke, xe, ye;

    rd("Prime q (Enter = 7919): ", buf, sizeof buf); if (buf[0]) q = strtoull(buf, NULL, 10);
    rd("Public a (Enter = 7): ", buf, sizeof buf);   if (buf[0]) a = strtoull(buf, NULL, 10);
    rd("Alice's secret x (Enter = 1234): ", buf, sizeof buf); if (buf[0]) x = strtoull(buf, NULL, 10);
    rd("Bob's secret y (Enter = 4321): ", buf, sizeof buf);   if (buf[0]) y = strtoull(buf, NULL, 10);

    printf("\n=== Standard Diffie-Hellman ===\n");
    X = powmod(a, x, q); Y = powmod(a, y, q);
    printf("Alice sends a^x mod q = %llu, Bob sends a^y mod q = %llu\n", X, Y);
    printf("Alice key = Y^x = %llu, Bob key = X^y = %llu\n", powmod(Y, x, q), powmod(X, y, q));
    printf("Eve must solve a discrete logarithm to get x or y.\n");

    printf("\n=== Variant: send x*a mod q and y*a mod q ===\n");
    X = x % q * a % q; Y = y % q * a % q;
    printf("Alice sends X = x*a mod q = %llu,  Bob sends Y = y*a mod q = %llu\n", X, Y);
    ka = x % q * Y % q; kb = y % q * X % q;
    printf("Alice computes K = x*Y mod q = %llu\nBob   computes K = y*X mod q = %llu   (both = x*y*a mod q)\n", ka, kb);

    printf("\n--- Eve (sees q, a, X, Y) ---\n");
    {
        u64 ai = modinv(a, q);
        ke = X * Y % q * ai % q;
        xe = X * ai % q; ye = Y * ai % q;
        printf("a^-1 mod q = %llu (extended Euclid)\n", ai);
        printf("Eve's key  K = X*Y*a^-1 mod q = %llu  -> %s\n", ke, ke == ka ? "SAME KEY, found without any secret number" : "different");
        printf("Eve finds secret x = X*a^-1 mod q = %llu (Alice's was %llu mod q)\n", xe, x % q);
        printf("Eve finds secret y = Y*a^-1 mod q = %llu (Bob's was %llu mod q)\n", ye, y % q);
    }
    printf("\nConclusion: the variant is completely insecure.\n");
    return 0;
}
