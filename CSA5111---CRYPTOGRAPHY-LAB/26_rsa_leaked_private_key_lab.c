/*
 * Program 26 : Bob leaks his RSA private key d and picks a new key pair (e', d')
 *              with the SAME modulus n.  Is this safe?   NO.
 *
 * Knowing (n, e, d) the attacker has a multiple of phi(n):  k = e*d - 1.
 * Writing k = 2^t * r (r odd) and picking a random a, some square root of 1
 * mod n that is not +-1 appears with probability >= 1/2; gcd(x-1, n) then
 * gives a prime factor of n.  With p and q known the attacker computes phi(n)
 * and therefore the private key d' of ANY new public exponent e'.
 * The new key pair gives no protection - a new MODULUS must be generated.
 * Compile : gcc 26_rsa_leaked_private_key.c -o rsaleak
 */
#include <stdio.h>
#include <stdlib.h>

typedef unsigned long long u64;

static u64 gcd(u64 a, u64 b) { return b ? gcd(b, a % b) : a; }
static u64 powmod(u64 b, u64 e, u64 m) {
    u64 r = 1;
    b %= m;
    while (e) { if (e & 1) r = r * b % m; b = b * b % m; e >>= 1; }
    return r;
}
static long long modinv(long long a, long long m) {
    long long t = 0, nt = 1, r = m, nr = a % m;
    while (nr) { long long q = r / nr, x = t - q * nt; t = nt; nt = x; x = r - q * nr; r = nr; nr = x; }
    return (t % m + m) % m;
}
static u64 next_prime(u64 x) {
    for (;; x++) { u64 i; int ok = x > 1; for (i = 2; i * i <= x; i++) if (x % i == 0) { ok = 0; break; } if (ok) return x; }
}

int main(void) {
    u64 p = next_prime(40000), q = next_prime(50000), n = p * q, phi = (p - 1) * (q - 1);
    u64 e = 65537, d, e2, d2, k, r, a, fp = 0;
    int t = 0;

    while (gcd(e, phi) != 1) e += 2;
    d = (u64)modinv((long long)e, (long long)phi);
    printf("Bob's key  : n = %llu (p, q secret), e = %llu, d = %llu   <-- d is LEAKED\n", n, e, d);

    /* Bob 'fixes' the problem by choosing a new key pair with the same n */
    e2 = 257; while (gcd(e2, phi) != 1) e2 += 2;
    d2 = (u64)modinv((long long)e2, (long long)phi);
    printf("Bob's new  : same n, e' = %llu, d' = %llu (secret)\n\n", e2, d2);

    printf("ATTACKER knows only n, e, d (and the new public e').\n");
    k = e * d - 1;
    r = k; while (r % 2 == 0) { r /= 2; t++; }
    printf("k = e*d - 1 = %llu = 2^%d * %llu\n", k, t, r);
    for (a = 2; a < 100 && !fp; a++) {
        u64 x = powmod(a, r, n);
        int i;
        if (x == 1 || x == n - 1) continue;
        for (i = 0; i < t; i++) {
            u64 y = x * x % n;
            if (y == 1) { fp = gcd(x - 1, n); break; }
            if (y == n - 1) break;
            x = y;
        }
    }
    if (!fp || fp == 1 || fp == n) { printf("Unlucky base choice - rerun with other bases.\n"); return 1; }
    printf("Found factor %llu of n  ->  p = %llu, q = %llu\n", fp, fp, n / fp);
    {
        u64 ph = (fp - 1) * (n / fp - 1);
        u64 d_att = (u64)modinv((long long)e2, (long long)ph);
        printf("Attacker computes phi(n) = %llu and d' = %llu\n", ph, d_att);
        printf("Bob's real d' = %llu  ->  %s\n", d2, d_att == d2 ? "attacker has BOB'S NEW PRIVATE KEY (NOT SAFE)" : "mismatch");
    }
    printf("\nConclusion: after a leak Bob must choose a completely new modulus n.\n");
    return 0;
}
