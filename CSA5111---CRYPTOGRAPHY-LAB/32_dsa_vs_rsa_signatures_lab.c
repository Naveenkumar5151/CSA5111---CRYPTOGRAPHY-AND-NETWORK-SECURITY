/*
 * Program 32 : DSA signatures are randomised, RSA signatures are not
 * DSA picks a fresh secret k for every signature, so signing the SAME message
 * twice gives DIFFERENT (r,s) pairs, both valid.  A plain (textbook) RSA
 * signature s = H(m)^d mod n is deterministic: the same message always gives the
 * same signature.
 *
 * Implications
 *  - With RSA anybody who sees two identical signatures knows the two signed
 *    messages are identical (signatures can be compared / used as message
 *    identifiers); with DSA the signature of a repeated message looks new, so it
 *    leaks nothing about repetition.
 *  - DSA signing needs a good random source for k: k must be secret, unpredictable
 *    and NEVER reused.  If two messages are signed with the same k the private key
 *    x can be computed (shown below).  RSA signing needs no random numbers.
 *  - A DSA signature cannot be treated as a unique "fingerprint" of the message.
 * Toy parameters (small numbers!): p = 283, q = 47, g = 64, hash = simple checksum mod q.
 * Compile : gcc 32_dsa_vs_rsa_signatures.c -o dsarsa
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef long long ll;

static const ll P = 283, Q = 47, G = 64;

static ll powmod(ll b, ll e, ll m) { ll r = 1; b %= m; while (e) { if (e & 1) r = r * b % m; b = b * b % m; e >>= 1; } return r; }
static ll modinv(ll a, ll m) { ll t = 0, nt = 1, r = m, nr = ((a % m) + m) % m; while (nr) { ll q = r / nr, x = t - q * nt; t = nt; nt = x; x = r - q * nr; r = nr; nr = x; } return (t % m + m) % m; }
static ll hash_q(const char *m) { ll h = 7; while (*m) h = (h * 31 + (unsigned char)*m++) % 1000003; return h % Q; }

static int dsa_sign(const char *m, ll x, ll k, ll *r, ll *s) {
    *r = powmod(G, k, P) % Q;
    *s = modinv(k, Q) * ((hash_q(m) + x * *r) % Q) % Q;
    return *r != 0 && *s != 0;
}
static int dsa_verify(const char *m, ll y, ll r, ll s) {
    ll w, u1, u2, v;
    if (r <= 0 || r >= Q || s <= 0 || s >= Q) return 0;
    w = modinv(s, Q); u1 = hash_q(m) * w % Q; u2 = r * w % Q;
    v = (powmod(G, u1, P) * powmod(y, u2, P) % P) % Q;
    return v == r;
}

int main(void) {
    const char *msg = "pay Bob 100 rupees";
    ll x = 24, y = powmod(G, x, P), r1, s1, r2, s2, k1, k2;
    ll rn = 3599, e = 31, d = 3031;                       /* toy RSA key from Program 24 */
    int tries;

    srand((unsigned)time(NULL));
    printf("DSA private key x = %lld, public key y = g^x mod p = %lld\nMessage: \"%s\"\n\n", x, y, msg);

    printf("--- DSA : sign the same message twice ---\n");
    do { k1 = 1 + rand() % (Q - 1); } while (!dsa_sign(msg, x, k1, &r1, &s1));
    do { k2 = 1 + rand() % (Q - 1); } while (k2 == k1 || !dsa_sign(msg, x, k2, &r2, &s2));
    printf("Signature 1 (k=%2lld): (r,s) = (%lld,%lld)  verify: %s\n", k1, r1, s1, dsa_verify(msg, y, r1, s1) ? "valid" : "INVALID");
    printf("Signature 2 (k=%2lld): (r,s) = (%lld,%lld)  verify: %s\n", k2, r2, s2, dsa_verify(msg, y, r2, s2) ? "valid" : "INVALID");
    printf("Signatures are %s\n\n", (r1 == r2 && s1 == s2) ? "the same" : "DIFFERENT although the message is identical");

    printf("--- RSA (toy key n=%lld e=%lld d=%lld) : sign the same message twice ---\n", rn, e, d);
    {
        ll h = hash_q(msg) + 1, a = powmod(h, d, rn), b = powmod(h, d, rn);
        printf("Signature 1 = %lld, Signature 2 = %lld  -> %s  (verify: %s)\n\n", a, b, a == b ? "IDENTICAL" : "different", powmod(a, e, rn) == h ? "valid" : "INVALID");
    }

    printf("--- Danger: reusing k in DSA reveals the private key ---\n");
    for (tries = 0; tries < 100; tries++) {
        const char *m2 = "pay Mallory 5000 rupees";
        ll ra, sa, rb, sb, num, den, k, xr;
        k = 1 + rand() % (Q - 1);
        if (!dsa_sign(msg, x, k, &ra, &sa) || !dsa_sign(m2, x, k, &rb, &sb)) continue;
        den = ((sa - sb) % Q + Q) % Q;
        if (den == 0) continue;
        num = ((hash_q(msg) - hash_q(m2)) % Q + Q) % Q;
        k = num * modinv(den, Q) % Q;                         /* k = (h1-h2)/(s1-s2) */
        xr = (((sa * k - hash_q(msg)) % Q + Q) % Q) * modinv(ra, Q) % Q;
        printf("Two messages signed with the same k -> attacker recovers k = %lld and x = %lld (true x = %lld)\n", k, xr, x);
        break;
    }
    return 0;
}
