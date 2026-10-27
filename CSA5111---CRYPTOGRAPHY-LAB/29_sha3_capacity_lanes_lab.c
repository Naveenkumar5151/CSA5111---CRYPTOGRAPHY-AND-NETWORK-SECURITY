/*
 * Program 29 : SHA-3 (Keccak) - how long until every capacity lane is non-zero?
 * SHA-3 option with block size r = 1024 bits : state = 1600 bits = 5x5 lanes of
 * 64 bits.  Rate = 1024 bits = 16 lanes, capacity = 576 bits = 9 lanes.
 * Lane index i = x + 5y.  The first message block P0 is XORed into the 16 rate
 * lanes (each has at least one non-zero bit); the 9 capacity lanes start as 0.
 * Then Keccak-f[1600] (24 rounds of theta, rho, pi, chi, iota) is applied.
 *
 * Answer: after the THETA step of the VERY FIRST ROUND.  Theta XORs into every lane
 * a value built from two neighbouring columns; each column already contains a
 * non-zero rate lane, so every lane (including all capacity lanes) becomes non-zero.
 * The program runs real Keccak steps and tracks the ORIGINAL capacity lanes even
 * after pi moves them (the permutation is ignored as the question says).
 * Compile : gcc 29_sha3_capacity_lanes.c -o sha3lanes
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long long u64;
#define ROTL(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const u64 RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
static const int rotc[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int piln[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

static u64 st[25];
static int lab[25];                 /* lab[i] = original lane number now sitting at position i */
static int rate_lanes;

static int count_capacity_nonzero(void) {
    int seen[25] = {0}, i, c = 0;
    for (i = 0; i < 25; i++) if (lab[i] >= rate_lanes && st[i]) seen[lab[i]] = 1;
    for (i = rate_lanes; i < 25; i++) c += seen[i];
    return c;
}

int main(int argc, char **argv) {
    int rbits = 1024, i, j, round, cap, hit = 0;
    u64 bc[5], t;

    if (argc > 1) rbits = atoi(argv[1]);
    if (rbits % 64 || rbits < 64 || rbits >= 1600) { printf("block size must be a multiple of 64 below 1600\n"); return 1; }
    rate_lanes = rbits / 64;
    cap = 25 - rate_lanes;
    printf("Block size r = %d bits = %d rate lanes; capacity = %d bits = %d lanes\n\n", rbits, rate_lanes, 1600 - rbits, cap);

    for (i = 0; i < 25; i++) { st[i] = (i < rate_lanes) ? (0x0123456789ABCDEFULL + (u64)i * 0x1111ULL) : 0; lab[i] = i; }
    printf("Start                      : %d of %d capacity lanes non-zero\n", count_capacity_nonzero(), cap);

    for (round = 0; round < 24 && !hit; round++) {
        for (i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (i = 0; i < 5; i++) { t = bc[(i + 4) % 5] ^ ROTL(bc[(i + 1) % 5], 1); for (j = 0; j < 25; j += 5) st[j + i] ^= t; }
        printf("Round %2d after theta       : %d of %d capacity lanes non-zero\n", round + 1, count_capacity_nonzero(), cap);
        if (count_capacity_nonzero() == cap) { hit = round + 1; break; }

        t = st[1]; { int tl = lab[1];
        for (i = 0; i < 24; i++) { u64 b0; int bl; j = piln[i]; b0 = st[j]; bl = lab[j]; st[j] = ROTL(t, rotc[i]); lab[j] = tl; t = b0; tl = bl; } }
        printf("Round %2d after rho and pi  : %d of %d\n", round + 1, count_capacity_nonzero(), cap);
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) bc[i] = st[j + i];
            for (i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        st[0] ^= RC[round];
        printf("Round %2d after chi, iota   : %d of %d\n", round + 1, count_capacity_nonzero(), cap);
    }
    printf("\nAll %d capacity lanes contain a non-zero bit after round %d (during its theta step).\n", cap, hit);
    return 0;
}
