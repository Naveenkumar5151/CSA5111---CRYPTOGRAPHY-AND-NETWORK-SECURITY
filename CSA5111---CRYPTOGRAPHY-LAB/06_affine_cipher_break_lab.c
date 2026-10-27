/*
 * Program 6 : Break an affine cipher using letter frequencies.
 * Given : most frequent ciphertext letter = B, second most frequent = U.
 * In English the most frequent letters are E (4) and T (19).
 * Assume  E -> B  and  T -> U :
 *      a*4  + b = 1  (mod 26)
 *      a*19 + b = 20 (mod 26)      subtract:  15a = 19 (mod 26)
 *      15^-1 = 7 (mod 26)  =>  a = 19*7 = 133 = 3 (mod 26),   b = 1 - 12 = 15
 * Key (a,b) = (3,15).   Decryption:  p = 3^-1 (C - 15) = 9 (C - 15) mod 26
 * This program does the same search by computer for any pair of letters and
 * (optionally) decrypts a ciphertext you type in.
 * Compile : gcc 06_affine_cipher_break.c -o affbreak
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}
static int gcd(int a, int b) { return b ? gcd(b, a % b) : a; }
static int modinv(int a) { int i; for (i = 1; i < 26; i++) if ((a * i) % 26 == 1) return i; return 0; }

static void decrypt(const char *c, char *p, int a, int b) {
    int ai = modinv(a), i;
    for (i = 0; c[i]; i++) {
        if (isalpha((unsigned char)c[i])) {
            int x = toupper((unsigned char)c[i]) - 'A';
            p[i] = (char)('a' + (ai * ((x - b + 26) % 26)) % 26);
        } else p[i] = c[i];
    }
    p[i] = 0;
}

static int english_score(const char *p) {
    int s = 0, i;
    for (i = 0; p[i]; i++) if (strchr("etaoinshr", p[i])) s++;
    return s;
}

int main(void) {
    char txt[2000], plain[2000], best[2000] = "";
    const char *top = "ETAOIN";
    int cnt[26] = {0}, m1 = 1, m2 = 20, i, j, a, b, bestscore = -1, cand = 0, besta = 0, bestb = 0;

    rd("Enter ciphertext (or press Enter to use B and U as the two top letters): ", txt, sizeof txt);
    if (txt[0]) {
        for (i = 0; txt[i]; i++) if (isalpha((unsigned char)txt[i])) cnt[toupper((unsigned char)txt[i]) - 'A']++;
        m1 = 0;
        for (i = 1; i < 26; i++) if (cnt[i] > cnt[m1]) m1 = i;
        m2 = (m1 == 0) ? 1 : 0;
        for (i = 0; i < 26; i++) if (i != m1 && cnt[i] > cnt[m2]) m2 = i;
    }
    printf("Most frequent cipher letter  : %c\nSecond most frequent letter  : %c\n\n", 'A' + m1, 'A' + m2);
    printf("Trying pairs of likely plaintext letters (E,T,A,O,I,N):\n");
    for (i = 0; i < 6; i++)
        for (j = 0; j < 6; j++) {
            if (i == j) continue;
            int p1 = top[i] - 'A', p2 = top[j] - 'A';
            for (a = 1; a < 26; a++) {
                if (gcd(a, 26) != 1) continue;
                for (b = 0; b < 26; b++)
                    if ((a * p1 + b) % 26 == m1 && (a * p2 + b) % 26 == m2) {
                        cand++;
                        printf("%2d) %c->%c, %c->%c  gives  a = %2d, b = %2d", cand, top[i], 'A' + m1, top[j], 'A' + m2, a, b);
                        if (txt[0]) {
                            int sc;
                            decrypt(txt, plain, a, b);
                            sc = english_score(plain);
                            printf("   score %d", sc);
                            if (sc > bestscore) { bestscore = sc; strcpy(best, plain); besta = a; bestb = b; }
                        }
                        printf("\n");
                    }
            }
        }
    if (txt[0]) printf("\nMost English-like result: key (a,b) = (%d,%d)\nPlaintext: %s\n", besta, bestb, best);
    else {
        printf("\nMost likely key (E->B, T->U): a = 3, b = 15\n");
        printf("Check: E(4)  = 3*4+15  = 27 mod 26 = 1  = B\n");
        printf("       E(19) = 3*19+15 = 72 mod 26 = 20 = U\n");
        printf("Decryption formula: p = 9*(C - 15) mod 26\n");
    }
    return 0;
}
