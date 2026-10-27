/*
 * Program 7 : Decrypt a simple-substitution ciphertext (Poe's "Gold-Bug" cipher)
 *
 * Original ciphertext symbols:
 *   53‡‡†305))6*;4826)4‡.)4‡);806*;48†8¶60))85;;]8*;:‡*8†83
 *   (88)5*†;46(;88*96*?;8)*‡(;485);5*†2:*‡(;4956*2(5*—4)8¶8*
 *   ;4069285);)6†8)4‡‡;1(‡9;48081;8:8‡1;48†85;4)485†528806*81
 *   (‡9;48;(88;4(‡?34;48)4‡;161;:188;‡?;
 * To keep the source plain ASCII the odd symbols are written as:
 *      ‡ -> #     † -> +     ¶ -> @     — -> -
 *
 * Method (as given in the question):
 *  1. The most frequent symbol (8) is probably 'e'.
 *  2. The most frequent trigram ";48" is probably "the"  -> ; = t, 4 = h, 8 = e.
 *  3. Deduce further words (e.g. "the", "and", "degrees", "thirteen"...) to get
 *     the remaining letters.
 * The program counts symbol / trigram frequencies, shows a partial
 * decryption using steps 1-2, then the complete decryption.
 *
 * Compile : gcc 07_substitution_cipher_decrypt.c -o decrypt
 */
#include <stdio.h>
#include <string.h>

static const char *cipher =
    "53##+305))6*;4826)4#.)4#);806*;48+8@60))85;;]8*;:#*8+83"
    "(88)5*+;46(;88*96*?;8)*#(;485);5*+2:*#(;4956*2(5*-4)8@8*"
    ";4069285);)6+8)4##;1(#9;48081;8:8#1;48+85;4)485+528806*81"
    "(#9;48;(88;4(#?34;48)4#;161;:188;#?;";

static void apply(const char *pairs, char *out) {
    char key[256];
    size_t i, n = strlen(cipher);
    memset(key, 0, sizeof key);
    for (i = 0; pairs[i] && pairs[i + 1]; i += 2) key[(unsigned char)pairs[i]] = pairs[i + 1];
    for (i = 0; i < n; i++) {
        char k = key[(unsigned char)cipher[i]];
        out[i] = k ? k : '_';
    }
    out[n] = 0;
}

int main(void) {
    int cnt[256] = {0}, i, j, n = (int)strlen(cipher);
    char out[1000];

    printf("Cipher length: %d symbols\n\nSymbol frequencies (high to low):\n", n);
    for (i = 0; i < n; i++) cnt[(unsigned char)cipher[i]]++;
    for (j = 0; j < 8; j++) {                      /* print the 8 most frequent */
        int best = -1;
        for (i = 0; i < 256; i++) if (cnt[i] && (best < 0 || cnt[i] > cnt[best])) best = i;
        printf("  '%c' : %2d  (%.1f%%)\n", best, cnt[best], 100.0 * cnt[best] / n);
        cnt[best] = 0;
    }

    {   /* most frequent trigram */
        int bestc = 0, besti = 0;
        for (i = 0; i + 2 < n; i++) {
            int c = 0;
            for (j = 0; j + 2 < n; j++) if (!strncmp(cipher + i, cipher + j, 3)) c++;
            if (c > bestc) { bestc = c; besti = i; }
        }
        printf("\nMost frequent trigram: \"%.3s\" (%d times)  ->  guess \"the\"\n", cipher + besti, bestc);
    }

    printf("\nStep 1-2 : 8=e, ;=t, 4=h\n");
    apply("8e;t4h", out);
    printf("%s\n", out);

    printf("\nStep 3 : deduce more words (degrees, and, thirteen, minutes, ...)\n");
    apply("5a3g#o+d0l)s6i*n;t4h8e2b.p]w:y(r9m?u-c@v1f", out);
    printf("Key (cipher->plain): 5=a 3=g #=o +=d 0=l )=s 6=i *=n ;=t 4=h 8=e 2=b .=p ]=w :=y (=r 9=m ?=u -=c @=v 1=f\n\n");
    printf("Decrypted text:\n%s\n", out);
    printf("\nWith word breaks:\n");
    printf("a good glass in the bishop's hostel in the devil's seat twenty-one degrees and\n");
    printf("thirteen minutes northeast and by north main branch seventh limb east side shoot\n");
    printf("from the left eye of the death's-head a bee line from the tree through the shot\n");
    printf("fifty feet out\n");
    return 0;
}
