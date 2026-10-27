/*
 * Program 8 : Monoalphabetic cipher with a keyword
 * The cipher alphabet is generated from a keyword: write the keyword (without
 * repeated letters) followed by the unused letters in normal order.
 * Example, keyword CIPHER:
 *   plain : a b c d e f g h i j k l m n o p q r s t u v w x y z
 *   cipher: C I P H E R A B D F G J K L M N O Q S T U V W X Y Z
 * Compile : gcc 08_keyword_monoalphabetic.c -o keywordcipher
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

int main(void) {
    char buf[64], kw[200], cip[27], text[1000], res[1000];
    int used[26] = {0}, n = 0, i, ch, enc[26], dec[26];

    rd("Enter keyword (e.g. CIPHER): ", kw, sizeof kw);
    for (i = 0; kw[i]; i++) {
        if (!isalpha((unsigned char)kw[i])) continue;
        int c = toupper((unsigned char)kw[i]) - 'A';
        if (!used[c]) { used[c] = 1; cip[n++] = (char)('A' + c); }
    }
    for (i = 0; i < 26; i++) if (!used[i]) cip[n++] = (char)('A' + i);
    cip[26] = 0;

    printf("\nplain : a b c d e f g h i j k l m n o p q r s t u v w x y z\ncipher: ");
    for (i = 0; i < 26; i++) printf("%c ", cip[i]);
    printf("\n\n");
    for (i = 0; i < 26; i++) { enc[i] = cip[i] - 'A'; dec[cip[i] - 'A'] = i; }

    rd("1. Encrypt  2. Decrypt : ", buf, sizeof buf);
    ch = atoi(buf);
    rd("Enter text: ", text, sizeof text);
    for (i = 0; text[i]; i++) {
        char c = text[i];
        int *m = (ch == 1) ? enc : dec;
        if (isupper((unsigned char)c))      res[i] = (char)('A' + m[c - 'A']);
        else if (islower((unsigned char)c)) res[i] = (char)('a' + m[c - 'a']);
        else res[i] = c;
    }
    res[i] = 0;
    printf("%s : %s\n", ch == 1 ? "Cipher text" : "Plain text ", res);
    return 0;
}
