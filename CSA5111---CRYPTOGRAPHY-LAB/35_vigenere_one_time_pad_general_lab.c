/*
 * Program 35 : One-time-pad version of the Vigenere cipher (general program)
 * The key is a stream of random numbers between 0 and 25 (as long as the message);
 * if the key is 3 19 5 ..., the first letter is shifted by 3, the second by 19,
 * the third by 5 and so on.
 *      C_i = (P_i + k_i) mod 26         P_i = (C_i - k_i) mod 26
 * Choose: encrypt with your own key stream, encrypt with a randomly generated
 * key stream, or decrypt.
 * Compile : gcc 35_vigenere_one_time_pad_general.c -o otpgeneral
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}

int main(void) {
    char buf[1000], txt[500], out[500];
    int key[500], n = 0, i, ch, nk = 0;

    printf("ONE-TIME PAD (Vigenere)\n1. Encrypt with my own key stream\n2. Encrypt with a random key stream\n3. Decrypt\n");
    rd("Choice: ", buf, sizeof buf);
    ch = atoi(buf);
    rd("Enter text: ", buf, sizeof buf);
    for (i = 0; buf[i]; i++) if (isalpha((unsigned char)buf[i])) txt[n++] = (char)toupper((unsigned char)buf[i]);
    txt[n] = 0;
    if (n == 0) { printf("No letters.\n"); return 1; }

    if (ch == 2) {
        srand((unsigned)time(NULL));
        for (i = 0; i < n; i++) key[i] = rand() % 26;
        nk = n;
        printf("Random key stream: ");
        for (i = 0; i < n; i++) printf("%d ", key[i]);
        printf("\n");
    } else {
        char *tok;
        rd("Enter key stream (numbers 0-25 separated by spaces): ", buf, sizeof buf);
        for (tok = strtok(buf, " ,"); tok && nk < 500; tok = strtok(NULL, " ,")) key[nk++] = atoi(tok);
        if (nk < n) { printf("A one-time pad key must be at least as long as the message (%d numbers needed, %d given).\n", n, nk); return 1; }
        for (i = 0; i < n; i++) if (key[i] < 0 || key[i] > 25) { printf("Key numbers must be between 0 and 25.\n"); return 1; }
    }
    for (i = 0; i < n; i++) {
        int s = (ch == 3) ? 26 - key[i] : key[i];
        out[i] = (char)('A' + (txt[i] - 'A' + s) % 26);
    }
    out[n] = 0;
    printf("%s : %s\n", ch == 3 ? "Plain text " : "Cipher text", out);
    return 0;
}
