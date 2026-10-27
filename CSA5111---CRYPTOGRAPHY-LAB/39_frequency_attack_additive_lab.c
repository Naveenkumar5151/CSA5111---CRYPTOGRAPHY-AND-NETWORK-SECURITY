/*
 * Program 39 : Letter-frequency attack on an additive (Caesar) cipher
 * No human intervention: all 26 shifts are tried, each candidate plaintext is
 * scored with a chi-squared statistic against English letter frequencies
 * (smaller = more English-like), and the candidates are printed in rough
 * order of likelihood.  The user chooses how many ("top 10" etc.).
 * Compile : gcc 39_frequency_attack_additive.c -o addattack
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const double ENG[26] = {8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
                               6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074};

typedef struct { int shift; double chi; } Cand;

static int cmp(const void *a, const void *b) {
    double d = ((const Cand *)a)->chi - ((const Cand *)b)->chi;
    return (d > 0) - (d < 0);
}
static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}

static const char *SAMPLE = 
    "NCJAEZRCLASJTDESPACLNETNPLYODEFOJZQEPNSYTBFPDQZCDPNFCPNZXXFY"
    "TNLETZYTYESPACPDPYNPZQLOGPCDLCTPDXZOPCYNCJAEZRCLASJPITDEDLEE"
    "SPTYEPCDPNETZYZQESPOTDNTAWTYPDZQXLESPXLETNDNZXAFEPCDNTPYNPLY"
    "OPWPNECTNLWPYRTYPPCTYRLAAWTNLETZYDZQNCJAEZRCLASJTYNWFOPPWPNE"
    "CZYTNNZXXPCNPNSTAMLDPOALJXPYENLCODOTRTELWNFCCPYNTPDNZXAFEPCA"
    "LDDHZCODLYOXTWTELCJNZXXFYTNLETZYDESPPYNCJAETZYZQLXPDDLRPECLY"
    "DQZCXDAWLTYEPIETYEZNTASPCEPIEHSTNSDSZFWOMPFYCPLOLMWPEZLYJZYP"
    "HSZOZPDYZESZWOESPDPNCPEVPJPLCWJNTASPCDDFNSLDESPNLPDLCNTASPCD"
    "TXAWJDSTQEPOPGPCJWPEEPCZQESPLWASLMPEMJLQTIPOLXZFYEHSTWPWLEPC"
    "XZYZLWASLMPETNDJDEPXDCPAWLNPOPLNSWPEEPCHTESLYZESPCDJXMZWMPNL"
    "FDPESPQCPBFPYNJZQWPEEPCDTYPYRWTDSEPIETDYZEFYTQZCXLYLEELNVPCN"
    "LYNZFYEESPWPEEPCDTYESPNTASPCEPIELYONZXALCPESPXHTESESPPIAPNEP"
    "OQCPBFPYNTPDEZCPNZGPCESPXPDDLRPHTESZFEVYZHTYRESPVPJ";

int main(void) {
    char buf[64], txt[5000];
    int cnt[26] = {0}, n = 0, i, s, top;
    Cand cand[26];

    rd("Enter ciphertext (Enter = built-in sample): ", txt, sizeof txt);
    if (!txt[0]) { strcpy(txt, SAMPLE); printf("(using the built-in sample, %d letters)\n", (int)strlen(txt)); }
    for (i = 0; txt[i]; i++)
        if (isalpha((unsigned char)txt[i])) { cnt[toupper((unsigned char)txt[i]) - 'A']++; n++; }
    if (n == 0) { printf("No letters found.\n"); return 1; }
    rd("How many top candidate plaintexts do you want (1-26)? ", buf, sizeof buf);
    top = atoi(buf);
    if (top < 1) top = 1;
    if (top > 26) top = 26;

    for (s = 0; s < 26; s++) {                        /* s = assumed key (shift) */
        double chi = 0;
        for (i = 0; i < 26; i++) {
            double exp = ENG[(i + 0) % 26] * n / 100.0;
            double obs = cnt[(i + s) % 26];           /* cipher letter (i+s) <- plain letter i */
            chi += (obs - exp) * (obs - exp) / exp;
        }
        cand[s].shift = s;
        cand[s].chi = chi;
    }
    qsort(cand, 26, sizeof(Cand), cmp);

    printf("\nTop %d possible plaintexts (most likely first):\n\n", top);
    for (i = 0; i < top; i++) {
        int k = cand[i].shift, j, shown = 0;
        printf("%2d) key = %2d  chi^2 = %8.1f : ", i + 1, k, cand[i].chi);
        for (j = 0; txt[j] && shown < 70; j++)
            if (isalpha((unsigned char)txt[j])) { putchar('a' + ((toupper((unsigned char)txt[j]) - 'A' - k + 26) % 26)); shown++; }
        printf("%s\n", txt[j] ? "..." : "");
    }
    return 0;
}
