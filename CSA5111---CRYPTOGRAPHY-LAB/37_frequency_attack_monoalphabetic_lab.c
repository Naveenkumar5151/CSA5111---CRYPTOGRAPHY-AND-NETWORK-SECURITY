/*
 * Program 37 : Letter-frequency attack on ANY monoalphabetic substitution
 *              cipher, without human intervention.
 *
 * Method
 *  1. Count the letters of the ciphertext and build a first guess by matching
 *     cipher letters to English letters in order of frequency
 *     (ETAOINSHRDLCUMWFGYPBVKJXQZ).
 *  2. Improve the guess automatically by simulated annealing: swap two entries of the
 *     key and keep the swap if the plaintext looks more like English (a worse
 *     swap is accepted with a small probability so the search can escape traps).  "Looks
 *     like English" = log-likelihood from letter, bigram (TH, HE, IN ...) and
 *     trigram (THE, AND, ING ...) frequencies.
 *  3. Several random restarts are made; the best DISTINCT keys are sorted and
 *     the user can ask for the "top N" possible plaintexts.
 * Works best for ciphertexts of 200+ letters (statistics need enough text).
 *
 * Compile : gcc 37_frequency_attack_monoalphabetic.c -o monoattack -lm
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#define MAXN 20000
#define RESTARTS 12
#define ITERS 20000
#define MAXRES 64

static const double ENG[26] = {8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
                               6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074};
static const char *FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

/* English statistics measured from ~560,000 letters of English text (counts per million) */
static const unsigned short BGC[26][26] = {   /* bigram counts per million */
    {0,2669,4156,1558,40,355,1229,2,2855,31,706,10568,4350,15238,0,1556,53,11679,7789,15408,1401,1053,279,308,1759,60},
    {1281,15,225,53,3959,0,0,0,1126,2412,0,3612,22,4,965,91,0,1256,384,67,3228,0,0,0,2237,0},
    {4719,0,972,15,9584,6,0,4051,2108,0,1059,3870,26,13,10767,73,20,1023,91,7892,2423,0,0,0,58,0},
    {990,158,22,708,9499,13,73,0,6058,22,0,288,4,6,1920,0,0,96,988,98,1245,53,29,2,234,0},
    {3391,368,7713,12207,2524,2995,898,203,1066,2,4,3060,3794,15021,174,2671,1480,20324,12920,5502,40,1717,798,5399,1497,0},
    {1008,4,0,2,1357,856,8,0,3950,0,8,386,2,0,5911,26,0,2112,22,1133,1728,0,0,0,444,0},
    {760,15,22,0,3704,15,236,1390,1213,0,0,469,78,1158,152,102,0,1535,444,192,1064,2,0,0,2,0},
    {6657,6,4,4,24608,2,0,4,4692,0,0,26,67,29,3979,0,0,366,46,1189,114,0,6,0,89,0},
    {1965,3610,8106,1835,2955,4715,2443,0,105,0,230,3197,2727,22795,12716,945,29,1790,13208,11800,82,2164,0,205,0,404},
    {35,0,13,0,2327,0,0,0,0,0,0,0,0,0,49,6,0,0,0,0,147,0,0,0,0,0},
    {131,0,8,0,1810,2,24,2,389,0,0,29,0,140,2,91,0,26,397,2,80,0,38,0,0,0},
    {5204,8,51,1303,9322,735,22,0,8880,2,4,5041,13,22,3096,62,0,64,1672,1359,2577,111,116,0,3116,0},
    {5142,1082,44,6,10078,2,0,0,1609,0,4,55,773,58,2682,3020,0,31,1240,154,1173,22,0,0,42,0},
    {3990,31,4733,9553,5967,440,8462,84,1649,11,183,878,348,599,5289,100,2,22,8627,12573,1399,865,11,2,1784,11},
    {210,2638,1911,4587,456,8551,965,38,424,0,301,1772,3946,20555,809,3876,0,16343,1840,5508,6405,1951,1860,60,82,53},
    {4375,0,15,214,5276,6,6,172,1189,0,15,3514,20,35,2445,1710,0,5743,190,2372,1256,0,2,0,1761,2},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1705,0,0,0,0,0},
    {8314,221,1124,1323,17212,252,1448,8,8515,2,1580,172,2814,1656,5439,473,0,1927,4131,2515,959,272,335,6,2224,0},
    {1124,0,1314,33,14339,158,17,1784,5830,4,120,652,105,46,3170,2014,49,8,5394,9466,3284,0,35,0,688,0},
    {6729,46,339,91,15254,53,0,34159,15511,0,0,918,219,60,8133,152,0,5705,4299,2403,1786,15,1064,4,3000,0},
    {1236,1665,1433,740,2593,109,552,0,1453,0,4,2700,2586,4167,78,1238,0,3530,4404,5151,4,0,0,2,0,0},
    {3031,0,0,0,6778,0,0,0,1585,0,0,0,31,0,281,0,0,0,2,2,2,0,0,0,0,0},
    {1737,0,0,11,945,0,0,2499,4093,0,0,111,0,252,2237,0,0,274,167,0,0,0,71,0,0,4},
    {451,0,1426,6,947,0,0,42,321,0,0,0,15,0,33,1207,0,0,33,889,0,0,4,46,80,0},
    {55,22,55,0,176,0,0,0,541,0,0,44,53,480,2944,1661,0,509,693,726,0,11,292,0,8,40},
    {114,0,0,0,438,6,0,0,96,0,0,0,0,0,6,2,0,0,2,0,0,0,0,0,15,0}
};
static const char *TGS[] = {"THE","ION","TIO","ING","ENT","AND","FOR","TER","ECT","ATI","MEN","ATE","LIC","NOT","ONS","CTI","CON","THA","VER","ICE","TRI","ARE","ALL","HAT","THI","HER","ERS","ITH","ASS","YOU","TED","RES","CLA","SIO","AME","HIS","PRO","STA","BUT","ENS","WIT","NSE","CEN","USE","STR","THO","JEC","BJE","BLE","OBJ","RIB","LAS","PRE","TAT","NCE","PAR","IST","IBU","ERE","COM","ERA","VAL","ATT","ITE","ABL","COP","WOR","INT","ESS","UTE","INE","EME","ONT","MET","NTE","DER","ANY","SSI","UME","PER","ARY","MOD","DEF","TEM","PLE","SED","CAL","UND","TYP","OTH","ALU","ITI","RAM","RAT","NAM","INS","YPE","IVE","MPL","ORK","NDE","ORM","TIN","NTA","RIN","EXC","RSI","EQU","NTI","IFI","OVE","MAT","UNC","ICA","EPT","NTS","CEP","FIN","ARG","TOR","IDE","CES","ODE","RED","RAN","RIG","DIS","ARA","ETH","OPY","COD","OPE","FUN","ERM","NED","LUE","OUR","XCE","LIS","PTI","NST","APP","REA","EXP","ENC","ONE","SES","EFI","CHA","NCT","AIN","DIF","TUR","IMP","ESE","GRA","TAN","TIC","ANT","MAY","DIN","RET","HAN","HEN","ECI","WHE","GHT","TTE","NDI","OMP","ARI","IGH","ROM","FRO","REC","HOD","IES","CAN","LES","SEC","WAR","ALS","NAL","ISE","RAR","ART","TTR","ASE","TAI","EVE","ONA","TES","ODI","ACT","BRA","LOW","ODU","RMA","NER","FIE","FER","PLI","INA","XPR","BLI","REE","SIN","UST","ACE","SPE","LIB","PEC","CAT","TRA","ANC","IBR","INC","REN","RAC","WHI","INI","PAT","UBL","IND","ICT","EXT","ANG","SUC","DIC","ETE","LLY","ETU","URN","TEN","NGE","ERI","ILL","EXE","OUN","ORT","SER","OGR","SEL","DED","ROG","SSE","LED","KEY","SUB","OSE","HOU","ITS","RIA","QUE","PUB","ULT","CUM","LIT","UCH","TIT","LLE","DOC","GET","ENE","NTR","HIC","POS","POR","ICH","ORD","RRE","LLO","NUM","LIN","IGN","OCU","RAL","AGE","CLU","UTI","XEC","TAB","IED","COR","OND","ECU","ERN","GEN","REF","ANS","OLL","IAL","LEM","CUT","RGU","GUM","HAV","IRE","PRI","COV","ERR","SEQ","DES","NCL","END","ULE","FRE","UEN","LAT","ESP","SIG","HES","OFT","ELF","MES","ADD","RMI","EST","DIT","LUD","ONL","SOF","ACK","HAR","EAT","MBE","BER","WIL","SHO","ORE","PPL","RCE","MUS","DUL","OUL","ULD","FTW","TWA","AVE","HIN","FFE","OUT","HAS","NON","MAN","VAR","LOC","ACC","TIV","RAI","STE","ITY","NEW","ETA","ACH","NLY","ILE","OTI","NIT","AIL","DEN","RMS","FIC","REP","TAR","VEN","RTI","NAR","CTS","SET","BIN","EAN","ROV","UAL","CTE","SOU","URC","AUS","TRU","TEX","UMB","OVI","VID","QUI","LSO","SAM","SEN","CCE","RRO","MER","CRI","RIC","ATO","SCR","NIN","FOL","ROR","ORS","OMM","ROU"};
static const unsigned short TGV[] = {29729,16215,12644,9421,9406,7359,6489,5956,5897,5817,5054,4811,4752,4675,4545,4497,4379,4346,4234,4210,4175,4160,4160,4110,4098,4039,3965,3852,3817,3740,3713,3621,3604,3536,3512,3485,3435,3432,3402,3373,3317,3269,3222,3172,3124,3112,3080,3077,3038,2947,2908,2888,2885,2876,2802,2760,2737,2716,2692,2666,2636,2606,2595,2571,2553,2550,2532,2518,2500,2494,2432,2429,2385,2358,2337,2334,2319,2319,2260,2240,2228,2228,2228,2225,2192,2186,2180,2168,2160,2151,2124,2095,2059,2059,2035,2026,1988,1982,1982,1979,1947,1947,1908,1905,1899,1879,1873,1870,1843,1828,1822,1822,1819,1810,1810,1805,1805,1796,1784,1775,1769,1766,1739,1736,1722,1719,1719,1719,1719,1707,1704,1692,1677,1671,1651,1642,1630,1630,1627,1618,1618,1615,1609,1597,1591,1589,1583,1580,1571,1553,1550,1550,1550,1544,1535,1532,1532,1523,1512,1512,1512,1512,1506,1503,1500,1476,1473,1464,1464,1455,1438,1435,1429,1426,1420,1420,1417,1411,1408,1399,1393,1370,1370,1367,1361,1355,1355,1346,1340,1331,1322,1319,1316,1313,1304,1296,1287,1284,1266,1257,1251,1239,1239,1236,1230,1225,1222,1222,1222,1219,1216,1213,1213,1207,1204,1198,1195,1189,1189,1186,1186,1186,1180,1180,1174,1171,1165,1162,1162,1151,1148,1148,1142,1139,1127,1127,1124,1121,1118,1118,1109,1109,1109,1091,1088,1088,1088,1083,1080,1077,1077,1071,1071,1068,1059,1059,1056,1056,1053,1050,1047,1041,1038,1029,1029,1029,1023,1020,1011,1011,1009,1006,1006,1003,1003,994,991,991,988,985,985,985,982,982,979,979,976,970,970,970,967,967,964,955,955,955,952,949,946,940,935,935,932,929,926,926,920,920,917,914,911,908,902,899,893,887,884,881,881,878,875,872,872,867,867,864,861,858,852,852,846,846,846,846,846,846,843,843,843,843,840,840,840,837,834,834,834,831,828,825,822,822,816,810,807,804,801,798,798,798,795,793,790,787,784,784,781,778,772,772,769,763,760,757,757,754,754,754,754,754,751,748,748,745,742,736,733,730,730,724,724,722,716,710,707,704,701,695,695,695};
#define NTG 400

static double L1[26], L2[26][26], L3[26][26][26];
static int C[MAXN], N, present[26];

typedef struct { int key[26]; double score; } Res;      /* key[cipher letter] = plain letter */
static Res res[MAXRES];
static int nres = 0;

static void init_tables(void) {
    int i, j, k;
    for (i = 0; i < 26; i++) L1[i] = log(ENG[i] / 100.0);
    for (i = 0; i < 26; i++) for (j = 0; j < 26; j++) L2[i][j] = log((BGC[i][j] + 20.0) / 1000000.0);
    for (i = 0; i < 26; i++) for (j = 0; j < 26; j++) for (k = 0; k < 26; k++) L3[i][j][k] = log(5.0 / 1000000.0);
    for (i = 0; i < NTG; i++) L3[TGS[i][0] - 'A'][TGS[i][1] - 'A'][TGS[i][2] - 'A'] = log(TGV[i] / 1000000.0);
}

static double score(const int *key) {
    int i;
    double s = 0;
    for (i = 0; i < N; i++) {
        int a = key[C[i]];
        s += L1[a];
        if (i + 1 < N) { int b = key[C[i + 1]]; s += L2[a][b]; if (i + 2 < N) s += L3[a][b][key[C[i + 2]]]; }
    }
    return s;
}

static void add_result(const int *key, double sc) {
    int i, worst = 0;
    for (i = 0; i < nres; i++) {                  /* same plaintext = same mapping on the letters that occur */
        int j, same = 1;
        for (j = 0; j < 26; j++) if (present[j] && res[i].key[j] != key[j]) { same = 0; break; }
        if (same) return;
    }
    if (nres < MAXRES) { memcpy(res[nres].key, key, 26 * sizeof(int)); res[nres++].score = sc; return; }
    for (i = 1; i < nres; i++) if (res[i].score < res[worst].score) worst = i;
    if (sc > res[worst].score) { memcpy(res[worst].key, key, 26 * sizeof(int)); res[worst].score = sc; }
}

static int cmp(const void *a, const void *b) {
    double d = ((const Res *)b)->score - ((const Res *)a)->score;
    return (d > 0) - (d < 0);
}
static void rd(const char *p, char *b, int n) {
    printf("%s", p);
    if (!fgets(b, n, stdin)) b[0] = 0;
    b[strcspn(b, "\r\n")] = 0;
}

static const char *SAMPLE = 
    "WLEGRAOLJGTEZDRTHGLJWRZWHJQIDRCIEAYRHWTQZVCHDYALDHWCLHWAPPCQ"
    "ZWJRZAQZQRTHGLHDHQWHAYJIBHLDJLZHDPAIHLQWLEGRAOLJGTEHMZDRDJRR"
    "THZQRHLDHWRZAQAYRTHIZDWZGXZQHDAYPJRTHPJRZWDWAPGCRHLDWZHQWHJQ"
    "IHXHWRLZWJXHQOZQHHLZQOJGGXZWJRZAQDAYWLEGRAOLJGTEZQWXCIHHXHWR"
    "LAQZWWAPPHLWHWTZGFJDHIGJEPHQRWJLIDIZOZRJXWCLLHQWZHDWAPGCRHLG"
    "JDDUALIDJQIPZXZRJLEWAPPCQZWJRZAQDRTHHQWLEGRZAQAYJPHDDJOHRLJQ"
    "DYALPDGXJZQRHMRZQRAWZGTHLRHMRUTZWTDTACXIFHCQLHJIJFXHRAJQEAQH"
    "UTAIAHDQARTAXIRTHDHWLHRNHEHJLXEWZGTHLDDCWTJDRTHWJHDJLWZGTHLD"
    "ZPGXEDTZYRHIHBHLEXHRRHLAYRTHJXGTJFHRFEJYZMHIJPACQRUTZXHXJRHL"
    "PAQAJXGTJFHRZWDEDRHPDLHGXJWHIHJWTXHRRHLUZRTJQARTHLDEPFAXFHWJ"
    "CDHRTHYLHVCHQWEAYXHRRHLDZQHQOXZDTRHMRZDQARCQZYALPJQJRRJWNHLW"
    "JQWACQRRTHXHRRHLDZQRTHWZGTHLRHMRJQIWAPGJLHRTHPUZRTRTHHMGHWRH"
    "IYLHVCHQWZHDRALHWABHLRTHPHDDJOHUZRTACRNQAUZQORTHNHE";

int main(void) {
    static char txt[MAXN + 10];
    char buf[64];
    int cnt[26] = {0}, order[26], key[26], bestkey[26], i, r, it, top;

    rd("Enter ciphertext (Enter = built-in sample): ", txt, MAXN);
    if (!txt[0]) { strcpy(txt, SAMPLE); printf("(using the built-in sample)\n"); }
    for (i = 0; txt[i] && N < MAXN; i++) if (isalpha((unsigned char)txt[i])) { C[N++] = toupper((unsigned char)txt[i]) - 'A'; cnt[C[N - 1]]++; present[C[N - 1]] = 1; }
    if (N < 30) { printf("Ciphertext too short for a frequency attack (need at least ~30 letters).\n"); return 1; }
    rd("How many top candidate plaintexts do you want? ", buf, sizeof buf);
    top = atoi(buf);
    if (top < 1) top = 1;
    if (top > 10) top = 10;

    init_tables();
    srand(12345);
    for (i = 0; i < 26; i++) order[i] = i;                         /* cipher letters sorted by frequency */
    for (i = 0; i < 26; i++) { int j; for (j = i + 1; j < 26; j++) if (cnt[order[j]] > cnt[order[i]]) { int t = order[i]; order[i] = order[j]; order[j] = t; } }
    printf("\nCipher letters by frequency: ");
    for (i = 0; i < 26; i++) printf("%c(%d) ", 'A' + order[i], cnt[order[i]]);
    printf("\n\nSearching (simulated annealing, %d restarts)...\n", RESTARTS);

    for (r = 0; r < RESTARTS; r++) {
        double best, cur;
        for (i = 0; i < 26; i++) key[order[i]] = FREQ_ORDER[i] - 'A';   /* frequency-rank start */
        for (i = 0; i < r * 2; i++) { int a = rand() % 26, b = rand() % 26, t = key[a]; key[a] = key[b]; key[b] = t; }
        cur = score(key);
        best = cur;
        memcpy(bestkey, key, sizeof key);
        for (it = 0; it < ITERS; it++) {                          /* simulated annealing */
            double T = 25.0 * (1.0 - (double)it / ITERS) + 0.05, s;
            int a = rand() % 26, b = rand() % 26, t;
            if (a == b) continue;
            t = key[a]; key[a] = key[b]; key[b] = t;
            s = score(key);
            if (s > cur || exp((s - cur) / T) > (double)rand() / RAND_MAX) {
                cur = s;
                if (cur > best) { best = cur; memcpy(bestkey, key, sizeof key); }
            } else { t = key[a]; key[a] = key[b]; key[b] = t; }
        }
        memcpy(key, bestkey, sizeof key);
        add_result(key, best);
    }
    qsort(res, nres, sizeof(Res), cmp);

    printf("\nTop %d possible plaintexts (most likely first):\n", top);
    for (r = 0; r < top && r < nres; r++) {
        int shown = 0;
        printf("\n%d) log-likelihood %.1f\n   key (cipher A..Z -> plain): ", r + 1, res[r].score);
        for (i = 0; i < 26; i++) putchar('a' + res[r].key[i]);
        printf("\n   plaintext: ");
        for (i = 0; i < N && shown < 160; i++, shown++) putchar('a' + res[r].key[C[i]]);
        printf("%s\n", N > 160 ? "..." : "");
    }
    return 0;
}
