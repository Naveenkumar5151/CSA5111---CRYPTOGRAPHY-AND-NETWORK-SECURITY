/*
 * Program 11 : How many keys does the Playfair cipher have?
 *
 * A key is an arrangement of the 25 letters in the 5x5 matrix:  25! keys
 *     25! = 15511210043330985984000000  ~  2^84  (about 2^83.7)
 *
 * Effectively unique keys: two matrices give identical encryption when one is
 * obtained from the other by cyclically shifting the rows and/or the columns
 * (the "next letter" rules wrap around, so the matrix is really a torus).
 * There are 5 row shifts x 5 column shifts = 25 equivalent matrices per key:
 *     25!/25 = 24!  = 620448401733239439360000  ~  2^79
 * (This is the standard textbook answer; reflections/transposes change the
 *  direction of the rules so they are NOT equivalent.)
 *
 * Compile : gcc 11_playfair_key_count.c -o pfkeys -lm
 */
#include <stdio.h>
#include <math.h>

int main(void) {
    double f = 1.0;
    int i;
    for (i = 2; i <= 25; i++) {
        f *= i;
        if (i == 24) printf("24! = %.6e   log2(24!) = %.2f\n", f, log2(f));
    }
    printf("25! = %.6e   log2(25!) = %.2f\n\n", f, log2(f));
    printf("Total Playfair keys                      : 25!      ~ 2^%.1f  (approx. 2^84)\n", log2(f));
    printf("Equivalent matrices per key (5 x 5 shifts): 25\n");
    printf("Effectively unique keys                  : 25!/25 = 24! ~ 2^%.1f  (approx. 2^79)\n", log2(f / 25.0));
    return 0;
}
