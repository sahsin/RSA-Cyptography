#include <stdio.h>
#include <gmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#include "randstate.h"
#include "numtheory.h"

// All the function implementation are based on assignment 6 documentation's pseudocode.
// Proper credit for assignment pseudocode belongs to Professor Long and Eugene Chou.
// For is_prime, my code is also based on Eric's section note on 11/10
// Base case consideration for Miller Rabin (is_prime) was based on
// Professor Darrell Long's Github: "Public-key-Crytography-in-Python"
// prime.py where since Miller Rabin start with bound
// of ( 2 - (n - 2)) so it fail number from 0 to 4. As a result, we need to "hardcode"
// these 4 cases to ensure these numbers work properly.

gmp_randstate_t state; // init state here in case

// Your last argument/function should be null terminate
// you end should be cleared
// Compute the greatest commom divisor of a and b and store computed divisor in g
// Jason (tutor) tell me to check the gcd and tell me to create temp variable for a and b
// so it doesn't get overwritten
void gcd(mpz_t d, mpz_t a, mpz_t b) {
    mpz_t t, temp_a, temp_b, amodb;
    mpz_inits(t, temp_a, temp_b, amodb, NULL);

    // set a and b to temp to prevent being overwritten
    mpz_set(temp_b, b);
    mpz_set(temp_a, a);

    while (mpz_cmp_ui(temp_b, 0) != 0) {
        mpz_set(t, temp_b); // temp = b
        mpz_mod(amodb, temp_a, temp_b); // a mod b
        mpz_set(temp_b, amodb); // b = a mob
        mpz_set(temp_a, t); // a = temp
    }
    mpz_set(d, temp_a); // return a
    mpz_clears(t, temp_a, temp_b, amodb, NULL);
}

void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {

    // init all the variable
    mpz_t r, rsub, t, tsub, q, temp_r, temp_t;
    mpz_inits(r, rsub, t, tsub, q, temp_r, temp_t,
        NULL); // you can inits all at once

    // assigning to var
    mpz_set(r, n); // r = n
    mpz_set(rsub, a); // r' = a
    mpz_set_ui(t, 0); // t = 0
    mpz_set_ui(tsub, 1); // t' = 1

    // while loop

    while (mpz_cmp_ui(rsub, 0) != 0) {

        // this is r and r'
        mpz_fdiv_q(q, r, rsub); // q = (r/r')

        // perform swapping (for r and r')

        mpz_set(temp_r, r); // store r in temp var
        mpz_set(r, rsub); // r <- r'
        mpz_mul(rsub, q, rsub); // r' <- q*r'
        mpz_sub(rsub, temp_r, rsub); // r' <- (r - q*r')

        // perform swapping (for t and t')

        mpz_set(temp_t, t); // store t in temp var
        mpz_set(t, tsub); // t <- t'
        mpz_mul(tsub, q, tsub); // t' <- q*t'
        mpz_sub(tsub, temp_t, tsub); // t' <- (t - q*t')
    }

    if (mpz_cmp_ui(r, 1) > 0) { // if r > 1
        mpz_set_ui(i, 0); // set i to 0
        mpz_clears(r, rsub, t, tsub, q, temp_r, temp_t, NULL);
        return;
    }
    if (mpz_cmp_ui(t, 0) < 0) {
        mpz_add(t, t, n); // tadd = t + n
    }
    mpz_set(i, t); // set to outfile

    mpz_clears(r, rsub, t, tsub, q, temp_r, temp_t,
        NULL); // free memory to prevent leak
}

// modular expo
void pow_mod(mpz_t out, mpz_t base, mpz_t exponent, mpz_t modulus) {
    mpz_t p;
    mpz_t v;
    mpz_t d; // exponent temp

    // allocate memory
    mpz_init(p);
    mpz_init(v);
    mpz_init(d);

    // assign variable
    mpz_set(d, exponent); // temp d = exponent
    mpz_set_ui(v, 1);
    mpz_set(p, base);
    while (mpz_cmp_ui(d, 0) > 0) {
        if (mpz_odd_p(d)) { // if d is odd
            mpz_mul(v, v, p); // (v * p)
            mpz_mod(v, v, modulus); // v = v mod n
        }
        //(p * p)
        mpz_mul(p, p, p);
        //set p = p mod n
        mpz_mod(p, p, modulus);
        // d = (d/2) (floor div)
        mpz_fdiv_q_ui(d, d, 2);
    }

    // set output to v
    mpz_set(out, v);
    // free the memory
    mpz_clear(p);
    mpz_clear(v);
    mpz_clear(d);
}

// Based partially on Eric's (tutor) psedudocode example from section note.
// Miles (tutor) told us to use temp variable to prevent things like power mod from getting overwritten.
bool is_prime(mpz_t n, uint64_t iters) {
    mpz_t r, a, nminuso, y, j, bound, two; // for r and s value in miller rabin
    mpz_inits(r, a, nminuso, y, j, bound, two, NULL); // init

    mp_bitcnt_t s = 0; // init s for power 2 ^ s

    // check base case from 0 to 4

    // Based on Professor Long's example
    // If n is 0, 1, and 4 (which is not a prime)
    if ((mpz_cmp_ui(n, 2) < 0) || (mpz_cmp_ui(n, 4) == 0)) {
        mpz_clears(r, a, nminuso, y, j, bound, two, NULL);
        return false;
    }
    // if n is a 3 (which is a prime)
    if (mpz_cmp_ui(n, 4) < 0) {
        mpz_clears(r, a, nminuso, y, j, bound, two, NULL);
        return true;
    }

    mpz_set_ui(two, 2); // two = 2
    mpz_sub_ui(nminuso, n, 1); // n - 1
    mpz_sub_ui(bound, n, 3); // n - 3 bound

    while (mpz_even_p(r)) { // while r is not odd
        mpz_tdiv_q_2exp(r, nminuso, s); // r = (n-1)/2*s (since it requires a bit, s is set as bit)
        mpz_fdiv_q_ui(r, r, 2); // r = r/2
        s += 1; // s = s + 1
    }

    mp_bitcnt_t sminus = s - 1; // s - 1 for the comparison

    // for i to k
    for (uint64_t i = 1; i < iters; i += 1) {
        // choose random a st (2, n - 2)
        mpz_urandomm(a, state, bound); // (2, n - 2)
        mpz_add_ui(a, a, 2); // (2, n -1)

        // y = power_mod(a,r,n)
        pow_mod(y, a, r, n);

        //if y is not 1
        if ((mpz_cmp_ui(y, 1) != 0) && (mpz_cmp(y, nminuso) != 0)) { // y != 1 and y != n -1
            mpz_set_ui(j, 1); // j = 1

            while ((mpz_cmp_ui(j, sminus) <= 0) && (mpz_cmp(y, nminuso) != 0)) {
                pow_mod(y, y, two, n); // y = power mod (y,2,n)
                if (mpz_cmp_ui(y, 1) == 0) { // if y == 1
                    mpz_clears(r, a, nminuso, y, j, bound, two, NULL); // prevent memory leak
                    return false;
                }
                mpz_add_ui(j, j, 1); // j = j + 1
            }
            if (mpz_cmp(y, nminuso) != 0) { // if y != n - 1
                mpz_clears(r, a, nminuso, y, j, bound, two, NULL); // clear to prevent seg fault
                return false;
            }
        }
    }
    mpz_clears(r, a, nminuso, y, j, bound, two, NULL); // clear to prevent seg fault
    return true;
}

// Based on Eric's pseudocode from (11/10/2021)
void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    do {
        mpz_urandomb(p, state, bits);
    } while (!is_prime(p, iters));
}
