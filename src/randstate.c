// random state interface for RSA library and number theory function

#include <stdio.h>
#include <gmp.h>
#include <stdint.h>

#include "randstate.h"

// specification regarding how to implement the randstate was based on
// assignment 6's document.

gmp_randstate_t state; // init state

void randstate_init(uint64_t seed) {
    gmp_randinit_mt(state); // init state with default algorithm
    gmp_randseed_ui(state, seed); // seeding it
}

void randstate_clear(void) {
    gmp_randclear(state); // clear the init global state
}
