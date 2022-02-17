// Keygen implementation here

#include <stdio.h>
#include <gmp.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <sys/stat.h>

#include "randstate.h"
#include "numtheory.h"
#include "rsa.h"

#define OPTIONS "hvb:i:n:d:s:"

gmp_randstate_t state;

void print_help() {
    printf("SYNOPSIS\n");
    printf("   Generates an RSA public/private key pair.\n");
    printf("\n");
    printf("USAGE\n");
    printf("   ./keygen [-hv] [-b bits] -n pbfile -d pvfile\n");
    printf("\n");
    printf("OPTIONS\n");
    printf("   -h              Display program help and usage.\n");
    printf("   -v              Display verbose program output.\n");
    printf("   -b bits         Minimum bits needed for public key n (default: 256).\n");
    printf("   -i confidence   Miller-Rabin iterations for testing primes (default: 50).\n");
    printf("   -n pbfile       Public key file (default: rsa.pub).\n");
    printf("   -d pvfile       Private key file (default: rsa.priv).\n");
    printf("   -s seed         Random seed for testing.\n");
}

int main(int argc, char **argv) {

    // set default path to rsa.pub and rsa.priv
    // credit to Eugene for showing us this trick to specify the path for rsa.pub and rsa.priv
    // in section (11/16)
    char *pubpath = "rsa.pub";
    char *privpath = "rsa.priv";

    FILE *pubfile = NULL;
    FILE *prifile = NULL;
    bool verbose = false;

    uint64_t MRiters = 50; // default Miller Rabin iterations
    uint64_t seed = time(NULL);
    uint64_t bits = 256; // default bits

    // mpz_t variable init and set up
    mpz_t p, q, n, e, d, m, s;
    mpz_inits(p, q, n, e, d, m, s, NULL);

    // username var
    char *username[sizeof(getenv("USER"))];

    // user input/help manual
    int opt = 0;
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'h':
            print_help();
            return 0;
            break;
            // verbose printing
        case 'v': verbose = true; break;
        case 'b':
            bits = atoi(optarg);
            break; // min is 256
            // MR iterations for testing primes
        case 'i': MRiters = atoi(optarg); break;
        case 'n': pubpath = optarg; break; // to specifies the public key file
        case 'd': privpath = optarg; break; // for private key file
        case 's': // soecifies a random seed
            seed = atoi(optarg);
            break;
        default:
            print_help();
            return 0;
            break;
        }
    }

    pubfile = fopen(pubpath, "w");
    if (!pubfile) {
        fprintf(stderr, "Error: unable to write into file.\n");
        fclose(pubfile);
        fclose(prifile);
        mpz_clears(p, q, n, e, d, m, s, NULL);
        return 0;
    }

    prifile = fopen(privpath, "w");
    if (!prifile) {
        fprintf(stderr, "Error: unable to write into file.\n");
        fclose(pubfile);
        fclose(prifile);
        mpz_clears(p, q, n, e, d, m, s, NULL);
        return 0;
    }

    // set file permission
    int number = fileno(prifile);
    fchmod(number, 0600);

    // init random seed using set seed
    randstate_init(seed);

    // make public key (p, q is prime num) n is product of pq
    // and e is the public exponent
    rsa_make_pub(p, q, n, e, bits, MRiters);

    // make private key
    rsa_make_priv(d, e, p, q);

    // get current user's name as a string
    *username = getenv("USER");

    // convert username into an mpz_t m
    mpz_set_str(m, *username, 62);

    // compute singature of username using rsa_sign
    rsa_sign(s, m, d, n); // s is signature

    // write the public and private key into file
    rsa_write_pub(n, e, s, *username, pubfile);
    rsa_write_priv(n, d, prifile);

    // print all the number
    size_t numbits;
    if (verbose == true) {
        gmp_printf("user = %s\n", *username);

        numbits = mpz_sizeinbase(s, 2); // we use this to get the bits
        gmp_printf("s (%d bits) = %Zd\n", numbits, s);

        numbits = mpz_sizeinbase(p, 2);
        gmp_printf("p (%d bits) = %Zd\n", numbits, p);

        numbits = mpz_sizeinbase(q, 2);
        gmp_printf("q (%d bits) = %Zd\n", numbits, q);

        numbits = mpz_sizeinbase(n, 2);
        gmp_printf("n (%d bits) = %Zd\n", numbits, n);

        numbits = mpz_sizeinbase(e, 2);
        gmp_printf("e (%d bits) = %Zd\n", numbits, e);

        numbits = mpz_sizeinbase(d, 2);
        gmp_printf("d (%d bits) = %Zd\n", numbits, d);
    }

    // free all the memory
    mpz_clears(p, q, n, e, d, m, s, NULL);
    randstate_clear();
    fclose(pubfile);
    fclose(prifile);
    return 0;
}
