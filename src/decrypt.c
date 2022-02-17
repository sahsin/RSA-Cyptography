// This is the decryption file

#include <stdlib.h>
#include <gmp.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include "randstate.h"
#include "numtheory.h"
#include "rsa.h"

#define OPTIONS "hvi:o:n:"

// helper function to print out help command when -h is enabled
void print_help() {
    printf("SYNOPSIS\n");
    printf("   Decrypts data using RSA decryption.\n");
    printf("   Encrypted data is encrypted by the encrypt program.\n");
    printf("\n");
    printf("USAGE\n");
    printf("   ./decrypt [-hv] [-i infile] [-o outfile] -n privkey\n");
    printf("\n");
    printf("OPTIONS\n");
    printf("   -h              Display program help and usage.\n");
    printf("   -v              Display verbose program output.\n");
    printf("   -i infile       Input file of data to decrypt (default: stdin).\n");
    printf("   -o outfile      Output file for decrypted data (default: stdout).\n");
    printf("   -n pvfile       Private key file (default: rsa.priv).\n");
}

int main(int argc, char **argv) {

    // setting up file
    FILE *infile = stdin;
    FILE *outfile = stdout;
    FILE *privfile = NULL;
    bool verbose = false;
    bool readpriv = true;

    mpz_t n, d;
    mpz_inits(n, d, NULL);

    // user input/help manual
    int opt = 0;
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'h': // help manual
            print_help();
            return 0;
            break;
        case 'v': // enable verbose
            verbose = true;
            break;
        case 'i': //infile

            infile = fopen(optarg, "r");
            if (!infile) {
                fprintf(stderr, "Error: unable to read file.\n");
                // check if other file are there yet
                if (outfile) {
                    fclose(outfile);
                }
                if (privfile) {
                    fclose(privfile);
                }
                mpz_clears(n, d, NULL);
                return 0;
            }
            break;
        case 'o': // outfile
            outfile = fopen(optarg, "w");
            if (!outfile) {
                fprintf(stderr, "Error: unable to write file.\n");
                if (infile) {
                    fclose(infile);
                }
                if (privfile) {
                    fclose(privfile);
                }
                mpz_clears(n, d, NULL);
                return 0;
            }
            break;
        case 'n': // this is the private key file
            readpriv = false; // disable the default private key file
            privfile = fopen(optarg, "r");
            if (!privfile) {
                fprintf(stderr, "Error: unable to read file.\n");
                if (infile) {
                    fclose(infile);
                }
                if (outfile) {
                    fclose(outfile);
                }
                mpz_clears(n, d, NULL);
                return 0;
            }
            break;
        default:
            print_help();
            return 0;
            break;
        }
    }
    // if no private key was specify
    // open default private key file
    if (readpriv) {
        privfile = fopen("rsa.priv", "r");
        if (!privfile) {
            fprintf(stderr, "Error: unable to read file.\n");
            if (infile) {
                fclose(infile);
            }
            if (outfile) {
                fclose(outfile);
            }
            mpz_clears(n, d, NULL);
            return 0;
        }
    }

    // read the private key from the opened private key file
    rsa_read_priv(n, d, privfile);

    //if verbose is true
    size_t numbits;
    if (verbose == true) {

        numbits = mpz_sizeinbase(n, 2); // we use this to get the bits
        gmp_printf("n (%d bits) = %Zd\n", numbits, n); // public modulus

        numbits = mpz_sizeinbase(d, 2);
        gmp_printf("d (%d bits) = %Zd\n", numbits, d); // private key
    }

    //decrypt file using rsa_decrypt_file()
    rsa_decrypt_file(infile, outfile, n, d);

    // free memory
    mpz_clears(n, d, NULL);
    fclose(infile);
    fclose(outfile);
    fclose(privfile);
    return 0;
}
