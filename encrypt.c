// This is the encryption file
#include <stdlib.h>
#include <gmp.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>

#include "randstate.h"
#include "numtheory.h"
#include "rsa.h"

#define OPTIONS "hvi:o:n:"

// helper function to print out help command
void print_help() {
    printf("SYNOPSIS\n");
    printf("   Encrypts data using RSA encryption.\n");
    printf("   Encrypted data is decrypted by the decrypt program.\n");
    printf("\n");
    printf("USAGE\n");
    printf("   ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey\n");
    printf("\n");
    printf("OPTIONS\n");
    printf("   -h              Display program help and usage.\n");
    printf("   -v              Display verbose program output.\n");
    printf("   -i infile       Input file of data to encrypt (default: stdin).\n");
    printf("   -o outfile      Output file for encrypted data (default: stdout).\n");
    printf("   -n pbfile       Public key file (default: rsa.pub).\n");
}

// main function
int main(int argc, char **argv) {

    // set up file
    FILE *infile = stdin;
    FILE *outfile = stdout;
    // default file to read public key from
    FILE *pubfile = NULL;

    bool verbose = false;
    bool readpub = true;

    // init mpz_t var
    mpz_t n, e, s, m;
    mpz_inits(n, e, s, m, NULL);

    // user input/help manual
    int opt = 0;
    while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch (opt) {
        case 'h':
            print_help();
            return 0;
            break;
        case 'v': verbose = true; break;
        case 'i': // file to read from (default is stdin)
            infile = fopen(optarg, "r");
            // if there is no file to read (print error and close necessary file)
            if (!infile) {
                fprintf(stderr, "Error: unable to read file.\n");
                fclose(infile);
                if (outfile) {
                    fclose(outfile);
                }
                if (pubfile) {
                    fclose(pubfile);
                }
                mpz_clears(n, e, s, NULL);
                return 0;
            }
            break;
        case 'o': // file to output to (default is stdout)
            outfile = fopen(optarg, "w");
            if (!outfile) {
                fprintf(stderr, "Error: unable to write file.\n");
                fclose(outfile);
                if (infile) {
                    fclose(infile);
                }
                if (pubfile) {
                    fclose(pubfile);
                }
                mpz_clears(n, e, s, NULL);
                return 0;
            }
            break;
        case 'n':
            // if a key file was provided
            readpub = false; // disable the the default key file
            pubfile = fopen(optarg, "r");
            if (!pubfile) {
                fprintf(stderr, "Error: unable to read file.\n");
                fclose(pubfile);
                if (infile) {
                    fclose(infile);
                }
                if (outfile) {
                    fclose(outfile);
                }
                mpz_clears(n, e, s, NULL);
                return 0;
            }
            break;
        default:
            print_help();
            return 0;
            break;
        }
    }

    // if no user input key file was inputted, open default rsa.pub
    if (readpub == true) {
        pubfile = fopen("rsa.pub", "r");
        // if there is no rsa.pub file to read
        if (!pubfile) {
            fprintf(stderr, "rsa.pub: No such file or directory\n");
            if (infile) {
                fclose(infile);
            }
            if (outfile) {
                fclose(outfile);
            }
            mpz_clears(n, e, s, NULL);
            return 0;
        }
    }
    // username var (we need to hard this, since we don't know the size)
    char username[1024];

    // read public key from opened public key file
    rsa_read_pub(n, e, s, username, pubfile);

    // print out info about the numberof bits
    size_t numbits;
    if (verbose == true) {
        gmp_printf("user = %s\n", username);

        numbits = mpz_sizeinbase(s, 2); // we use this to get the bits
        gmp_printf("s (%d bits) = %Zd\n", numbits, s);

        numbits = mpz_sizeinbase(n, 2);
        gmp_printf("n (%d bits) = %Zd\n", numbits, n);

        numbits = mpz_sizeinbase(e, 2);
        gmp_printf("e (%d bits) = %Zd\n", numbits, e);
    }

    // convert the user name into an mpz_t (like keygen)
    mpz_set_str(m, username, 62);

    //verify the rsa signature
    //if invalid, exit program
    if (rsa_verify(m, s, e, n) == false) {
        gmp_printf("invalid singature.\n");
        fclose(infile);
        fclose(outfile);
        fclose(pubfile);
        mpz_clears(n, e, s, NULL);
        return 0;
    }

    //encrypt the file using rsa_encrypt_file()
    rsa_encrypt_file(infile, outfile, n, e);
    fclose(infile);
    fclose(outfile);
    fclose(pubfile);
    mpz_clears(n, e, s, m, NULL);
    return 0;
}
