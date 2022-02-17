// Implementation of the RSA library

#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <gmp.h>

#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"

// Make public key
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {
    // create and init variables
    mpz_t p_minus, q_minus, gcd_e, temp_n;
    mpz_inits(p_minus, q_minus, gcd_e, temp_n, NULL);
    
    do {

        // Set up num for upper and lower bound
        uint64_t lower = (nbits / 4);
        uint64_t upper = ((3 * nbits) / 4);

        // set up bits bound 
        uint64_t pbits = lower + (random() % (upper - lower + 1)); // nbits/4,(3 * nbits)/4)
        uint64_t qbits = nbits - pbits; // the rest into q bits

        // make the prime number
        make_prime(p, pbits, iters);
        make_prime(q, qbits, iters);
        mpz_mul(n, p, q); // n = p * q

    } while (!(mpz_sizeinbase(n, 2) == nbits));

    // compute Euler totient function
    // toitent(n) = (p-1)(q-1)
    mpz_sub_ui(p_minus, p, 1); // p - 1
    mpz_sub_ui(q_minus, q, 1); // q - 1
    mpz_mul(temp_n, p_minus, q_minus); // totient

    do {
        mpz_urandomb(e, state, nbits); // generate random num in e
        gcd(gcd_e, e, temp_n); // store into gcd_e
    } while (mpz_cmp_ui(gcd_e, 1) != 0); // while the gcd_e is not the greatest common divisor

    mpz_clears(p_minus, q_minus, gcd_e, temp_n, NULL);
    return;
}

// write a public RSA key to pbfile
void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {

    // n, e, s, then user name. With each with a trailing newline

    gmp_fprintf(pbfile,
        "%Zx\n"
        "%Zx\n"
        "%Zx\n"
        "%s\n",
        n, e, s, username);

    return;
}

// Read public key 
void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {

    // read in n, e, s and user

    gmp_fscanf(pbfile,
        "%Zx\n"
        "%Zx\n"
        "%Zx\n"
        "%s\n",
        n, e, s, username);

    return;
}

// make the private key
void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
    mpz_t p_temp, q_temp, totient_n;
    mpz_inits(p_temp, q_temp, totient_n, NULL);

    mpz_sub_ui(p_temp, p, 1); // p - 1
    mpz_sub_ui(q_temp, q, 1); // q - 1
    mpz_mul(totient_n, p_temp, q_temp); // phi(n) = (p-1)(q-1)

    // compute d using inverse of e mod phi(n)
    mod_inverse(d, e, totient_n);

    mpz_clears(p_temp, q_temp, totient_n, NULL);
    return;
}

// Write private RSA key to pvfile
void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {

    // n, d, with trailing newline and in hexstring
    gmp_fprintf(pvfile,
        "%Zx\n"
        "%Zx\n",
        n, d);
    return;
}

void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fscanf(pvfile,
        "%Zx\n"
        "%Zx\n",
        n, d);
    return;
}

void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    // c = m^e (mod n)
    pow_mod(c, m, e, n);
    return;
}

// encrypt the file
void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
    mpz_t m, c; // for encrypt
    mpz_inits(c, m, NULL);

    // calculate block size k
    // k = log2(n) - 1 /8
    size_t k = ((mpz_sizeinbase(n, 2) - 1) / 8);

    // allocate memory for block
    uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t));

    // zero out the zero block with 0xFF
    block[0] = 0xFF;

    size_t j = 1;

    while (j > 0) {
        // use fread (read in a block of file)
        j = fread(block + 1, sizeof(uint8_t), k - 1, infile);

        // using mpz_import(output, number of element, order = 1, size (uint8_t), endian = 1, nails = 0, block)
        mpz_import(m, j + 1, 1, sizeof(uint8_t), 1, 0, block);

        // encrypt m
        rsa_encrypt(c, m, e, n);

        // write to file
        gmp_fprintf(outfile, "%Zx\n", c);
    }

    // free memory
    mpz_clears(c, m, NULL);
    free(block);
    return;
}

// decrypt it using power mod
void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    // m = c^d (mod n)
    // pow mod (output, base, exponent, modulus)
    pow_mod(m, c, d, n);
    return;
}

// decrypt the file
void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
    // for storing scanned in file
    mpz_t c, m;
    mpz_inits(c, m, NULL);

    // use mpz_sizebase(n, 2) credit to Eugene for telling us this
    // k = log2(n) - 1 /8
    size_t k = (mpz_sizeinbase(n, 2) - 1) / 8;

    size_t j = 1;

    // allocate memory for block
    uint8_t *block = (uint8_t *) calloc(k, sizeof(uint8_t));

    // while there are unprocessed bytes in infile (using while loop)
    // I was originally using a do while, but it was printing an extra loop
    while (!feof(infile)) {

        // moved here due to scan-build having error
        j = gmp_fscanf(infile, "%Zx\n", c);

        // call rsa_decrypt to decrypt
        rsa_decrypt(m, c, d, n);

        // mpz_export(*output, size, order = 1, size, endian = 1, nail = 0, const)
        mpz_export(block, &j, 1, sizeof(uint8_t), 1, 0, m);

        // write to file
        fwrite((block + 1), sizeof(uint8_t), j - 1, outfile);
    }

    // free memory
    mpz_clears(c, m, NULL);
    free(block);

    return;
}

// sign the singature
void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    // s = m^d (mod n)
    pow_mod(s, m, d, n);
    return;
}

// verify if the signature is valid or not
bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t verifying;
    mpz_init(verifying);

    // Verified = s^e (mod n)
    pow_mod(verifying, s, e, n);

    // if V(s) == m return true
    if (mpz_cmp(verifying, m) == 0) {
        mpz_clear(verifying);
        return true;
    } else { // else false
        mpz_clear(verifying);
        return false;
    }
}
