# RSA-Cyptography
This is a a cryptography project created using C programming for UCSC's CSE13s.  The encryption and decryption process used the RSA algorithm. (No students from the CSE 13S class should view this repo as it has been added to the list of repo to be MOSS. I've warned you.) 

## Building

Build the program with:

```
* make all

Builds keygen encrypt decrypt
```

```
* make keygen

Builds keygen
```
```
* make decrypt

Builds decrypt
```
```
* make encrypt 

Builds encrypt
```
```
* make clean

to remove files
```
```
* make format

to format file using clang-format
```

## Running

Run the program with:

```
* $./keygen [-hv] [-b bits] -n pbfile -d pvfile

Running -h will print out program usage and help.

Running -v will display the verbose program output.

Running -n and -d will specify a file to take and print out the the key to. If not specify, it will be printed out to the default file or rsa.pub and rsa.priv.

Running -b will change the minimum bits needed for public key n. Where the default n is 256. 

Running -i will change the Miller-Rabin iterations for testing primes. 

Running -s will change the seed for generating the randstate. 

```
```
* $./encrypt [-hv] [-i infile] [-o outfile] -n pubkey

Running -h will print out program usage and help.

Running -v will display the verbose program output. 

Running -i and -o will specify a file to take and print out to. If not specify, it will be printed out
```
```
* $./decrypt [-hv] [-i infile] [-o outfile] -n privkey

Running -h will print out program usage and help.

Running -v will display the verbose program output.

Running -i and -o will specify a file to take and print out to. If not specify, it will be printed out from the terminal.
```
## File

The file contain:

```
decrypt.c
```

```
encrypt.c
```

```
Makefile
```

```
keygen.c
```

```
numtheory.h
```

```
numtheory.c
```
```
randstate.h
```

```
randstate.c
```

```
rsa.h
```
```
rsa.c
```
