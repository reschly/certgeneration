/*
 * makersacert.c
 *
 *  Created on: Mar 16, 2013
 *      Author: reschly
 */


#include "certgeneration.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <stdio.h>


void makersacert(int days, char* commonname, int bits)
{
	RSA *key;
	EVP_PKEY *pkey;
	X509 *x;
	FILE *out;

	key = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, key);

	x = makeselfcert(pkey, days, commonname, EVP_sha256());

	out = fopen("rsa_cert.pem", "w");
	if (out == NULL)
		exit(-1);
	PEM_write_X509(out, x);
	fclose(out);
	out = fopen("rsa_cert_key.pem", "w");
	if (out == NULL)
		exit(-1);
	PEM_write_RSAPrivateKey(out, key, NULL, NULL, 0, NULL, NULL);
	fclose(out);
}

void usage(char* arg0)
{
	printf("Usage: %s size commonname\n", arg0);
	printf("\tsize: modulus size, in bits\n");
	printf("\tcommonname: common name for certificate, either a hostname or email\n\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	int bits;

	if (argc < 3)
		usage(argv[0]);
	bits = atoi(argv[1]);

	if (bits < 17) // must be bigger than RSA_F4...
		usage(argv[0]);

	makersacert(365*3, argv[2], bits);

	return 0;
}
