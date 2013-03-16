/*
 * makeeccert.c
 *
 *  Created on: Mar 15, 2013
 *      Author: reschly
 */


#include "certgeneration.h"
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#include <stdio.h>


void makeeccert384(int days, char* commonname)
{
	EC_KEY *key;
	EVP_PKEY *pkey;
	X509 *x;
	FILE *out;

	key = EC_KEY_new_by_curve_name(NID_secp384r1);
	EC_KEY_generate_key(key);
	EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_EC_KEY(pkey, key);

	x = makeselfcert(pkey, days, commonname, EVP_sha384());

	out = fopen("ec384_cert.pem", "w");
	if (out == NULL)
		exit(-1);
	PEM_write_X509(out, x);
	fclose(out);
	out = fopen("ec384_cert_key.pem", "w");
	if (out == NULL)
		exit(-1);
	PEM_write_ECPrivateKey(out, key, NULL, NULL, 0, NULL, NULL);
	fclose(out);
}


void makeeccert256(int days, char* commonname)
{
	EC_KEY *key;
	EVP_PKEY *pkey;
	X509 *x;
	FILE *out;

	key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	EC_KEY_generate_key(key);
	EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_EC_KEY(pkey, key);

	x = makeselfcert(pkey, days, commonname, EVP_sha256());

	out = fopen("ec256_cert.pem", "w");
	if (out == NULL)
		exit(-1);
	PEM_write_X509(out, x);
	fclose(out);
	out = fopen("ec256_cert_key.pem", "w");
	if (out == NULL)
		exit(-1);
	PEM_write_ECPrivateKey(out, key, NULL, NULL, 0, NULL, NULL);
	fclose(out);

}

void usage(char* arg0)
{
	printf("Usage: %s size commonname\n", arg0);
	printf("\tsize: 256 or 384, for P-256 or P-384\n");
	printf("\tcommonname: common name for certificate, either a hostname or email\n\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	int curve;

	if (argc < 3)
		usage(argv[0]);
	curve = atoi(argv[1]);

	if (curve == 256)
		makeeccert256(365*3, argv[2]);
	else if (curve == 384)
		makeeccert384(365*3, argv[2]);
	else
		usage(argv[0]);

	return 0;
}
