#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

int main()
{
	EC_KEY* eck = NULL;

	unsigned char SHA1[] = {
		0xff, 0xa4, 0xff, 0xff, 0x77,
		0xff, 0xab, 0xff, 0xff, 0xff,
		0x04, 0xff, 0xff, 0xff, 0x1c,
		0xc5, 0xff, 0xa9, 0xff, 0xff
	};

	unsigned int signLen = 0;
	unsigned char* signature = (unsigned char*)malloc(80);

	eck = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // initialize EC_KEY with NIST P256R1 curve params
	EC_KEY_generate_key(eck); // generate a NIST P256R1 key pair


	ECDSA_sign(0, SHA1, sizeof(SHA1), signature, &signLen, eck); // ECDSA signature generated into signature buffer; for the same EC private key, each ECDSA signature will be different for the next calls to ECDSA_sign

	FILE* sigFile = fopen("signature.sig", "wb");
	fwrite(signature, 1, signLen, sigFile);

	EC_KEY_free(eck);
	return 0;
}