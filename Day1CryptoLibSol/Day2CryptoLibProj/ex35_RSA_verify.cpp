#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/applink.c>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>

int main()
{
	RSA* rsa_public;

	// usually the message digest SHA1 is re-computed against the restored message at the destination point 
	unsigned char recomputed_SHA1[] = { 0x2b, 0xa2, 0x7c, 0xe4, 0xaf, 0xd6, 0xcb, 0x94, 0xa2, 0xcd, 0xc0, 0xda, 0x23, 0x72, 0x97, 0x75, 0xbf, 0x5c, 0x2f, 0xd8 };

	FILE* fpublic = fopen("RSAPublicKey.pem", "r");
	rsa_public = PEM_read_RSAPublicKey(fpublic, NULL, NULL, NULL);

	int rsa_size = RSA_size(rsa_public);

	unsigned char message_digest_sha1[SHA_DIGEST_LENGTH];

	FILE* fsign = fopen("signature.sig", "rb");
	fseek(fsign, 0, SEEK_END);
	size_t sign_length = ftell(fsign);
	fseek(fsign, 0, SEEK_SET);
	unsigned char* signature = (unsigned char*)malloc(sign_length);
	fread(signature, sign_length, 1, fsign);


	RSA_public_decrypt(sign_length, signature, message_digest_sha1, rsa_public, RSA_PKCS1_PADDING);

	memcmp(recomputed_SHA1, message_digest_sha1, sizeof(recomputed_SHA1)) ? printf("\nSign is not genuine.") : printf("\nSign is genuine.");

	RSA_free(rsa_public);
	fclose(fpublic);
	fclose(fsign);
	free(signature);

	return 0;
}