#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <memory.h>
#include <stdio.h>
#include <malloc.h>
#include <crtdbg.h>

#define NO_SIGNATURES 3
#define FILENAME_MAX_LEN 32
#define RSA_PEM_SIZE 887

int main()
{
	AES_KEY aes_key;
	unsigned char key[] = { 0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12 };
	
	unsigned char** rsa_priv_keys = (unsigned char**)malloc(sizeof(unsigned char*) * NO_SIGNATURES);

	FILE* f = NULL;
	char fileName[FILENAME_MAX_LEN];
	char fileNameRightRSA[FILENAME_MAX_LEN];
	AES_set_decrypt_key(key, 128, &aes_key);

	for (unsigned char i = 0; i < NO_SIGNATURES; i++)
	{
		sprintf(fileName, "privateKey_%hhu.enc", i + 1);
		f = fopen(fileName, "rb");
		fseek(f, 0, SEEK_END);
		size_t lenKey = ftell(f);
		fseek(f, 0, SEEK_SET);
		rsa_priv_keys[i] = (unsigned char*)malloc(lenKey);
		fread(rsa_priv_keys[i], lenKey, 1, f);
		fclose(f);
		unsigned char* decrypted = (unsigned char*)malloc(lenKey);
		for (size_t j = 0; j < lenKey; j += AES_BLOCK_SIZE)
		{
			AES_ecb_encrypt(rsa_priv_keys[i] + j, decrypted + j, &aes_key, AES_DECRYPT);
		}
		sprintf(fileName, "privateKey_%hhu.pem", i + 1);
		f = fopen(fileName, "wb");
		fwrite(decrypted, RSA_PEM_SIZE, 1, f);
		fclose(f);
		free(decrypted);


		FILE* f = fopen("in.txt", "r");
		fseek(f, 0, SEEK_END);
		size_t msgLen = ftell(f);
		fseek(f, 0, SEEK_SET);
		unsigned char* buffer = (unsigned char*)malloc(msgLen);
		fread(buffer, msgLen, 1, f);
		fclose(f);

		unsigned char computed_SHA[SHA256_DIGEST_LENGTH];

		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, buffer, msgLen);
		SHA256_Final(computed_SHA, &ctx);

		free(buffer);
		RSA* rsa;
		f = fopen(fileName, "r");
		rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
		fclose(f);

		unsigned int sig_len = RSA_size(rsa);

		unsigned char* signature = (unsigned char*)malloc(sig_len);

		RSA_private_encrypt(sizeof(computed_SHA), computed_SHA, signature, rsa, RSA_PKCS1_PADDING);


		sprintf(fileName, "esign_%hhu.sig", i+1);
		f = fopen(fileName, "wb");
		fwrite(signature, sig_len, 1, f);
		fclose(f);

		f = fopen("eSign.sig", "rb");
		fseek(f, 0, SEEK_END);
		size_t sign_length = ftell(f);
		fseek(f, 0, SEEK_SET);
		unsigned char* valid_signature = (unsigned char*)malloc(sign_length);
		fread(valid_signature, sign_length, 1, f);
		fclose(f);

		memcmp(signature, valid_signature, sign_length) ? printf("\nKey %hhu is not genuine.", i + 1) : printf("\nKey %hhu is genuine.", i+1);

		free(valid_signature);
		free(signature);
		RSA_free(rsa);
	}

	for (unsigned char i = 0; i < NO_SIGNATURES; i++)
	{
		free(rsa_priv_keys[i]);
	}
	free(rsa_priv_keys);

	_CrtDumpMemoryLeaks();

	return 0;
}