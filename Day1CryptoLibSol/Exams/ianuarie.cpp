#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>

void printArray(unsigned const char* const arr, unsigned const len, const char* const name)
{
	printf("\nThe content of the %s array is (hex): ", name);
	for (unsigned char i = 0; i < len; i++)
	{
		printf("%02x", arr[i]);
	}
}

int main()
{
	//1st req
	SHA256_CTX ctx;
	FILE* f = fopen("name.txt", "r");
	fseek(f, 0, SEEK_END);
	size_t len = ftell(f);
	fseek(f, 0, SEEK_SET);

	unsigned char* name = (unsigned char*)malloc(len);
	fread(name, len, 1, f);
	fclose(f);

	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_Init(&ctx);

	SHA256_Update(&ctx, name, len);

	SHA256_Final(digest, &ctx);

	printArray(digest, sizeof(digest), "sha256_of_my_name");

	//2nd req
	f = fopen("iv.txt", "r");
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char i = 0;
	unsigned int value;

	while (fscanf(f, " 0x%x,", &value) == 1 && i < AES_BLOCK_SIZE)
	{
		iv[i++] = (unsigned char)value;
	}

	fclose(f);

	f = fopen("aes.key", "rb");
	fseek(f, 0, SEEK_END);
	size_t key_len = ftell(f);
	fseek(f, 0, SEEK_SET);

	unsigned char* key = (unsigned char*)malloc(key_len);
	fread(key, key_len, 1, f);
	fclose(f);

	AES_KEY aes_key;

	AES_set_encrypt_key(key, key_len * 8, &aes_key);

	size_t partial_block = len % AES_BLOCK_SIZE ? 1 : 0;
	size_t ciphertext_blocks = len / AES_BLOCK_SIZE + partial_block;

	size_t padded_length = ciphertext_blocks * AES_BLOCK_SIZE;

	unsigned char* ciphertext = (unsigned char*)malloc(padded_length);

	printArray(iv, AES_BLOCK_SIZE, "iv");

	AES_cbc_encrypt(name, ciphertext, len, &aes_key, iv, AES_ENCRYPT);

	printArray(ciphertext, padded_length, "aes-256-cbc");

	f = fopen("enc_name.aes", "wb");
	fwrite(ciphertext, padded_length, 1, f);
	fclose(f);

	//3rd req
	RSA* rsa = NULL;
	rsa = RSA_generate_key(1024, USHRT_MAX, NULL, NULL);

	f = fopen("pub1.pem", "wb");
	PEM_write_RSAPublicKey(f, rsa);
	fclose(f);

	unsigned char computed_SHA[SHA256_DIGEST_LENGTH];

	SHA256_Init(&ctx);

	SHA256_Update(&ctx, ciphertext, padded_length);

	SHA256_Final(computed_SHA, &ctx);

	unsigned char* signature = (unsigned char*)malloc(RSA_size(rsa));
	size_t sig_size = 0;

	RSA_sign(NID_sha256, computed_SHA, SHA256_DIGEST_LENGTH, signature, &sig_size, rsa);

	f = fopen("digital.sign", "wb");
	fwrite(signature, sig_size, 1, f);
	fclose(f);

	RSA_verify(NID_sha256, computed_SHA, SHA256_DIGEST_LENGTH, signature, sig_size, rsa) ? printf("\nVerification of the signature succeeded.") : printf("\nVerification of the signature failed.");

	RSA_free(rsa);
	free(ciphertext);
	free(key);
	free(name);

	return 0;
}