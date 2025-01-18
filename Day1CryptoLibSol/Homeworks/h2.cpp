#include <openssl/aes.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <crtdbg.h>
#include <malloc.h>
#define MAX_BUFF 256
int main()
{
	const char* accFileName = "Accounts.txt";
	const char* keyFileName = "pass.key";
	const char* outFile = "SHA256_Enc.txt";
	char* buff = (char*)malloc(MAX_BUFF);
	FILE* f = fopen(keyFileName, "rb");
	fseek(f, 0, SEEK_END);
	size_t len = ftell(f);
	unsigned char* key = (unsigned char*)malloc(len);
	fseek(f, 0, SEEK_SET);
	fread(key, 1, len, f);
	fclose(f);
	char* charSHA256;
	unsigned char sha256[SHA256_DIGEST_LENGTH];
	f = fopen(accFileName, "r");
	FILE* g = fopen(outFile, "w");
	while (fgets(buff, MAX_BUFF, f))
	{
		strtok(buff, " ");
		strtok(NULL, " ");
		strtok(NULL, " ");
		charSHA256 = strtok(NULL, " ");
		size_t i = 0;
		while (sscanf(charSHA256+2*i, "%02x", &sha256[i]))
		{
			i++;
		}
		AES_KEY aes;
		AES_set_encrypt_key(key, len * 8, &aes);
		unsigned char partial_block = sizeof(sha256) % AES_BLOCK_SIZE ? 1 : 0;
		unsigned char ciphertext_blocks = sizeof(sha256) / AES_BLOCK_SIZE + partial_block;
		unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);
		AES_ecb_encrypt(sha256, ciphertext, &aes, AES_ENCRYPT);
		for (unsigned int i = 0; i < (unsigned int)ciphertext_blocks * AES_BLOCK_SIZE; i += 1)
		{
			fprintf(g, "%02x", ciphertext[i]);
		}
		fprintf(g, "\n");
		free(ciphertext);
	}
	fclose(g);
	fclose(f);
	free(buff);
	_CrtDumpMemoryLeaks();
	return 0;
}