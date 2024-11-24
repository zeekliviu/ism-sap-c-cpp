#include <stdio.h>
#include <openssl/aes.h>
#include <malloc.h>
#include <crtdbg.h>
#include <memory.h>

// TODO: switch to binary and text files for key, plaintext and ciphertext
// TODO: update implementation for key_192 and key_256

int main()
{
	unsigned char plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
							 0x11, 0x02, 0x03, 0x44, 0x55, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
							 0x21, 0x02, 0x03, 0x44, 0x65, 0x06, 0x07, 0x08, 0x09, 0xAA, 0x0B, 0x0C, 0xDD, 0x0E, 0x0F,
							 0x31, 0x02, 0x03, 0x44, 0x75, 0x06, 0x07, 0x08, 0x09, 0xBA, 0x0B, 0x0C, 0xDD, 0x0E };

	unsigned char key_128[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99, 0x88, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x9a, 0x8b};

	unsigned char* ciphertext = NULL;
	//unsigned char ciphertext[(sizeof(plaintext) / AES_BLOCK_SIZE + sizeof(plaintext) % AES_BLOCK_SIZE ? 1 : 0) * AES_BLOCK_SIZE ];

	AES_KEY aes_key;
	AES_set_encrypt_key(key_128, sizeof(key_128) * 8, &aes_key);
	unsigned char partial_block = sizeof(plaintext) % AES_BLOCK_SIZE ? 1 : 0;
	unsigned char ciphertext_blocks = sizeof(plaintext) / AES_BLOCK_SIZE + partial_block;

	ciphertext = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

	for (unsigned char plain_block_offset = 0; plain_block_offset < sizeof(plaintext); plain_block_offset += AES_BLOCK_SIZE) {
		AES_encrypt(plaintext + plain_block_offset, ciphertext + plain_block_offset, &aes_key);
	}

	printf("AES-ECB Ciphertext: ");
	for (unsigned int i = 0; i < (unsigned int)ciphertext_blocks*AES_BLOCK_SIZE; i += 1)
	{
		printf("%02x", ciphertext[i]);
	}

	AES_set_decrypt_key(key_128, sizeof(key_128) * 8, &aes_key);
	unsigned char* decryptedtext = (unsigned char*)malloc(sizeof(plaintext));

	unsigned int cipher_block_offset = 0;
	for (cipher_block_offset = 0; cipher_block_offset < (unsigned int)(ciphertext_blocks - 1) * AES_BLOCK_SIZE; cipher_block_offset += AES_BLOCK_SIZE) {
		AES_decrypt(ciphertext + cipher_block_offset, decryptedtext + cipher_block_offset, &aes_key);
	}

	unsigned char last_block[AES_BLOCK_SIZE];
	
	AES_decrypt(ciphertext + cipher_block_offset, last_block, &aes_key);
	if (partial_block)
	{
		memcpy(decryptedtext + cipher_block_offset, last_block, sizeof(plaintext) % AES_BLOCK_SIZE);
	}
	else
	{
		memcpy(decryptedtext + cipher_block_offset, last_block, AES_BLOCK_SIZE);
	}

	printf("\nPlaintext: ");
	for (unsigned int i = 0; i < sizeof(plaintext); i += 1)
	{
		printf("%02x", plaintext[i]);
	}
	printf("\nAES-ECB Decryptedtext: ");
	for (unsigned int i = 0; i < sizeof(plaintext); i += 1)
	{
		printf("%02x", decryptedtext[i]);
	}

	memcmp(plaintext, decryptedtext, sizeof(plaintext)) ? printf("\nDecryption failed") : printf("\nDecryption successful");

	free(ciphertext);
	free(decryptedtext);


	_CrtDumpMemoryLeaks();

	return 0;
}