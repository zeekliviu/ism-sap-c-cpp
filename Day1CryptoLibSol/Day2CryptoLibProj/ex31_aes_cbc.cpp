#include <openssl/aes.h>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <crtdbg.h>

// TODO: extend implementation for binary and text files: plaintext, ciphertext, key, iv
// TODO: switch to key_192 and key_256

void printArray(unsigned const char* const arr, unsigned const char length, const char* const name)
{
	printf("\nThe %s array is: ", name);
	for (unsigned char i = 0; i < length; i++)
	{
		printf("%02x", arr[i]);
	}
}

int main()
{
	unsigned char plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
							 0x11, 0x02, 0x03, 0x44, 0x55, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
							 0x21, 0x02, 0x03, 0x44, 0x65, 0x06, 0x07, 0x08, 0x09, 0xAA, 0x0B, 0x0C, 0xDD, 0x0E, 0x0F,
							 0x31, 0x02, 0x03, 0x44, 0x75, 0x06, 0x07, 0x08, 0x09, 0xBA, 0x0B, 0x0C, 0xDD, 0x0E };
	unsigned char key_128[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99, 0x88, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x9a, 0x8b };

	unsigned char iv[] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	unsigned char iv2[sizeof(iv)];

	memcpy(iv2, iv, sizeof(iv)); // needed because the IV will be changed after the call to AES_cbc_encrypt
								 // at decryption time, the initial IV must be the same with the initial IV for encryption

	unsigned char* ciphertext = NULL;

	AES_KEY aes_key;

	// encryption

	AES_set_encrypt_key(key_128, sizeof(key_128) * 8, &aes_key);

	unsigned char partial_block = sizeof(plaintext) % AES_BLOCK_SIZE ? 1 : 0;
	unsigned char ciphertext_blocks = sizeof(plaintext) / AES_BLOCK_SIZE + partial_block;

	ciphertext = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

	AES_cbc_encrypt(plaintext, ciphertext, sizeof(plaintext), &aes_key, iv, AES_ENCRYPT);

	printArray(ciphertext, ciphertext_blocks * AES_BLOCK_SIZE, "ciphertext");

	// decryption

	AES_set_decrypt_key(key_128, sizeof(key_128) * 8, &aes_key);

	unsigned char* decryptedText = (unsigned char*)malloc(sizeof(plaintext));

	AES_cbc_encrypt(ciphertext, decryptedText, sizeof(plaintext), &aes_key, iv2, AES_DECRYPT);

	printArray(decryptedText, sizeof(plaintext), "plaintext restored");

	memcmp(plaintext, decryptedText, sizeof(plaintext)) ? printf("\nDecryption failed!") : printf("\nDecryption succeded!");

	free(ciphertext);
	free(decryptedText);

	_CrtDumpMemoryLeaks();

	return 0;
}