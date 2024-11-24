#include <stdio.h>
#include <malloc.h>
#include <openssl/aes.h>
#include <crtdbg.h>

int main()
{
	FILE* f;
	AES_KEY aes_key;
	unsigned char* buff = NULL;
	unsigned char key[AES_BLOCK_SIZE];
	unsigned char* ciphertext;

	// preparing the message
	f = fopen("dummy.txt", "r");
	fseek(f, 0, SEEK_END);
	unsigned long msg_length = ftell(f);
	buff = (unsigned char*)malloc(msg_length);
	fseek(f, 0, SEEK_SET);
	fread(buff, msg_length, 1, f);
	fclose(f);

	// preparing the key for encryption
	f = fopen("key.txt", "r"); // key must be 128 bits a.k.a. 16 bytes a.k.a. 16 chars - thisisasecretkey
	fseek(f, 0, SEEK_END);
	unsigned long key_length = ftell(f);
	if (key_length != AES_BLOCK_SIZE)
	{
		printf("The key is not 16 bytes!");
		return -1;
	}
	fseek(f, 0, SEEK_SET);
	fread(key, AES_BLOCK_SIZE, 1, f);
	fclose(f);

	AES_set_encrypt_key(key, key_length * 8, &aes_key);

	// encrypting
	unsigned char partial_block = msg_length % AES_BLOCK_SIZE ? 1 : 0;
	unsigned long ciphertext_blocks = msg_length / AES_BLOCK_SIZE + partial_block;
	unsigned long total_ciphertext_size = ciphertext_blocks * AES_BLOCK_SIZE;

	ciphertext = (unsigned char*)malloc(total_ciphertext_size);

	for (unsigned long plain_block_offset = 0; plain_block_offset < msg_length; plain_block_offset += AES_BLOCK_SIZE)
	{
		AES_encrypt(buff + plain_block_offset, ciphertext + plain_block_offset, &aes_key);
	}

	free(buff);

	// writing the bytes to file
	f = fopen("ecb_enc.txt", "w");
	for (unsigned long i = 0; i < total_ciphertext_size; i++)
	{
		fprintf(f, "%02x", ciphertext[i]);
	}
	fclose(f);

	free(ciphertext);

	// preparing the key for decryption
	AES_set_decrypt_key(key, key_length * 8, &aes_key);

	// getting the ciphertext from the file
	f = fopen("ecb_enc.txt", "r");

	ciphertext = (unsigned char*)malloc(total_ciphertext_size);

	for (unsigned long i = 0; i < total_ciphertext_size; i++)
	{
		unsigned int tmp;
		fscanf(f, "%02x", &tmp);
		ciphertext[i] = (unsigned char)tmp;
	}
	fclose(f);

	// decrypting
	unsigned char* decryptedText = (unsigned char*)malloc(msg_length);

	for (unsigned long i = 0; i < total_ciphertext_size; i += AES_BLOCK_SIZE) {
		AES_decrypt(ciphertext + i, decryptedText + i, &aes_key);
	}
	
	free(ciphertext);

	// output the decrypted text to a file
	f = fopen("ecb_dec.txt", "w");
	for (unsigned long i = 0; i < msg_length; i++)
	{
		fprintf(f, "%c", decryptedText[i]);
	}
	free(decryptedText);
	fclose(f);

	_CrtDumpMemoryLeaks();
	return 0;
}