#include <stdio.h>
#include <malloc.h>
#include <openssl/aes.h>
#include <crtdbg.h>

#define AES_256_KEY_LENGTH 32

int main()
{
	FILE* f;
	AES_KEY aes_key;
	unsigned char* buff = NULL;
	unsigned char key[AES_256_KEY_LENGTH];
	
	// preparing the message
	f = fopen("dummy.bin", "rb");
	fseek(f, 0, SEEK_END);
	unsigned long msg_length = ftell(f);
	buff = (unsigned char*)malloc(msg_length);
	fseek(f, 0, SEEK_SET);
	fread(buff, msg_length, 1, f);
	fclose(f);

	// preparing the key for encryption
	f = fopen("key.bin", "rb");
	fseek(f, 0, SEEK_END);
	unsigned long key_length = ftell(f);
	if (key_length != AES_256_KEY_LENGTH)
	{
		printf("The key is not 32 bytes!");
		return -1;
	}
	fseek(f, 0, SEEK_SET);
	fread(key, AES_256_KEY_LENGTH, 1, f);
	fclose(f);

	AES_set_encrypt_key(key, key_length * 8, &aes_key);

	//encrypting
	unsigned char partial_block = msg_length % AES_BLOCK_SIZE ? 1 : 0;
	unsigned long ciphertext_blocks = msg_length / AES_BLOCK_SIZE + partial_block;
	unsigned long total_ciphertext_size = ciphertext_blocks * AES_BLOCK_SIZE;

	unsigned char* ciphertext = (unsigned char*)malloc(total_ciphertext_size);

	for (unsigned long plain_block_offset = 0; plain_block_offset < msg_length; plain_block_offset += AES_BLOCK_SIZE)
	{
		AES_encrypt(buff + plain_block_offset, ciphertext + plain_block_offset, &aes_key);
	}

	free(buff);

	// writing the bytes to file
	f = fopen("ecb_enc.bin", "wb");
	fwrite(ciphertext, total_ciphertext_size, 1, f);
	fclose(f);

	free(ciphertext);

	// preparing the key for decryption
	AES_set_decrypt_key(key, key_length * 8, &aes_key);

	// getting the ciphertext from the file
	f = fopen("ecb_enc.bin", "rb");

	ciphertext = (unsigned char*)malloc(total_ciphertext_size);
	fread(ciphertext, total_ciphertext_size, 1, f);
	fclose(f);

	// decrypting
	unsigned char* decryptedArray = (unsigned char*)malloc(msg_length);

	for (unsigned long i = 0; i < total_ciphertext_size; i += AES_BLOCK_SIZE)
	{
		AES_decrypt(ciphertext + i, decryptedArray + i, &aes_key);
	}

	free(ciphertext);

	// output the decrypted array to a file
	f = fopen("ecb_dec.bin", "wb");
	fwrite(decryptedArray, msg_length, 1, f);
	free(decryptedArray);
	fclose(f);

	_CrtDumpMemoryLeaks();

	return 0;
}