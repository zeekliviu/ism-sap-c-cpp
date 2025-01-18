#include <openssl/aes.h>
#include <openssl/evp.h>
#include <malloc.h>
#include <memory.h>

#define CIPHERTEXT_LENGTH 512

void printHex(unsigned char* input, int length)
{
	for (unsigned char i = 0; i < length; i++)
		printf("%02x", input[i]);
}

int main()
{
	unsigned char iv[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
						  0x01, 0x02, 0x03, 0x01, 0x01, 0x01, 0xff, 0xff, };
	unsigned char iv2[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
						  0x01, 0x02, 0x03, 0x01, 0x01, 0x01, 0xff, 0xff, };
	
	unsigned char aes_key[] = {
		0x01, 0x02, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61,
		0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01,
		0x01, 0xff, 0xff, 0xff, 0xff, 0x01, 0xff, 0xff,
	};

	EVP_CIPHER_CTX *context;
	// allocate the context
	context = EVP_CIPHER_CTX_new();
	// initialization of the context
	EVP_CIPHER_CTX_init(context);

	EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), NULL, aes_key, iv);

	int keyLength = EVP_CIPHER_CTX_key_length(context);
	int blockSize = EVP_CIPHER_CTX_block_size(context);
	int ivSize = EVP_CIPHER_CTX_iv_length(context);
	printf("The key length is %d. The block size is %d. The IV size is %d.\n\n", keyLength, blockSize, ivSize);


	FILE* fsrc = fopen("input.txt", "rb");
	fseek(fsrc, 0, SEEK_END);
	int fileLen = ftell(fsrc);
	fseek(fsrc, 0, SEEK_SET);
	int ciphertextLength = (fileLen / blockSize) * blockSize + (fileLen % blockSize ? blockSize : 0);
	unsigned char* ciphertext = (unsigned char*)malloc(sizeof(unsigned char) * ciphertextLength);
	int cipherLen = 0;
	int inOffset = 0, outOffset = 0;
	unsigned char* inData = (unsigned char*)malloc(sizeof(unsigned char) * fileLen);
	fread(inData, 1, fileLen, fsrc);
	EVP_EncryptUpdate(context, ciphertext, &cipherLen, inData, 15); // each update will encrypt block-aligned input;

	if (cipherLen > 0)
	{
		outOffset += cipherLen;
	}
	inOffset += 15;

	EVP_EncryptUpdate(context, (unsigned char*)(ciphertext + outOffset), &cipherLen, (unsigned char*)inData +inOffset, 35); // each update will encrypt block-aligned input;

	if (cipherLen > 0)
	{
		outOffset += cipherLen;
	}
	inOffset += 35;

	EVP_EncryptUpdate(context, (unsigned char*)(ciphertext + outOffset), &cipherLen, (unsigned char*)inData + inOffset, (int)(fileLen-inOffset)); // each update will encrypt block-aligned input;

	if (cipherLen > 0)
	{
		outOffset += cipherLen;
	}
	inOffset += fileLen-inOffset;

	EVP_EncryptFinal_ex(context, (unsigned char*)(ciphertext+outOffset), &cipherLen); // the output pointer is at the end of the output buffer after one/many calls of update

	FILE* fdst = fopen("ciphertext.cbc", "wb+");
	fwrite(ciphertext, sizeof(unsigned char), ciphertextLength, fdst);

	fclose(fdst);
	fclose(fsrc);
	//free(ciphertext);
	free(inData);
	EVP_CIPHER_CTX_free(context);

	context = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(context);
	EVP_DecryptInit_ex(context, EVP_aes_256_cbc(), NULL, aes_key, iv);

	fsrc = fopen("ciphertext.cbc", "rb");
	fseek(fsrc, 0, SEEK_END);
	cipherLen = ftell(fsrc);
	fseek(fsrc, 0, SEEK_SET);
	memset(ciphertext, 0, ciphertextLength);
	fread(ciphertext, sizeof(unsigned char), cipherLen, fsrc);

	unsigned char* plaintext = (unsigned char*)malloc(sizeof(unsigned char)*(cipherLen));
	int decipherLen = 0;
	EVP_DecryptUpdate(context, plaintext, &decipherLen, ciphertext, cipherLen);

	EVP_DecryptFinal_ex(context, plaintext+decipherLen, &decipherLen);

	fdst = fopen("decrypted_cbc.txt", "wb");
	fwrite(plaintext, sizeof(unsigned char), cipherLen, fdst);
	return 0;
}