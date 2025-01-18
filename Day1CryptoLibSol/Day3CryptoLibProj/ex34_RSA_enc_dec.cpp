#include <stdio.h>
#include <malloc.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int main(int argc, char** argv)
{
	FILE* fsrc, * fdst;

	errno_t err = fopen_s(&fsrc, argv[1], "rb"); // this is the file to be encrypted with the RSA key
	errno_t err1 = fopen_s(&fdst, "encFile.bin", "wb+");

	if (err)
	{
		printf("Input file could not be open");
	}

	if (err1)
	{
		printf("Output file could not be created");
	}

	RSA* pubKey;
	FILE* fPubKey;
	err = fopen_s(&fPubKey, "RSAPublicKey.pem", "rb");

	if (err)
	{
		printf("Public key could not be find!");
		return -1;
	}

	pubKey = PEM_read_RSAPublicKey(fPubKey, NULL, NULL, NULL);
	int keySize = RSA_size(pubKey); // RSA key size in number of bytes
	int encSize = 0; // number of bytes for one single round of RSA encryption

	unsigned char* data = (unsigned char*)malloc(keySize * sizeof(unsigned char)); // buffer with the plaintext to be encrypted
	unsigned char* out = (unsigned char*)malloc(keySize * sizeof(unsigned char)); // buffer with the encrypted text
	
	int remainingSize;
	while ((remainingSize = fread(data, 1, keySize, fsrc)) && (remainingSize == keySize))
	{
		encSize = RSA_public_encrypt(keySize, data, out, pubKey, RSA_NO_PADDING);
		fwrite(out, 1, keySize, fdst);
	}
	
	if (remainingSize > 0)
	{
		encSize = RSA_public_encrypt(remainingSize, data, out, pubKey, RSA_PKCS1_PADDING);
		fwrite(out, 1, keySize, fdst);
	}

	// dealocations
	free(out);
	free(data);
	fclose(fdst);
	fclose(fsrc);
	fclose(fPubKey);
	RSA_free(pubKey);

	FILE* encFile;
	err = fopen_s(&encFile, "encFile.bin", "rb");

	if (err)
	{
		printf("Encrypted file could not be open");
		return -1;
	}

	RSA* privKey;
	FILE* fPrivKey;

	err = fopen_s(&fPrivKey, "RSAPrivateKey.pem", "rb");

	if (err)
	{
		printf("Private key file could not be open");
		return -1;
	}

	FILE* decryptedFile;
	err = fopen_s(&decryptedFile, "decrypted.txt", "w+");

	if (err)
	{
		printf("Decrypted file could not be created.");
		return -1;
	}

	privKey = PEM_read_RSAPrivateKey(fPrivKey, NULL, NULL, NULL);
	keySize = RSA_size(privKey);

	unsigned char* encryptedData = (unsigned char*)malloc(sizeof(unsigned char) * keySize);
	unsigned char* decryptedData = (unsigned char*)malloc(sizeof(unsigned char) * keySize);

	fseek(encFile, 0, SEEK_END);
	int noBlocks = ftell(encFile) / keySize;
	fseek(encFile, 0, SEEK_SET);

	int decryptedLen;
	while (noBlocks != 1)
	{
		fread(encryptedData, 1, keySize, encFile);
		decryptedLen = RSA_private_decrypt(keySize, encryptedData, decryptedData, privKey, RSA_NO_PADDING);
		if (decryptedLen == -1)
		{
			return -1;
		}
		fwrite(decryptedData, 1, decryptedLen, decryptedFile);
		noBlocks--;
	}
	int remainingPos = ftell(encFile);
	fseek(encFile, 0, SEEK_END);
	int fileZile = ftell(encFile);
	fseek(encFile, remainingPos, SEEK_SET);
	fread(encryptedData, 1, fileZile - remainingPos, encFile);
	RSA_private_decrypt(fileZile - remainingPos, encryptedData, decryptedData, privKey, RSA_PKCS1_PADDING);
	fwrite(decryptedData, 1, fileZile - remainingPos, decryptedFile);

	free(decryptedData);
	free(encryptedData);
	fclose(decryptedFile);
	fclose(fPrivKey);
	fclose(encFile);
	RSA_free(privKey);

	return 0;
}