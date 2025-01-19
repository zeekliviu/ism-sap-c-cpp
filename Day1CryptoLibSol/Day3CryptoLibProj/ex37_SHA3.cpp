#include <stdio.h>
#include <openssl/evp.h>
#include <malloc.h>
#include <memory.h>

int main()
{
	EVP_MD_CTX* ctx = NULL;
	const EVP_MD* digest = NULL;

	unsigned char data[] = {
	0xff, 0xa4, 0xff
	};


	digest = EVP_sha3_256();
	ctx = EVP_MD_CTX_new();

	int digestLen = EVP_MD_size(digest);
	unsigned char* md = (unsigned char*)malloc(digestLen);
	memset(md, 0x00, digestLen);

	EVP_DigestInit_ex(ctx, digest, NULL); // initialization of the context
	EVP_DigestUpdate(ctx, data, sizeof(data));
	unsigned int size = 0;
	
	EVP_DigestFinal(ctx, md, &size);
	printf("SHA3 result = ");
	for (unsigned char i = 0; i < digestLen; i++)
	{
		printf("%02x", md[i]);
	}
	printf("\n\n");
	return 0;
}