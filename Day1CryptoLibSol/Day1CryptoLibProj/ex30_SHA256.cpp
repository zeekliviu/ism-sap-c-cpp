#include <stdio.h>
#include <openssl/sha.h>
int main()
{
	FILE* g = NULL;
	errno_t err2 = fopen_s(&g, "input2.txt", "r");
	SHA256_CTX ctx2;
	SHA256_Init(&ctx2);
	unsigned char buff;
	unsigned int temp;
	unsigned char output2[SHA256_DIGEST_LENGTH];
	while (fscanf_s(g, "%02x", &temp) != EOF)
	{
		buff = (unsigned char)temp;
		SHA256_Update(&ctx2, &buff, 1);
	}
	fclose(g);
	SHA256_Final(output2, &ctx2);
	printf("\nSHA256 digest for the file input2.txt: ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i += 1)
	{
		printf("%02x", output2[i]);
	}

	return 0;
}