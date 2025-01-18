#include <crtdbg.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <openssl/sha.h>
#define BUFF_LEN 256

void stringify(unsigned char* input, char* output)
{
	for (unsigned char i = 0; i < SHA_DIGEST_LENGTH; i++)
	{
		sprintf(&output[i*2], "%02x", input[i]);
	}
}
int main()
{
	const char* REFERENCE = "2e1a480670e31a5d015e28de043136b62e762d29";
	const char* FILE_NAME_IN = "10-million-password-list-top-1000000.txt";
	const char* FILE_NAME_OUT = "pass_SHA1.txt";
	char buff[BUFF_LEN];
	unsigned char output[SHA_DIGEST_LENGTH];
	char hexString[SHA_DIGEST_LENGTH * 2 + 1];
	SHA_CTX ctx;

	FILE* f = fopen(FILE_NAME_IN, "rb");
	FILE* g = fopen(FILE_NAME_OUT, "w");

	while (fscanf(f, "%s\n", buff) != EOF)
	{
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, buff, strlen(buff));
		SHA1_Final(output, &ctx);
		stringify(output, hexString);
		if (!strcmp(hexString, REFERENCE))
		{
			printf("The password is %s.", buff);
		}
		fprintf(g, "%s\n", hexString);
	}
	fclose(g);
	fclose(f);
	
	_CrtDumpMemoryLeaks();
	return 0;
}