#include <stdio.h>
#include <openssl/sha.h>

#define INPUT_BLOCK_LENGTH 15

int main()
{
	unsigned char input[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
							 0x11, 0x02, 0x03, 0x44, 0x55, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
							 0x21, 0x02, 0x03, 0x44, 0x65, 0x06, 0x07, 0x08, 0x09, 0xAA, 0x0B, 0x0C, 0xDD, 0x0E, 0x0F, 
							 0x31, 0x02, 0x03, 0x44, 0x75, 0x06, 0x07, 0x08, 0x09, 0xBA, 0x0B, 0x0C, 0xDD, 0x0E };

	// Hashing the input using SHA1
	SHA_CTX ctx;

	SHA1_Init(&ctx);
	unsigned char input_length = sizeof(input) / sizeof(input[0]); // total length of the array
	unsigned char remaining_length = input_length;
	unsigned char output[SHA_DIGEST_LENGTH];

	while (remaining_length > 0)
	{
		if (remaining_length > INPUT_BLOCK_LENGTH)
		{
			// sha1 update done for INPUT_BLOCK_LENGTH bytes
			SHA1_Update(&ctx, (input + input_length - remaining_length), INPUT_BLOCK_LENGTH); // one data block having exactly 15 bytes is processed
			remaining_length -= INPUT_BLOCK_LENGTH;
		}
		else {
			// sha1 update done for less or equal to 15 bytes as data length
			SHA1_Update(&ctx, (input + input_length - remaining_length), remaining_length); // remaining data block is processed
			remaining_length = 0; // there is no more data to be processed by SHA1_Update rounds
			SHA1_Final(output, &ctx);
		}
	}

	printf("SHA1 digest for the hard-coded input: ");
	for (int i = 0; i < SHA_DIGEST_LENGTH; i += 1)
	{
		printf("%02x", output[i]);
	}

	// Hashing the same input from a binary file using SHA1
	FILE* f = NULL;
	errno_t err = fopen_s(&f, "input_SHA1.bin", "rb");
	if (err == 0)
	{
		SHA1_Init(&ctx);
		remaining_length = input_length;
		while (remaining_length > 0)
		{
			unsigned char buf[INPUT_BLOCK_LENGTH];
			if (remaining_length > INPUT_BLOCK_LENGTH)
			{
				// sha1 update done for INPUT_BLOCK_LENGTH bytes
				
				fread(buf, 1, INPUT_BLOCK_LENGTH, f);
				SHA1_Update(&ctx, buf, INPUT_BLOCK_LENGTH); // one data block having exactly 15 bytes is processed
				remaining_length -= INPUT_BLOCK_LENGTH;
			}
			else {
				// sha1 update done for less or equal to 15 bytes as data length
				fread(buf, 1, remaining_length, f);
				SHA1_Update(&ctx, buf, remaining_length); // remaining data block is processed
				remaining_length = 0; // there is no more data to be processed by SHA1_Update rounds
				SHA1_Final(output, &ctx);
			}
		}
		printf("\nSHA1 digest for the file input: ");
		
		for (int i = 0; i < SHA_DIGEST_LENGTH; i += 1)
		{
			printf("%02x", output[i]);
		}
	}
	else {
		printf("File is not found!");
	}

	// Writing the input array to a text file (hex format) then reading it and hashing it using SHA1
	FILE* g = NULL;
	errno_t err2 = fopen_s(&g, "input2.txt", "w");
	for (int i = 0; i < sizeof(input) / sizeof(input[0]); i += 1)
	{
		fprintf(g, "%02x", input[i]);
	}
	fclose(g);
	err2 = fopen_s(&g, "input2.txt", "r");
	SHA1_Init(&ctx);
	unsigned int temp;
	unsigned char buff;
	while (fscanf_s(g, "%02x", &temp) != EOF)
	{
		buff = (unsigned char)temp;
		SHA1_Update(&ctx, &buff, 1);
	}
	fclose(g);
	SHA1_Final(output, &ctx);
	printf("\nSHA1 digest for the file input2.txt: ");
	for (int i = 0; i < SHA_DIGEST_LENGTH; i += 1)
	{
		printf("%02x", output[i]);
	}
	
	return 0;
}