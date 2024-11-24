#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <stdio.h>

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
	RSA *rsa_kp = NULL;
	rsa_kp = RSA_generate_key(1024, USHRT_MAX, NULL, NULL);

	RSA_check_key(rsa_kp) ? printf("Key is valid!") : printf("Key is invalid!");


	FILE* fprivate;
	errno_t err = fopen_s(&fprivate, "RSAPrivateKey.pem", "w");
	PEM_write_RSAPrivateKey(fprivate, rsa_kp, NULL, NULL, 0, NULL, NULL);
	FILE* fpublic;
	err = fopen_s(&fpublic, "RSAPublicKey.pem", "w");
	PEM_write_RSAPublicKey(fpublic, rsa_kp);

	RSA_free(rsa_kp);

	return 0;
}