#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/applink.c>

#define SIG_BUF_LEN 512

void printHex(unsigned char* arr, int size)
{
	for (int i = 0; i < size; i++)
	{
		printf("%02x", arr[i]);
	}
	printf("\n");
}

void print_hex_line(FILE* out, const unsigned char* data, size_t len)
{
	for (size_t i = 0; i < len; i++)
	{
		fprintf(out, "%02x", data[i]);
	}
	fprintf(out, "\n");
}

// Helper: Compute the SHA-256 of an entire file (binary-safe).
// On success, digest_out has 32 bytes of the file's SHA-256, and returns 0.
// On error, returns non-zero.
int compute_file_sha256(const char* filename, unsigned char digest_out[SHA256_DIGEST_LENGTH])
{
	FILE* f = fopen(filename, "rb");
	if (!f) {
		perror("fopen in compute_file_sha256");
		return 1;
	}

	SHA256_CTX ctx;
	SHA256_Init(&ctx);

	unsigned char buf[4096];
	size_t nread;
	while ((nread = fread(buf, 1, sizeof(buf), f)) > 0) {
		SHA256_Update(&ctx, buf, nread);
	}
	fclose(f);

	SHA256_Final(digest_out, &ctx);
	return 0;
}

// Helper: Sign a 32-byte SHA-256 digest with the given RSA private key
// using RSA_sign with NID_sha256. Return 0 on success, non-zero on failure.
int sign_digest(const RSA* rsa,
	const unsigned char digest[SHA256_DIGEST_LENGTH],
	unsigned char* sig_out,
	size_t* sig_len)
{
	// RSA_sign wants an unsigned int for the signature length
	unsigned int tmp_len = 0;
	if (!RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, sig_out, &tmp_len, (RSA*)rsa)) {
		// If you want error details:
		// ERR_load_crypto_strings();
		// fprintf(stderr, "RSA_sign error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}
	*sig_len = tmp_len;
	return 0;
}

int encrypt_file_ecb(const char* in_filename, const char* out_filename, const char* key_filename)
{
	// 1) Read 16-byte key from pass.key
	FILE* key_file = fopen(key_filename, "rb");
	if (!key_file) {
		perror("fopen key file");
		return 1;
	}

	unsigned char aes_key[16];
	size_t key_read = fread(aes_key, 1, sizeof(aes_key), key_file);
	fclose(key_file);

	if (key_read != 16) {
		fprintf(stderr, "Error: pass.key must be exactly 16 bytes (128 bits)\n");
		return 1;
	}

	// 2) Open input file (read binary) and output file (write binary)
	FILE* fin = fopen(in_filename, "rb");
	if (!fin) {
		perror("fopen in_filename");
		return 1;
	}
	FILE* fout = fopen(out_filename, "wb");
	if (!fout) {
		perror("fopen out_filename");
		fclose(fin);
		return 1;
	}

	// 3) Initialize the AES encryption key
	AES_KEY enc_key;
	if (AES_set_encrypt_key(aes_key, 128, &enc_key) < 0) {
		fprintf(stderr, "Error setting AES key.\n");
		fclose(fin);
		fclose(fout);
		return 1;
	}

	// We'll read the entire input into memory for simplicity.
	// For large files, you'd want a streaming approach (reading chunk by chunk in multiples of 16).
	// But let's do a direct approach here.

	// 4) Determine file size
	fseek(fin, 0, SEEK_END);
	long filesize = ftell(fin);
	fseek(fin, 0, SEEK_SET);

	if (filesize < 0) {
		fprintf(stderr, "Error: ftell returned negative.\n");
		fclose(fin);
		fclose(fout);
		return 1;
	}

	// 5) Read file into buffer
	unsigned char* file_data = (unsigned char*)malloc(filesize);
	if (!file_data) {
		fprintf(stderr, "Memory allocation error\n");
		fclose(fin);
		fclose(fout);
		return 1;
	}
	if (fread(file_data, 1, filesize, fin) != (size_t)filesize) {
		fprintf(stderr, "Error reading entire file.\n");
		free(file_data);
		fclose(fin);
		fclose(fout);
		return 1;
	}
	fclose(fin);

	// 6) Apply PKCS#7 padding
	// - The padded size must be multiple of 16.
	// - The last byte(s) of the block indicate how many padding bytes there are.
	size_t block_size = 16;
	size_t padding_needed = block_size - (filesize % block_size);
	if (padding_needed == 0) {
		padding_needed = 16; // If already multiple of 16, we add a whole extra block of padding
	}

	size_t total_size = filesize + padding_needed;
	unsigned char* padded_data = (unsigned char*)malloc(total_size);
	if (!padded_data) {
		fprintf(stderr, "Memory allocation error\n");
		free(file_data);
		fclose(fout);
		return 1;
	}

	// Copy original data
	memcpy(padded_data, file_data, filesize);
	free(file_data);

	// Fill padding bytes: each padding byte is the number of bytes added
	for (size_t i = 0; i < padding_needed; i++) {
		padded_data[filesize + i] = (unsigned char)padding_needed;
	}

	// 7) Encrypt in ECB mode, one 16-byte block at a time
	// The result will also be `total_size` bytes
	unsigned char* encrypted_data = (unsigned char*)malloc(total_size);
	if (!encrypted_data) {
		fprintf(stderr, "Memory allocation error\n");
		free(padded_data);
		fclose(fout);
		return 1;
	}

	for (size_t offset = 0; offset < total_size; offset += 16) {
		AES_ecb_encrypt(padded_data + offset,
			encrypted_data + offset,
			&enc_key,
			AES_ENCRYPT);
	}

	free(padded_data);

	// 8) Write encrypted data to the output file
	if (fwrite(encrypted_data, 1, total_size, fout) != total_size) {
		fprintf(stderr, "Error writing encrypted data.\n");
		free(encrypted_data);
		fclose(fout);
		return 1;
	}

	free(encrypted_data);
	fclose(fout);

	return 0; // success
}

#define MAX_SIZE 256
int main()
{
	FILE* accounts = fopen("Accounts_exam.txt", "r");
	FILE* allSigns = fopen("AllSigns.sig", "w");

	char buffer[MAX_SIZE];
	unsigned char sha[SHA256_DIGEST_LENGTH];
	char* charSHA;

	FILE* pkey_file = fopen("RSAPrivateKey_exam.pem", "r");
	if (!pkey_file)
	{
		perror("fopen pkey");
		return 1;
	}

	RSA* rsa = PEM_read_RSAPrivateKey(pkey_file, NULL, NULL, NULL);
	fclose(pkey_file);
	if (!rsa)
	{
		perror("RSA");
		return 1;
	}

	while (fgets(buffer, sizeof(buffer), accounts))
	{
		strtok(buffer, " ");
		strtok(NULL, " ");
		strtok(NULL, " ");
		charSHA = strtok(NULL, " ");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
			if (sscanf(&charSHA[i * 2], "%2hhx", &sha[i]) != 1) {
				break;
			}
		}

		unsigned char signature[SIG_BUF_LEN];
		size_t sig_len = 0;
		if (!RSA_sign(NID_sha256, sha, SHA256_DIGEST_LENGTH, signature, &sig_len, rsa))
		{
			perror("RSA sign");
			return 1;
		}

		print_hex_line(allSigns, signature, sig_len);
	}

	fclose(allSigns);
	fclose(accounts);

	unsigned char sha_accounts[SHA256_DIGEST_LENGTH];
	if (compute_file_sha256("Accounts_exam.txt", sha_accounts) != 0) {
		fprintf(stderr, "Failed to compute SHA-256 of Accounts_exam.txt\n");
		RSA_free(rsa);
		return 1;
	}

	// Sign that digest
	unsigned char signature1[SIG_BUF_LEN];
	size_t sig_len1 = 0;
	if (sign_digest(rsa, sha_accounts, signature1, &sig_len1) != 0) {
		fprintf(stderr, "Failed to sign digest of Accounts_exam.txt\n");
		RSA_free(rsa);
		return 1;
	}

	// Write it to Sign1.sig (binary or hex). Let's do hex with newline:
	FILE* sign1 = fopen("Sign1.sig", "wb");
	if (!sign1) {
		perror("fopen Sign1.sig");
		RSA_free(rsa);
		return 1;
	}
	print_hex_line(sign1, signature1, sig_len1);
	fclose(sign1);

	// 5) Also produce a single signature for the ENTIRE AllSigns.sig
	//    and store that in Sign2.sig
	unsigned char sha_allSigns[SHA256_DIGEST_LENGTH];
	if (compute_file_sha256("AllSigns.sig", sha_allSigns) != 0) {
		perror("failed allSigns.sig");
		RSA_free(rsa);
		return 1;
	}

	unsigned char signature2[SIG_BUF_LEN];
	size_t sig_len2 = 0;
	if (sign_digest(rsa, sha_allSigns, signature2, &sig_len2) != 0) {
		perror("failed digesting all signs");
		RSA_free(rsa);
		return 1;
	}

	FILE* sign2 = fopen("Sign2.sig", "wb");
	if (!sign2) {
		perror("fopen Sign2.sig");
		RSA_free(rsa);
		return 1;
	}
	print_hex_line(sign2, signature2, sig_len2);
	fclose(sign2);

	// Done, free RSA key
	RSA_free(rsa);


	// encryption
	if (encrypt_file_ecb("Accounts_exam.txt", "aes1.enc", "pass.key") != 0) {
		fprintf(stderr, "Failed to encrypt Accounts_exam.txt\n");
	}
	if (encrypt_file_ecb("AllSigns.sig", "aes2.enc", "pass.key") != 0) {
		fprintf(stderr, "Failed to encrypt AllSigns.sig\n");
	}

	return 0;
}