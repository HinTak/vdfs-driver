#ifndef CRYPTO_WRAPPER_H
#define CRYPTO_WRAPPER_H
#include <linux/mpi.h>
typedef struct
{
	MPI rsa_n;
	MPI rsa_e;
} rsakey_t;

enum rsa_padding_mask
{
	RSA_PADDING_PKCS1_TYPE0 = 0x1, //padding 0x00000000..0000[data]
	RSA_PADDING_PKCS1_TYPE1 = 0x2, //padding 0x0001FFFF..FF00[data]
};

int calculate_sw_hash_md5(unsigned char *buf, size_t buf_len, char *hash);
int calculate_sw_hash_sha1(unsigned char *buf, size_t buf_len, char *hash);
int calculate_sw_hash_sha256(unsigned char *buf, size_t buf_len, char *hash);

void destroy_rsa_key(rsakey_t *pkey);
rsakey_t *create_rsa_key(const char *pub_rsa_n, const char *pub_rsa_e,
		size_t n_size, size_t e_size);

int rsa_check_signature(const rsakey_t *pkey,
		const uint8_t *signature, uint32_t sign_len,
		uint8_t *hash, uint32_t hash_len, int padding_type);

#endif
