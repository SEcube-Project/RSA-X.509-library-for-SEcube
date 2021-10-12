#include "rsa.h"

#include "se3_rand.h"

void rsa_init(rsa_context *ctx)
{
	mbedtls_rsa_init(ctx);
	mbedtls_rsa_set_padding(ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
}

void rsa_free(rsa_context *ctx)
{
	mbedtls_rsa_free(ctx);
}

size_t rsa_get_len(const rsa_context *ctx)
{
	return mbedtls_rsa_get_len(ctx);
}

int rsa_import(rsa_context *ctx, size_t key_len, unsigned char *N, unsigned char *D, unsigned char *E)
{
	rsa_init(ctx);

	int ret = mbedtls_rsa_import_raw(ctx, N, key_len, NULL, 0, NULL, 0,	D, key_len, E, key_len);

	if (ret != 0){
		rsa_free(ctx);
		return ret;
	}

	return mbedtls_rsa_complete(ctx);
}

int rsa_export(const rsa_context *ctx, unsigned char *N, size_t N_len, unsigned char *D, size_t D_len, unsigned char *E, size_t E_len)
{
	return mbedtls_rsa_export_raw(ctx, N, N_len, NULL, 0, NULL, 0, D, D_len, E, E_len);
}

int rsa_gen_key(rsa_context *ctx, unsigned int nbits, int exponent)
{
	return mbedtls_rsa_gen_key(ctx, se3_rand_mbedtls, NULL, nbits, exponent);
}	

int rsa_encrypt(rsa_context *ctx, const unsigned char *plain, size_t plain_len,	unsigned char *cipher)
{
	return mbedtls_rsa_rsaes_oaep_encrypt(ctx, se3_rand_mbedtls, NULL, NULL, 0, plain_len, plain, cipher);
}

int rsa_decrypt(rsa_context *ctx, const unsigned char *cipher, unsigned char *plain, size_t *plain_len,	size_t plain_max_len)
{
	return mbedtls_rsa_rsaes_oaep_decrypt(ctx, se3_rand_mbedtls, NULL, NULL, 0, plain_len, cipher, plain, plain_max_len);
}

int rsa_sign(rsa_context *ctx, const unsigned char *text, unsigned int text_len, unsigned char *signature)
{
	unsigned char hash[32] = {0};
	int ret;

	ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), text, text_len, hash);

	if (ret == 0) {
		ret = mbedtls_rsa_rsassa_pss_sign_ext(ctx, se3_rand_mbedtls,
				NULL, MBEDTLS_MD_SHA256, 32, hash,
				MBEDTLS_RSA_SALT_LEN_ANY, signature);
	}

	return ret;
}

int rsa_verify(rsa_context *ctx, const unsigned char *text, unsigned int text_len, const unsigned char *signature)
{
	unsigned char hash[32] = {0};
	int ret;

	ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), text, text_len, hash);

	if (ret == 0) {
		ret = mbedtls_rsa_rsassa_pss_verify(ctx, MBEDTLS_MD_SHA256, 32, hash, signature);
	}

	return ret;
}

