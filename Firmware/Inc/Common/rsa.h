#ifndef RSA_H
#define RSA_H
#include "mbedtls/rsa.h"

typedef mbedtls_rsa_context rsa_context;

/**
 * \brief          This function initializes an RSA context.
 *
 * \note           This function initializes the padding and the hash
 *                 identifier to respectively #MBEDTLS_RSA_PKCS_V21 and
 *                 #MBEDTLS_MD_SHA256.
 *
 * \param ctx      The RSA context to initialize. This must not be \c NULL.
 */
void rsa_init(rsa_context *ctx);

/**
 * \brief          This function frees the components of an RSA key.
 *
 * \param ctx      The RSA context to free. May be \c NULL, in which case
 *                 this function is a no-op. If it is not \c NULL, it must
 *                 point to an initialized RSA context.
 */
void rsa_free(rsa_context *ctx);

/**
 * \brief          This function imports and completes core RSA parameters, in
 *                 raw big-endian binary format, into an RSA context.
 *
 * \note           The imported parameters are copied and need not be preserved
 *                 for the lifetime of the RSA context being set up.
 *
 * \param ctx      The initialized RSA context to store the parameters in.
 * \param N        The RSA modulus.
 * \param N_len    The Byte length of \p N.
 * \param D        The private exponent. This may be \c NULL.
 * \param D_len    The Byte length of \p D; it is ignored if \p D == NULL.
 * \param E        The public exponent.
 * \param E_len    The Byte length of \p E.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int rsa_import(rsa_context *ctx, size_t key_len,
		unsigned char *N, unsigned char *D, unsigned char *E);

/**
 * \brief          This function exports core parameters of an RSA key
 *                 in raw big-endian binary format.
 *
 *                 If this function runs successfully, the non-NULL buffers
 *                 pointed to by \p N, \p D, and \p E are fully written,
 *                 with additional unused space filled leading by zero Bytes.
 *
 * \note           The length parameters are ignored if the corresponding
 *                 buffer pointers are NULL.
 *
 * \param ctx      The initialized RSA context.
 * \param N        The Byte array to store the RSA modulus,
 *                 or \c NULL if this field need not be exported.
 * \param N_len    The size of the buffer for the modulus.
 * \param D        The Byte array to hold the private exponent,
 *                 or \c NULL if this field need not be exported.
 * \param D_len    The size of the buffer for the private exponent.
 * \param E        The Byte array to hold the public exponent,
 *                 or \c NULL if this field need not be exported.
 * \param E_len    The size of the buffer for the public exponent.
 *
 * \return         \c 0 on success.
 * \return         A non-zero return code on any other failure.
 */
int rsa_export(const rsa_context *ctx, unsigned char *N, size_t N_len,
		unsigned char *D, size_t D_len, unsigned char *E, size_t E_len);

/**
 * \brief          This function retrieves the length of RSA modulus in Bytes.
 *
 * \param ctx      The initialized RSA context.
 *
 * \return         The length of the RSA modulus in Bytes.
 *
 */
size_t rsa_get_len(const rsa_context *ctx);

/**
 * \brief          This function generates an RSA keypair.
 *
 * \note           mbedtls_rsa_init() must be called before this function,
 *                 to set up the RSA context.
 *
 * \param ctx      The initialized RSA context used to hold the key.
 * \param nbits    The size of the public key in bits.
 * \param exponent The public exponent to use. For example, \c 65537.
 *                 This must be odd and greater than \c 1.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int rsa_gen_key(rsa_context *ctx, unsigned int nbits, int exponent);

/**
 * \brief            This function performs a PKCS#1 v2.1 OAEP encryption
 *                   operation (RSAES-OAEP-ENCRYPT).
 *
 * \note             The output buffer must be as large as the size
 *                   of ctx->N. For example, 128 Bytes if RSA-1024 is used.
 *
 * \param ctx        The initialized RSA context to use.
 * \param plain      The input data to encrypt. This must be a readable
 *                   buffer of size \p plain_len Bytes. It may be \c NULL if
 *                   `plain_len == 0`.
 * \param plain_len  The length of the plaintext buffer \p input in Bytes.
 * \param cipher     The output buffer. This must be a writable buffer
 *                   of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                   for an 2048-bit RSA modulus.
 *
 * \return           \c 0 on success.
 * \return           An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int rsa_encrypt(rsa_context *ctx, const unsigned char *plain, size_t plain_len,
		unsigned char *cipher);
/**
 * \brief            This function performs a PKCS#1 v2.1 OAEP decryption
 *                   operation (RSAES-OAEP-DECRYPT).
 *
 * \note             The output buffer length \c plain_max_len should be
 *                   as large as the size \p ctx->len of \p ctx->N, for
 *                   example, 128 Bytes if RSA-1024 is used, to be able to
 *                   hold an arbitrary decrypted message. If it is not
 *                   large enough to hold the decryption of the particular
 *                   ciphertext provided, the function returns
 *                   #MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE.
 *
 * \param ctx        The initialized RSA context to use.
 * \param cipher     The ciphertext buffer. This must be a readable buffer
 *                   of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                   for an 2048-bit RSA modulus.
 * \param plain      The buffer used to hold the plaintext. This must
 *                   be a writable buffer of length \p plain_max_len Bytes.
 * \param plain_len  The address at which to store the length of
 *                   the plaintext. This must not be \c NULL.
 * \param plain_max_len The length in Bytes of the output buffer \p plain.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int rsa_decrypt(rsa_context *ctx, const unsigned char *cipher,
		unsigned char *plain, size_t *plain_len,
		size_t plain_max_len);
/**
 * \brief          This function performs a PKCS#1 v2.1 PSS signature
 *                 operation (RSASSA-PSS-SIGN).
 *
 * \param ctx      The initialized RSA context to use.
 * \param text     The buffer holding the raw data.
 *                 This must be a readable buffer of at least \p text_len Bytes.
 * \param text_len  The length of the raw data in Bytes.
 *                 This must match the output length of the corresponding
 *                 hash algorithm.
 * \param signature The buffer to hold the signature. This must be a writable
 *                 buffer of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                 for an 2048-bit RSA modulus. A buffer length of
 *                 #MBEDTLS_MPI_MAX_SIZE is always safe.
 *
 * \return         \c 0 if the signing operation was successful.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int rsa_sign(rsa_context *ctx, const unsigned char *text, unsigned int text_len,
		unsigned char *signature);

/**
 * \brief          This function performs a PKCS#1 v2.1 PSS verification
 *                 operation (RSASSA-PSS-VERIFY).
 *
 * \param ctx      The initialized RSA public key context to use.
 * \param text     The buffer holding the message digest or raw data.
 *                 This must be a readable buffer of at least \p text_len Bytes.
 * \param text_len The length of the message digest or raw data in Bytes.
 *                 This must match the output length of the corresponding hash algorithm.
 * \param signature The buffer holding the signature. This must be a readable
 *                 buffer of length \c ctx->len Bytes. For example, \c 256 Bytes
 *                 for an 2048-bit RSA modulus.
 *
 * \return         \c 0 if the verify operation was successful.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int rsa_verify(rsa_context *ctx, const unsigned char *text, unsigned int text_len,
		const unsigned char *signature);

#endif /* RSA_H */

