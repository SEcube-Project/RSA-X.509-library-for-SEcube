/**
  ******************************************************************************
  * File Name          : security_api.h
  * Description        : Functions and data structures related to the security domain of L1 APIs.
  ******************************************************************************
  *
  * Copyright � 2016-present Blu5 Group <https://www.blu5group.com>
  *
  * This library is free software; you can redistribute it and/or
  * modify it under the terms of the GNU Lesser General Public
  * License as published by the Free Software Foundation; either
  * version 3 of the License, or (at your option) any later version.
  *
  * This library is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  * Lesser General Public License for more details.
  *
  * You should have received a copy of the GNU Lesser General Public
  * License along with this library; if not, see <https://www.gnu.org/licenses/>.
  *
  ******************************************************************************
  */

/*! \file  security_api.h
 *  \brief This header file defines functions and data structures related to the security domain of L1 APIs.
 *  \version SEcube Open Source SDK 1.5.1
 */

#ifndef SECURITY_API_H_
#define SECURITY_API_H_

#include "../L1 Base/L1_base.h"

/** This class is used to store the result of the L1Digest() API. It is required, in particular, when the algorithm used to
 *  generate the digest is HMAC-SHA256 because this algorithm requires the usage of a shared secret (a key) and a nonce (to avoid
 *  replay), hence the attributes of this class. If you simply want to compute the digest with SHA-256, then the nonce and
 *  the key are not used at all, therefore the only attribute you care about is the digest. */
class SEcube_digest{
public:
	uint32_t key_id; /**< The ID of the key that is used to generate the digest with HMAC-SHA256. */
	uint16_t algorithm; /**< The algorithm used to generate the digest. */
	std::array<uint8_t, B5_SHA256_DIGEST_SIZE> digest; /**< The digest of the data. The size is B5_SHA256_DIGEST_SIZE because current digest algorithms always produce a result on 32 bytes. */
	std::array<uint8_t, B5_SHA256_DIGEST_SIZE> digest_nonce; /**< This is the nonce that is used to compute the authenticated digest with HMAC-SHA256. */
	bool usenonce; /**< Use the nonce parameter as input to generate the digest. This can be useful if you already have a digest that was computed on the data
	you are working on, and you want to recompute it to check if the data have been modified. So you also need to set the same nonce that was used in the previous
	computation. */
};

/** This class implements a L1Ciphertext object, which is used exclusively by L1Encrypt() and L1Decrypt().
 *  For these APIs, a dedicated object is required because it is important to keep track of every detail of
 *  the crypto computation, for example which nonce or initialization vector was used. The user should not
 *  care about these details, but they are required to correctly perform different operations, for example
 *  to decrypt some data with L1Decrypt() after having encrypted them with L1Encrypt(). */
class SEcube_ciphertext{
public:
	uint32_t key_id; /**< The ID of the key that was used to perform the crypto operation. */
	uint16_t algorithm; /**< The algorithm used to perform the crypto operation (i.e. AES). */
	uint16_t mode; /**< The mode of the algorithm (i.e. CTR). */
	std::unique_ptr<uint8_t[]> ciphertext; /**< The buffer holding the encrypted data. */
	size_t ciphertext_size; /**< The dimension of the ciphertext (bytes). */
	std::array<uint8_t, B5_SHA256_DIGEST_SIZE> digest; /**< The digest that is associated to the data if using AES with HMAC-SHA-256. */
	std::array<uint8_t, B5_SHA256_DIGEST_SIZE> digest_nonce; /**< This is the nonce that is used to compute the authenticated digest. */
	std::array<uint8_t, B5_AES_BLK_SIZE> CTR_nonce; /**< This is the nonce that is used to run the AES cipher in CTR mode. */
	std::array<uint8_t, B5_AES_BLK_SIZE> initialization_vector; /**< This is the initialization vector that is used to run AES in CBC, CFB, OFB modes. */
	void reset(); /**< Reset the content of the L1Ciphertext object. */
};

class RSA_IO_data{
public:
	std::unique_ptr<uint8_t[]> data; /**< The buffer holding the data (ciphertext or plaintext). */
	size_t data_size;
	void reset();
};

class X509_certificate{
public:
	uint32_t id;
	uint32_t issuer_key_id; /**< ID of the key of the issuer. */
	uint32_t subject_key_id; /**< ID of the key of the subject. */
	std::string serial_number; /**< Unique alphanumeric serial number issued by the certificate authority. */
	std::string not_before; /**< Time at which the certificate is first considered valid. */
	std::string not_after; /**< Time at which the certificate is no longer considered valid. */
	std::string issuer_info; /**< Comma-separated string containing OID types and values. */
	std::string subject_info; /**< Comma-separated string containing OID types and values. */
	X509_certificate(uint32_t id, uint32_t issuer_key_id, uint32_t subject_key_id, std::string serial_number, std::string not_before, std::string not_after,	std::string issuer_info, std::string subject_info);
};

class SecurityApi {
private:
public:
	virtual ~SecurityApi() {};

/****************/
/* Generic APIs */
/****************/
	/** @brief Retrieve the list of algorithms supported by the device.
	 * @param [out] algorithmsArray */
	virtual void Get_algorithms(std::vector<se3Algo>& algorithmsArray) = 0;


/***********************/
/* Digest-related APIs */
/***********************/
	/** @brief Compute the digest of some data.
	 * @param [in] input_size The length of the buffer to be processed.
	 * @param [in] input_data The buffer to be processed.
	 * @param [out] digest The object where the digest will be stored.
	 * @detail Before calling this function, you must setup some of the parameters of the digest object that you are going to pass.
	 * Check the documentation of the digest object. For instance, if you want to generate the SHA-256 digest you simply need to set
	 * the "algorithm" parameter. If you want to use the HMAC-SHA256, you also need to set other parameters. */
	virtual void Digest(size_t input_size, std::shared_ptr<uint8_t[]> input_data, SEcube_digest& digest) = 0;

/********************/
/* AES-related APIs */
/********************/
	/** @brief Initialize the crypto context needed to perform an encryption or decryption operation.
	 * @param [in] algorithm The algorithm to be used (see L1Algorithms::Algorithms).
	 * @param [in] mode A combination of the direction (i.e. encrypt or decrypt) and algorithm mode (i.e. CTR). See CryptoInitialisation::mode and CryptoInitialisation::Feedback.
	 * @param [in] keyId The ID of the key to be used to perform the operation.
	 * @param [out] sessId Here is stored the identifier of the crypto context that is initialized. Must be used later by L1CryptoUpdate().
	 * @detail This is a low level function to exploit the crypto features of the SEcube. It can be ignored, we suggest using L1Encrypt(), L1Decrypt() and L1Digest() instead. */
	virtual void Crypto_init(uint16_t algorithm, uint16_t mode, uint32_t keyId, uint32_t& sessId) = 0;
	/** @brief Use the crypto context initialized by L1CryptoInit() to perform the corresponding action on a specific portion of data.
	 * @param [in] sessId The id previously set by L1CryptoUpdate().
	 * @param [in] flags Specific flag for this operation, see L1Crypto::UpdateFlags.
	 * @param [in] data1Len The length of the first buffer to be processed by this crypto operation (can be 0).
	 * @param [in] data1 The first buffer to be processed by this crypto operation (can be NULL).
	 * @param [in] data2Len The length of the second buffer to be processed by this crypto operation (can be 0).
	 * @param [in] data2 The second buffer to be processed by this crypto operation (can be NULL).
	 * @param [out] dataOutLen The length of the output of the crypto operation.
	 * @param [in] dataOut The buffer filled with the result of the crypto operation.
	 * @detail This is a low level function to exploit the crypto features of the SEcube. It can be ignored, we suggest using L1Encrypt(), L1Decrypt() and L1Digest() instead. */
	virtual void Crypto_update(uint32_t sessId, uint16_t flags, uint16_t data1Len, uint8_t* data1, uint16_t data2Len, uint8_t* data2, uint16_t* dataOutLen, uint8_t* dataOut) = 0;
	/** @brief Encrypt some data according to a specific algorithm and mode (i.e. AES-256-CBC), using a specific key.
	 * @param [in] plaintext_size The length of the buffer to be encrypted.
	 * @param [in] plaintext The buffer to be encrypted.
	 * @param [out] encrypted_data The L1Ciphertext object where the encrypted data and other metadata will be stored.
	 * @param [in] algorithm The algorithm to be used (see L1Algorithms::Algorithms).
	 * @param [in] algorithm_mode The mode of the algorithm (i.e. CBC, CTR, etc.). See CryptoInitialisation::Feedback.
	 * @param [in] key_id The ID of the key to be used to perform the operation.
	 * @detail Throws exception in case of errors. */
	virtual void Symm_enc(size_t plaintext_size, std::shared_ptr<uint8_t[]> plaintext, SEcube_ciphertext& encrypted_data, uint16_t algorithm, uint16_t algorithm_mode, uint32_t key_id) = 0;
	/** @brief Decrypt data that were previously encrypted using L1Encrypt().
	 * @param [in] encrypted_data The L1Ciphertext object where the encrypted data and other metadata is stored.
	 * @param [out] plaintext_size The size (bytes) of the decrypted data.
	 * @param [out] plaintext The buffer holding the decrypted data.
	 * @detail Throws exception in case of errors. The L1Ciphertext object passed as parameter should be configured with all the details required by the decryption process.
	 * If the object was generated calling the L1Encrypt() API, then it is already ok. If the data to decrypt have not been encrypted with the L1Encrypt() function, they
	 * must be encapsulated into a L1Ciphertext object; then the object must be configured with the required parameters (i.e. algorithm, mode, nonce, iv, etc...) so that
	 * the L1Decrypt() can perform its task. */
	virtual void Symm_dec(SEcube_ciphertext& encrypted_data, size_t& plaintext_size, std::shared_ptr<uint8_t[]>& plaintext) = 0;
	/* @brief List the keys stored inside the memory of a SEcube device.
	 * @param [out] keylist The list of keys inside the SEcube (ID, length).
	 * @detail This function is dedicated to manual key management, therefore only the keys that are not managed by SEkey will be listed. Throws exception in case of errors. */
	virtual void List_symm_key(std::vector<std::pair<uint32_t, uint16_t>>& keylist) = 0;
	/* @brief Function to manually add or remove keys in the SEcube device. Use this for test purposes or if you do not want to use SEkey.
	 * @param [in] k The key to be written to the SEcube or removed.
	 * @param [in] op The type of operation. See L1Commands::KeyOpEdit for info.
	 * @detail Throws exception in case of errors. When op = L1Commands::KeyOpEdit::SE3_KEY_OP_ADD the parameter k must be filled with all
	 * attributes (id, key size, key value). When op = L1Commands::KeyOpEdit::SE3_KEY_OP_DELETE the parameter k can be filled with the ID
	 * of the key to be deleted, key size must be set to 0 and key value must be NULL. When op = L1Commands::KeyOpEdit::SE3_KEY_OP_ADD_TRNG
	 * the parameter k must be filled with the ID of the key to be added and with the desired key size, key value must be NULL because the
	 * value of the key will be computed inside the SEcube with the TRNG. Notice that the key ID of the keys managed with this API must be
	 * inside the range reserved to keys that are manually managed and out of the scope of SEkey. */
	virtual void Edit_symm_key(se3SymmKey& k, uint16_t op) = 0;
	/* @brief Check if the key with the specified ID is stored inside the SEcube.
	 * @param [in] key_id The ID of the key to search.
	 * @param [out] found Boolean that stores the result of the search. True if the key is found, false otherwise.
	 * @detail Throws exception in case of errors. There is no limitation in terms of IDs that can be passed (everything in range from 0 to 2^32-1 is fine). */
	virtual void Find_symm_key(uint32_t key_id, bool& found) = 0;

/********************/
/* RSA-related APIs */
/********************/
	/** @brief Get modulus and public exponent of asymmetric key.
	* @param [in] id The ID of the key to search for.
	* @return The object containing all info about the requested key. If the requested key is not found, an exception is thrown.
	* @detail Throws exception in case of errors, or if the key is not found. */
	virtual void Get_asymm_key(se3AsymmKey &k) = 0;
	/** @brief Handler for injecting or generating asymmetric keys. Used by L1KeyEdit().
	 * @param [in] k The key to be injected of generated.
	 * @param [in] op The operation to be performed (injection or generation).
	 * @detail Throws exception in case of errors. Do not use expliticly, use L1KeyEdit() instead. */
	virtual void Edit_asymm_key(se3AsymmKey& k, uint16_t op) = 0;
	virtual void Find_asymm_key(uint32_t key_id, bool& found) = 0;
	/** @brief Perform an asymmetric key crypto operation.
	 * @param [in] text_in_size The size of the text to be processed.
	 * If it is greater than (key size + B5_SHA256_DIGEST_SIZE * 2 + 1)
	 * the operation fails: it is advisable to use asymmetric cryptography
	 * to encrypt a symmetric key and then use symmetric cryptography to
	 * encrypt the long text efficiently.
	 * @param [in] text_in The text to be processed.
	 * @param [in] public_key The value which specify the kind of crypto
	 * operation to be performed.
	 * @param [in] key The key information to be used in the crypto operation.
	 * @param [in] on_the_fly The value which specify whether to use the
	 * @param [out] text_out_size The size of the processed text.
	 * @param [out] text_out The processed text.
	 * provided key or read the key from flash.
	 * @detail Throws exception in case of errors.
	 * When \p on_the_fly = true \p key must be filled with all asymmetric
	 * key attributes (dataSize, asymmKey).
	 * When \p on_the_fly = false \p key can be filled with id only. */
	virtual void RSA_enc_dec(std::shared_ptr<uint8_t[]> input, size_t inputLen, RSA_IO_data& output, se3AsymmKey& key, bool public_key, bool on_the_fly) = 0;
	/** @brief Compute the signature of a text.
	 * @param [in] input_size The size of the text to be processed.
	 * @param [in] input_data The text to be processed.
	 * @param [in] key The key information to be used for computing the signature.
	 * @param [in] on_the_fly The value which specify whether to use the
	 * provided key or read the key from flash.
	 * @param [out] sign_size The size of the computed signature.
	 * @param [out] sign The computed signature.
	 * @detail Throws exception in case of errors.
	 * When \p on_the_fly = true \p key must be filled with all asymmetric
	 * key attributes (dataSize, asymmKey).
	 * When \p on_the_fly = false \p key can be filled with id only. */
	virtual void RSA_sign(const std::shared_ptr<uint8_t[]> input, const size_t inputLen, std::shared_ptr<uint8_t[]> &signature, size_t &signature_size, const se3AsymmKey& key, bool on_the_fly) = 0;
	/** @brief Verify the validity of a signature.
	 * @param [in] input_size The size of the original text.
	 * @param [in] input_data The original text.
	 * @param [in] key The key information used for computing the signature.
	 * @param [in] on_the_fly The value which specify whether the key is provided
	 * as input or it should be read from flash.
	 * @param [in] sign_size The size of the signature to be verified.
	 * @param [in] sign The signature to be verified.
	 * @param [out] verified Boolean value containing the result of verification
	 * (true if successful).
	 * @detail Throws exception in case of errors.
	 * When \p on_the_fly = true \p key must be filled with all asymmetric
	 * key attributes (dataSize, asymmKey).
	 * When \p on_the_fly = false \p key can be filled with id only. */
	virtual void RSA_verify(const std::shared_ptr<uint8_t[]> input, const size_t inputLen, const std::shared_ptr<uint8_t[]> signature, const size_t signature_size, const se3AsymmKey& key, bool on_the_fly, bool &verified) = 0;

/********************/
/* PKI-related APIs */
/********************/
	/** @brief Add or remove certificates to the SEcube device.
	 * @param [in] op The type of operation. See L1Commands::CertOpEdit for info.
	 * @param [in] info Information about the certificate to be managed.
	 * @detail Throws exception in case of errors.
	 * When op = L1Commands::CertOpEdit::SE3_CERT_OP_ADD the parameter info
	 * must be filled with all attributes.
	 * When op = L1Commands::CertOpEdit::SE3_CERT_OP_DELETE the parameter
	 * info can be filled with the ID only. */
	virtual void Edit_certificate(const L1Commands::CertOpEdit op, const X509_certificate info) = 0;
	/** @brief Check if a certificate with the provided ID is stored inside the SEcube.
	 * @param [in] certId The ID of the certificate to search for.
	 * @param [out] found Boolean that stores the result (true = found, false = not found).
	 * @detail Throws exception in case of errors. */
	virtual void Find_certificate(uint32_t certId, bool& found) = 0;
	/** @brief Retrieve a certificate from the SEcube, in PEM format.
	* @param [in] cert_id The ID of the certificate to retrieve.
	* @param [out] cert The string holding the certificate data in PEM format.
	* @detail Throws exception in case of errors. */
	virtual void Get_certificate(const uint32_t cert_id, std::string &cert) = 0;
	/** @brief Retrieve the IDs of the certificates stored inside the SEcube device.
	 * @param [out] certlist The list of IDs.
	 * @detail Throws exception in case of errors. */
	virtual void List_certificates(std::vector<uint32_t>& certList) = 0;
};

#endif
