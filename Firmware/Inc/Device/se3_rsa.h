#ifndef SE3_RSA_H
#define SE3_RSA_H

#include <stdint.h>

/**
 * \brief generate an RSA key of the specified length and store it to flash.
 *
 * \param[in] req_size		the size in Bytes of the request sent
 * 							from host (should be SE3_RSA_KEYGEN_REQ_SIZE).
 * \param[in] req			the buffer storing the request sent from host
 * 							(key ID and key length).
 * \param[out] resp_size	the size in Bytes of the response to host
 * 							(2 in case of success, 0 otherwise).
 * \param[out] resp			the buffer storing the response to host
 * 							("OK" in case of success, nothing otherwise).
 *
 * \return 					SE3_RET_SUCCESS in case of success; error code otherwise.
 */
uint16_t se3_rsa_keygen(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp);

uint16_t se3_rsa_keyfind(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);
uint16_t se3_rsa_keydel(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/**
 * \brief store an RSA key to flash.
 *
 * \param[in] req_size		the size in Bytes of the request sent
 * 							from host.
 * \param[in] req			the buffer storing the request sent from host
 * 							(key ID, key size and key).
 * \param[out] resp_size	the size in Bytes of the response to host
 * 							(2 in case of success, 0 otherwise).
 * \param[out] resp			the buffer storing the response to host
 *							("OK" in case of success, nothing otherwise).
 *
 * \return 					SE3_RET_SUCCESS in case of success; error code otherwise.
 */
uint16_t se3_rsa_keyadd(uint16_t req_size, uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/**
 * \brief get the public part of an RSA key stored to flash.
 *
 * \param[in] req_size		the size in Bytes of the request sent
 * 							from host (should be SE3_RSA_KEYGET_REQ_SIZE).
 * \param[in] req			the buffer storing the request sent from host
 * 							(key ID).
 * \param[out] resp_size	the size in Bytes of the response to host
 * 							(2 in case of success, 0 otherwise).
 * \param[out] resp			the buffer storing the response to host
 * 							(key in case of success, nothing otherwise).
 *
 * \return 					SE3_RET_SUCCESS in case of success; error code otherwise.
 */
uint16_t se3_rsa_keyget(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp);

/**
 * \brief perform an RSA operation.
*
 * \param[in] req_size		the size in Bytes of the request sent
 * 							from host.
 * \param[in] req			the buffer storing the request sent from host
 * 							(operation;
 * 							boolean value specifying whether to use
 * 							a key stored to flash or a key passed as input;
 * 							ID of the key to be used or the key itself;
 * 							plain/cipher text, depending on operation;
 * 							signature, in case of verify operation).
 * \param[out] resp_size	the size in Bytes of the response to host.
 * \param[out] resp			the buffer storing the response to host
 * 							(the processed text or a boolean value in case
 * 							of verify operation).
 *
 * \return 					SE3_RET_SUCCESS in case of success; error code otherwise.
 */
uint16_t se3_rsa_operate(uint16_t req_size, uint8_t* req,	uint16_t* resp_size, uint8_t* resp);

/**
 * \brief generate an X.509 certificate and store it to flash.
 *
 * \param[in] req_size		the size in Bytes of the request sent
 * 							from host.
 * \param[in] req			the buffer storing the request sent from host
 * 							(certificate ID, issuer key ID, subject key ID,
 * 							serial, not-before date, not-after date,
 * 							issuer name length, issuer name,
 * 							subject name length, subject name).
 * \param[out] resp_size	the size in Bytes of the response to host
 * 							(2 in case of success, 0 otherwise).
 * \param[out] resp			the buffer storing the response to host
 * 							("OK" in case of success, nothing otherwise).
 *
 * \return 					SE3_RET_SUCCESS in case of success; error code otherwise.
 */
uint16_t se3_rsa_x509_cert_gen(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp);

/**
 * \brief get an X.509 certificate stored to flash.
 *
 * \param[in] req_size		the size in Bytes of the request sent
 * 							from host (should be SE3_RSA_X509_CERT_GET_REQ_SIZE).
 * \param[in] req			the buffer storing the request sent from host
 * 							(certificate ID).
 * \param[out] resp_size	the size in Bytes of the response to host.
 * \param[out] resp			the buffer storing the response to host
 * 							(certificate in case of success, nothing otherwise).
 *
 * \return 					SE3_RET_SUCCESS in case of success; error code otherwise.
 */
uint16_t se3_rsa_x509_cert_get(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp);

/**
 * \brief delete an X.509 certificate stored to flash.
 *
 * \param[in] req_size		the size in Bytes of the request sent
 * 							from host (should be SE3_RSA_X509_CERT_REQ_SIZE).
 * \param[in] req			the buffer storing the request sent from host
 * 							(certificate ID).
 * \param[out] resp_size	the size in Bytes of the response to host
 * 							(2 in case of success, 0 otherwise).
 * \param[out] resp			the buffer storing the response to host
 * 							("OK" in case of success, nothing otherwise).
 *
 * \return 					SE3_RET_SUCCESS in case of success; error code otherwise.
 */
uint16_t se3_rsa_x509_cert_delete(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp);

/**
 * \brief get the list of IDs of X.509 certificates stored to flash.
 *
 * \param[in] req_size		the size in Bytes of the request sent
 * 							from host (should be 0).
 * \param[in] req			the buffer storing the request sent from host
 * 							(nothing).
 * \param[out] resp_size	the size in Bytes of the response to host
 * 							(number of IDs in the list).
 * \param[out] resp			the buffer storing the response to host
 * 							(list of IDs of X.509 certificates stored to flash).
 *
 * \return 					SE3_RET_SUCCESS in case of success, error code otherwise.
 */
uint16_t se3_rsa_x509_cert_list(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp);

/**
 * \brief check if the X.509 certificate corresponding
 * 	to the specified ID is stored to flash.
 *
 * \param[in] req_size		the size in Bytes of the request sent
 * 							from host (should be SE3_RSA_X509_CERT_REQ_SIZE).
 * \param[in] req			the buffer storing the request sent from host
 * 							(certificate ID).
 * \param[out] resp_size	the size in Bytes of the response to host
 * 							(2 in case of success, 0 otherwise).
 * \param[out] resp			the buffer storing the response to host
 * 							("OK" in case of success, nothing otherwise).
 *
 * \return 					SE3_RET_SUCCESS in case of success; error code otherwise.
 */
uint16_t se3_rsa_x509_cert_find(uint16_t req_size, const uint8_t* req,
		uint16_t* resp_size, uint8_t* resp);

#endif /* SE3_RSA_H */
