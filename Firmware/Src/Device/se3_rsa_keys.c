/**
  ******************************************************************************
  * File Name          : se3_rsa_keys.c
  * Description        : Low level RSA key management
  ******************************************************************************
  */

#include <se3_rsa.h>
#include "se3_rsa_keys.h"

#include "se3_keys.h"

#define SE3_RSA_KEY_BUFF_SIZE 4+3*SE3_RSA_MAX_KEY_SIZE_BYTES

/** \brief Convert an RSA key flash node to a plain key flash node
 *
 *  \param rsa		pointer to the RSA key flash node to be converted
 *  \param plain	pointer to the plain key flash node to store the
 *  				converted node
 *
 *  \note	N and E fields of \ref rsa must be not null
 *  \note	D field of \ref rsa can be null if D_size field is 0
 *  \note	data field of \ref data must point to an allocated
 *  		memory area at least as big as N_size + D_size + E_size + 3
 *
 *  \return \c true on success
 */
static bool se3_rsa_to_plain_flash(se3_rsa_flash_key *rsa, se3_flash_key *plain)
{
	uint8_t *data;
	if ((rsa == NULL) ||
		(plain == NULL) ||
		(rsa->N == NULL) ||
		(rsa->E == NULL)){
		return false;
	}
	// when key is not public only, private exponent D must be present
	if (!(rsa->public_only) && (rsa->D == NULL)){
		return false;
	}
	plain->id = rsa->id;
	plain->data_size = (sizeof(rsa->key_size) + sizeof(rsa->type) +	sizeof(rsa->public_only) + ((2 + !(rsa->public_only)) * rsa->key_size));
	data = plain->data;
	memcpy(data, &(rsa->key_size), sizeof(rsa->key_size));
	data += sizeof(rsa->key_size);
	memcpy(data, &(rsa->type), sizeof(rsa->type));
	data += sizeof(rsa->type);
	memcpy(data, &(rsa->public_only), sizeof(rsa->public_only));
	data += sizeof(rsa->public_only);
	memcpy(data, rsa->N, rsa->key_size);
	data += rsa->key_size;
	memcpy(data, rsa->E, rsa->key_size);
	data += rsa->key_size;
	if (!(rsa->public_only)) {
		memcpy(data, rsa->D, rsa->key_size);
	}
	return true;
}

/** \brief Convert a plain key flash node to an RSA key flash node
 *
 *  \param plain	pointer to the plain key flash node to be converted
 *  \param rsa		pointer to the RSA key flash node to store the converted node
 *
 *  \return \c true on success
 */
static bool se3_plain_to_rsa_flash(se3_flash_key *plain, se3_rsa_flash_key *rsa)
{
	uint8_t *data;
	if ((plain == NULL) ||
		(rsa == NULL) ||
		(plain->data == NULL) ||
		(rsa->N == NULL) ||
		(rsa->E == NULL)){
		return false;
	}
	rsa->id = plain->id;
	data = plain->data;
	memcpy(&(rsa->key_size), data, sizeof(rsa->key_size));
	data += sizeof(rsa->key_size);
	memcpy(&(rsa->type), data, sizeof(rsa->type));
	data += sizeof(rsa->type);
	memcpy(&(rsa->public_only), data, sizeof(rsa->public_only));
	data += sizeof(rsa->public_only);
	// when key is not public only, private exponent D buffer must be allocated
	if (!(rsa->public_only) && (rsa->D == NULL)){
		return false;
	}
	memcpy(rsa->N, data, rsa->key_size);
	data += rsa->key_size;
	memcpy(rsa->E, data, rsa->key_size);
	data += rsa->key_size;
	if (!(rsa->public_only)) {
		memcpy(rsa->D, data, rsa->key_size);
	} else {
		rsa->D = NULL;
	}
	return true;
}

bool se3_rsa_key_find(uint32_t id, se3_flash_it* it)
{
    return se3_key_find(id, it);
}

bool se3_rsa_key_new(se3_flash_it* it, se3_rsa_flash_key* key)
{
	se3_flash_key plain;
	uint8_t data[SE3_RSA_KEY_BUFF_SIZE] = {0};
	plain.data = data;
	if (!se3_rsa_to_plain_flash(key, &plain)) {
//		SE3_TRACE(("E key_new cannot convert rsa to plain flash block\n"));
		return false;
	}
	return se3_key_new(it, &plain);
}

void se3_rsa_key_read(se3_flash_it* it, se3_rsa_flash_key* key)
{
	se3_flash_key plain;
	uint8_t data[SE3_RSA_KEY_BUFF_SIZE] = {0};
	plain.data = data;
	se3_key_read(it, &plain);
	if (!se3_plain_to_rsa_flash(&plain, key)){
//		SE3_TRACE(("E key_new cannot convert rsa to plain flash block\n"));
	}
}

bool se3_rsa_key_equal(se3_flash_it* it, se3_rsa_flash_key* key)
{
	se3_flash_key plain;
	uint8_t data[SE3_RSA_KEY_BUFF_SIZE] = {0};
	plain.data = data;
	if (!se3_rsa_to_plain_flash(key, &plain)) {
//		SE3_TRACE(("E key_new cannot convert rsa to plain flash block\n"));
		return false;
	}
	return se3_key_equal(it, &plain);
}

bool se3_rsa_key_write(se3_flash_it* it, se3_rsa_flash_key* key)
{
	se3_flash_key plain;
	uint8_t data[SE3_RSA_KEY_BUFF_SIZE] = {0};
	plain.data = data;
	if (!se3_rsa_to_plain_flash(key, &plain)) {
//		SE3_TRACE(("E key_new cannot convert rsa to plain flash block\n"));
		return false;
	}
	return se3_key_write(it, &plain);
}

void se3_rsa_key_fingerprint(se3_rsa_flash_key* key, const uint8_t* salt, uint8_t* fingerprint)
{
	se3_flash_key plain;
	uint8_t data[SE3_RSA_KEY_BUFF_SIZE] = {0};
	plain.data = data;
	if (!se3_rsa_to_plain_flash(key, &plain)) {
//		SE3_TRACE(("E key_new cannot convert rsa to plain flash block\n"));
		return;
	}
	se3_key_fingerprint(&plain, salt, fingerprint);
}
