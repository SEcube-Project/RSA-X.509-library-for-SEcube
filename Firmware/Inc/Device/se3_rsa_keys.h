/**
  ******************************************************************************
  * File Name          : se3_rsa_keys.h
  * Description        : Low level RSA key management
  ******************************************************************************
  */

/**
 *  \file se3_rsa_keys.h
 *  \brief RSA key management
 *
 *  This file is a wrapper around se3_keys.h to make it easily usable
 *  with RSA asymmetric keys.
 */

#ifndef SE3_RSA_KEYS_H
#define SE3_RSA_KEYS_H

#pragma once

#include "se3_flash.h"


/** \brief RSA flash key structure
 *
 *  Disposition of the fields within the flash node:
 *  0:3     										id
 *  4:5     										key_size
 *  6												key_type
 *  7												public_only
 *  8:(8+key_size-1)								N
 *  (8+key_size):(8+2*key_size-1)					D
 *  (8+2*key_size):(8+3*key_size)					E (if public_only == 0)
 */
typedef struct se3_rsa_flash_key_ {
	uint32_t id;
	uint16_t key_size;
	uint8_t type;
	uint8_t public_only;
	uint8_t* N;
	uint8_t* E;
	uint8_t* D;
} se3_rsa_flash_key;

/** \brief Find a key
 *
 *  Find a key in the flash memory
 *  \param id identifier of the key
 *  \param it a flash iterator that will be set to the key's position
 *  \return true on success
 */
bool se3_rsa_key_find(uint32_t id, se3_flash_it* it);

/** \brief Add a new key
 *  
 *  Create a new node with the necessary amount of space for the key,
 *  then write the key.
 *  \remark if a flash operation fails, the hwerror flag (se3c0.hwerror) is set.
 *  \param it a flash iterator which will receive the position of the new node
 *  \param key a flash key structure containing the key information
 *      The data and name fields must point to a valid memory region,
 *      unless their size (data_size, name_size) is zero.
 *  \return true on success, else false
 */
bool se3_rsa_key_new(se3_flash_it* it, se3_rsa_flash_key* key);

/** \brief Read a key
 *  
 *  Read a key from a flash node
 *  \param it a flash iterator pointing to the key
 *  \param key a flash key structure which will receive the key's information. 
 *      The data and name fields will be filled only if not NULL.
 */
void se3_rsa_key_read(se3_flash_it* it, se3_rsa_flash_key* key);

/** \brief Check if key is equal
 *  
 *  Check if the supplied key is equal to a key stored in the flash.
 *  \param it a flash iterator pointing to a key
 *  \param key a flash key structure to compare
 *  \return true if equal, else false
 */
bool se3_rsa_key_equal(se3_flash_it* it, se3_rsa_flash_key* key);

/** \brief Write key data
 *  
 *  Write key data to a flash node
 *  \remark if a flash operation fails, the hwerror flag (se3c0.hwerror) is set.
 *  \param it a flash iterator pointing to a newly created flash node of key type
 *  \param key a flash key structure containing the key information
 *      The data and name fields must point to a valid memory region,
 *      unless their size (data_size, name_size) is zero.
 *  \return true on success, else false
 */
bool se3_rsa_key_write(se3_flash_it* it, se3_rsa_flash_key* key);

/** \brief Produce salted key fingerprint
 *  
 *  \param key a flash key structure containing the key information
 *  \param salt a 32-byte salt
 *  \param fingerprint output 32-byte fingerprint of the key data
 */
void se3_rsa_key_fingerprint(se3_rsa_flash_key* key, const uint8_t* salt, uint8_t* fingerprint);

#endif
