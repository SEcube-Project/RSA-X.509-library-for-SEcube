/**
 ******************************************************************************
 * File Name          : se3_x509.h
 * Description        : Low level X.509 certificate management
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

/**
 *  \file se3_x509.h
 *  \brief X.509 certificate management
 */

#ifndef SE3_X509_H
#define SE3_X509_H

#pragma once
#include "se3c1def.h"
#include "se3_flash.h"
#include "pbkdf2.h"
#include "se3_keys.h"
#define SE3_TYPE_X509 111

/** \brief Flash X.509 certificate structure
 *
 *  Disposition of the fields within the flash node:
 *  0:3     id
 *  4:5     data_size
 *  6:(6+data_size-1) data
 */
typedef struct se3_flash_x509_ {
	uint32_t id;
	uint16_t data_size;
	uint8_t* data;
} se3_flash_x509;

/** Flash X.509 certificate fields */
//enum {
//	SE3_FLASH_KEY_OFF_ID = 0,
//	SE3_FLASH_KEY_OFF_DATA_LEN = 4,
//	SE3_FLASH_KEY_OFF_DATA = 6,
//	SE3_FLASH_KEY_SIZE_HEADER = SE3_FLASH_KEY_OFF_DATA
//};

/** \brief Find a X.509 certificate
 *
 *  Find a X.509 certificate in the flash memory
 *  \param id identifier of the X.509 certificate
 *  \param it a flash iterator that will be set to the X.509 certificate's position
 *  \return true on success
 */
bool se3_x509_find(uint32_t id, se3_flash_it* it);

/** \brief List IDs of all X.509 certificates stored to flash
 *
 *  \param list buffer storing the IDs
 *  \return list size
 */
int se3_x509_list(uint32_t *list);

/** \brief Add a new X.509 certificate
 *  
 *  Create a new node with the necessary amount of space for the X.509 certificate,
 *  then write the X.509 certificate.
 *  \remark if a flash operation fails, the hwerror flag (se3c0.hwerror) is set.
 *  \param it a flash iterator which will receive the position of the new node
 *  \param cert a flash X.509 certificate structure containing the X.509 certificate information
 *      The data and name fields must point to a valid memory region,
 *      unless their size (data_size, name_size) is zero.
 *  \return true on success, else false
 */
bool se3_x509_new(se3_flash_it* it, se3_flash_x509* cert);

/** \brief Read a X.509 certificate
 *  
 *  Read a X.509 certificate from a flash node
 *  \param it a flash iterator pointing to the X.509 certificate
 *  \param cert a flash X.509 certificate structure which will receive the X.509 certificate's information. 
 *      The data and name fields will be filled only if not NULL.
 */
void se3_x509_read(se3_flash_it* it, se3_flash_x509* cert);

/** \brief Check if X.509 certificate is equal
 *  
 *  Check if the supplied X.509 certificate is equal to a X.509 certificate stored in the flash.
 *  \param it a flash iterator pointing to a X.509 certificate
 *  \param cert a flash X.509 certificate structure to compare
 *  \return true if equal, else false
 */
bool se3_x509_equal(se3_flash_it* it, se3_flash_x509* cert);

/** \brief Write X.509 certificate data
 *  
 *  Write X.509 certificate data to a flash node
 *  \remark if a flash operation fails, the hwerror flag (se3c0.hwerror) is set.
 *  \param it a flash iterator pointing to a newly created flash node of X.509 certificate type
 *  \param cert a flash X.509 certificate structure containing the X.509 certificate information
 *      The data and name fields must point to a valid memory region,
 *      unless their size (data_size, name_size) is zero.
 *  \return true on success, else false
 */
bool se3_x509_write(se3_flash_it* it, se3_flash_x509* cert);

/** \brief Produce salted X.509 certificate fingerprint
 *  
 *  \param cert a flash X.509 certificate structure containing the X.509 certificate information
 *  \param salt a 32-byte salt
 *  \param fingerprint output 32-byte fingerprint of the X.509 certificate data
 */
void se3_x509_fingerprint(se3_flash_x509* cert, const uint8_t* salt, uint8_t* fingerprint);

#endif

