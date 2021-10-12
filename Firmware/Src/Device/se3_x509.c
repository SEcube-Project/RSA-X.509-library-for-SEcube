/**
 ******************************************************************************
 * File Name          : se3_x509.c
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

#include "se3_x509.h"

enum {
	SE3_KEY_OFFSET_ID = 0,
	SE3_KEY_OFFSET_DATALEN = 4,
	SE3_KEY_OFFSET_DATA = 6
};

bool se3_x509_find(uint32_t id, se3_flash_it* it)
{
	uint32_t cert_id = 0;
	se3_flash_it_init(it);
	while (se3_flash_it_next(it)) {
		if (it->type == SE3_TYPE_X509) {
			SE3_GET32(it->addr, SE3_KEY_OFFSET_ID, cert_id);
			if (cert_id == id) {
				return true;
			}
		}
	}
	return false;
}

int se3_x509_list(uint32_t *list)
{
	se3_flash_it it;
	int list_len;

	se3_flash_it_init(&it);

	list_len = 0;
	while (se3_flash_it_next(&it)) {
		if (it.type == SE3_TYPE_X509) {
			SE3_GET32(it.addr, SE3_KEY_OFFSET_ID, list[list_len++]);
		}
	}

	return list_len;
}

bool se3_x509_new(se3_flash_it* it, se3_flash_x509* cert)
{
	uint16_t size = (SE3_FLASH_KEY_SIZE_HEADER + cert->data_size);
	if (size > SE3_FLASH_NODE_DATA_MAX) {
		return false;
	}
	if (!se3_flash_it_new(it, SE3_TYPE_X509, size)) {
		SE3_TRACE(("E cert_new cannot allocate flash block\n"));
		return false;
	}
	return se3_x509_write(it, cert);
}

void se3_x509_read(se3_flash_it* it, se3_flash_x509* cert)
{
	SE3_GET32(it->addr, SE3_KEY_OFFSET_ID, cert->id);
	SE3_GET16(it->addr, SE3_KEY_OFFSET_DATALEN, cert->data_size);
	if (cert->data) {
		memcpy(cert->data, it->addr + SE3_KEY_OFFSET_DATA, cert->data_size);
	}
}

bool se3_x509_equal(se3_flash_it* it, se3_flash_x509* cert)
{
	uint32_t u32tmp = 0;
	uint16_t u16tmp = 0;
	if (cert->data == NULL){
		return false;
	}
	SE3_GET32(it->addr, SE3_KEY_OFFSET_ID, u32tmp);
	if (u32tmp != cert->id){	return false; }
	SE3_GET16(it->addr, SE3_KEY_OFFSET_DATALEN, u16tmp);
	if (u16tmp != cert->data_size){	return false; }
	if (memcmp(it->addr + SE3_KEY_OFFSET_DATA, cert->data, cert->data_size)) {
		return false;
	}
	return true;
}

bool se3_x509_write(se3_flash_it* it, se3_flash_x509* cert)
{
	bool success = false;
	do {
		if (!se3_flash_it_write(it, SE3_KEY_OFFSET_ID, (uint8_t*)&(cert->id), 4)) { // id is uint32_t
			break;
		}
		if (!se3_flash_it_write(it, SE3_KEY_OFFSET_DATALEN, (uint8_t*)&(cert->data_size), 2)) { // datalen is uint16_t
			break;
		}
		if (cert->data_size) {
			if (!se3_flash_it_write(it, SE3_KEY_OFFSET_DATA, cert->data, cert->data_size)) {
				break;
			}
		}
		success = true;
	} while (0);

	if (!success) {
		SE3_TRACE(("[se3_x509_write] cannot write to flash block\n"));
	}
	return success;
}

void se3_x509_fingerprint(se3_flash_x509* cert, const uint8_t* salt, uint8_t* fingerprint)
{
	PBKDF2HmacSha256(cert->data, cert->data_size, salt, SE3_KEY_SALT_SIZE, 1, fingerprint, SE3_KEY_FINGERPRINT_SIZE);
}

