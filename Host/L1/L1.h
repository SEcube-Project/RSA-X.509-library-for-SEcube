/**
  ******************************************************************************
  * File Name          : L1.h
  * Description        : Attributes and the methods of the L1 class.
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

/*! \file  L1.h
 *  \brief This header file defines the attributes and the methods of the L1 class.
 *  \version SEcube Open Source SDK 1.5.1
 */

#ifndef L1_H_
#define L1_H_

#include "../L0/L0.h"
#include "L1 Base/L1_base.h"
#include "Login-Logout API/login_logout_api.h"
#include "Security API/security_api.h"
#include "Utility API/utility_api.h"

/** This class defines the attributes and the methods of a L1 object. L1 is built upon L0, therefore it uses a higher
 *  level of abstraction. L0 is focused on very basic actions (such as low level USB communication with the SEcube),
 *  L1 is focused on more "generic" actions, such as the encryption of data or the login to the SEcube using a specific
 *  PIN code. L0 should be used in the initial stage of any SEcube-related software, for instance to list all the available
 *  SEcube devices. Then, after a specific SEcube device has been selected, L1 comes into play allowing to login to the
 *  SEcube and to perform more complex operations (i.e. encrypt data). If a higher level of abstraction is needed (i.e.
 *  to perform even more complex operations, such as working on an encrypted file) then the libraries belonging to the L2
 *  level can be used (although it should be noted that a corresponding L2 object does not exist, since these libraries
 *  offer specific APIs to the developers).  */
class L1 : private L0, public LoginLogoutApi, public SecurityApi, public UtilityApi {
private:
	L1Base base;
	uint8_t index; // this is used only by SEkey to support multiple SEcube connected to the same host computer (default value 255)
	void SessionInit();
	void PrepareSessionBufferForChallenge(uint8_t* cc1, uint8_t* cc2, uint16_t access);
	void TXRXData(uint16_t cmd, uint16_t reqLen, uint16_t cmdFlags, uint16_t* respLen, uint32_t timeout = SE3_TIMEOUT);
	void Se3PayloadCryptoInit();
	void Se3PayloadEncrypt(uint16_t flags, uint8_t* iv, uint8_t* data, uint16_t nBlocks, uint8_t* auth);
	void Se3PayloadDecrypt(uint16_t flags, const uint8_t* iv, uint8_t* data, uint16_t nBlocks, const uint8_t* auth);
	void L1Config(uint16_t type, uint16_t op, std::array<uint8_t, L1Parameters::Size::PIN>& value);
	//void KeyList(uint16_t maxKeys, uint16_t skip, se3SymmKey* keyArray, uint16_t* count);
public:
	L1(); /**< Default constructor. */
	L1(uint8_t index); /**< Custom constructor used only in a very specific case by the APIs of the SEkey library (L2). Do not use elsewhere. */
	~L1(); /**< Destructor. Automatic logout implemented. */

	/* SEcube utility APIs */
	void Select_SEcube(std::array<uint8_t, L0Communication::Size::SERIAL>& sn) override;
	void Select_SEcube(uint8_t indx) override;
	void Factory_init(const std::array<uint8_t, L0Communication::Size::SERIAL>& serialno) override;
	void Get_SEcube_serialNumber(std::string& sn) override;
	void Set_admin_pin(std::array<uint8_t, L1Parameters::Size::PIN>& pin) override;
	void Set_user_pin(std::array<uint8_t, L1Parameters::Size::PIN>& pin) override;

	/* SEcube login/logout APIs */
	void Login(const std::array<uint8_t, L1Parameters::Size::PIN>& pin, se3_access_type access, bool force) override ;
	void Logout() override ;
	void Logout_forced() override;
	bool LoggedIn() override;
	se3_access_type AccessType() override;

	/* AES-related APIs */
	void Crypto_init(uint16_t algorithm, uint16_t mode, uint32_t keyId, uint32_t& sessId) override;
	void Crypto_update(uint32_t sessId, uint16_t flags, uint16_t data1Len, uint8_t* data1, uint16_t data2Len, uint8_t* data2, uint16_t* dataOutLen, uint8_t* dataOut) override;
	void Symm_enc(size_t plaintext_size, std::shared_ptr<uint8_t[]> plaintext, SEcube_ciphertext& encrypted_data, uint16_t algorithm, uint16_t algorithm_mode, uint32_t key_id) override;
	void Symm_dec(SEcube_ciphertext& encrypted_data, size_t& plaintext_size, std::shared_ptr<uint8_t[]>& plaintext) override;
	void Edit_symm_key(se3SymmKey& k, uint16_t op) override;
	void List_symm_key(std::vector<std::pair<uint32_t, uint16_t>>& keylist) override ;
	void Find_symm_key(uint32_t key_id, bool& found) override ;

	/* Digest-related APIs */
	void Digest(size_t input_size, std::shared_ptr<uint8_t[]> input_data, SEcube_digest& digest) override;

	/* RSA-related APIs */
	void Get_asymm_key(se3AsymmKey& k) override;
	void Edit_asymm_key(se3AsymmKey& k, uint16_t op) override;
	void Find_asymm_key(uint32_t key_id, bool& found) override;
	void RSA_enc_dec(std::shared_ptr<uint8_t[]> input, size_t inputLen, RSA_IO_data& output, se3AsymmKey& key, bool public_key, bool on_the_fly) override;
	void RSA_sign(const std::shared_ptr<uint8_t[]> input, const size_t inputLen, std::shared_ptr<uint8_t[]> &signature, size_t &signature_size, const se3AsymmKey& key, bool on_the_fly) override;
	void RSA_verify(const std::shared_ptr<uint8_t[]> input, const size_t inputLen, const std::shared_ptr<uint8_t[]> signature, const size_t signature_size, const se3AsymmKey& key, bool on_the_fly, bool &verified) override;

	/* PKI-related APIs */
	void Edit_certificate(const L1Commands::CertOpEdit op, const X509_certificate info) override;
	void Find_certificate(uint32_t certId, bool& found) override;
	void Get_certificate(const uint32_t cert_id, std::string &cert) override;
	void List_certificates(std::vector<uint32_t>& certList) override;

	/* Other APIs */
	void Get_algorithms(std::vector<se3Algo>& algorithmsArray) override ;

	/*****************************************/
	/* SEkey APIs used for internal purposes */
	/*****************************************/
	/** @brief Read or write the user ID and the user name of the SEcube owner (member of SEkey) from/to the SEcube. Used only by SEkey, do not use explicitly.
	 * @param [in] id The string where the user ID is stored.
	 * @param [in] name The string where the user name is stored.
	 * @param [in] mode Read or write, according to L1SEkey::Direction.
	 * @return True on success, false otherwise. If mode is read, the user ID and the user name are returned through the respective parameters. If mode is write, those values are stored into the SEcube. */
	bool SEkey_Info(std::string& id, std::string& name, uint8_t mode);
	/** @brief Export a key from the SEcube flash memory, wrapping it with another key. Used only by SEkey, do not use explicitly.
	 * @param [in] key_export_id The ID of the key to be exported.
	 * @param [in] key_wrapping_key The ID of the wrapping key.
	 * @param [out] key_export_data The byte array where the wrapped key will be stored.
	 * @param [out] key_export_len The length of the exported key (length of the ciphertext).
	 * @return True on success, false otherwise. */
	bool SEkey_GetKeyEnc(uint32_t key_export_id, uint32_t key_wrapping_key, std::shared_ptr<uint8_t[]>& key_export_data, uint16_t& key_export_len);
	/** @brief This is used to list the IDs of all the keys stored inside a SEcube device. Used only by SEkey, do not use explicitly.
	 * @param [in] buffer The buffer where the result is stored (6010 bytes recommended size).
	 * @param [out] buflen The length of the result.
	 * @details This function is used exclusively by SEkey to perform a sort of garbage collector, it should not be used in any other case. */
	void SEkey_Maintenance(uint8_t *buffer, uint16_t *buflen);
	/** @brief Delete the key with the specified ID from the SEcube. Used only by SEkey, do not use explicitly.
	 * @param [in] key_id The ID of the key to be deleted.
	 * @return True on success, false otherwise. */
	bool SEkey_DeleteKey(uint32_t key_id);
	/** @brief Check if the SEcube is ready for SEkey (meaning that it has been initialized with the correct keys).
	 * @return True if the SEcube is initialized for SEkey, false otherwise. */
	bool SEkey_isReady();
	/** @brief Delete all the keys from the SEcube, except for the keys specified in the keep parameter. Used only by SEkey, do not use explicitly.
	 * @param [in] keep The IDs of the keys that must not be deleted.
	 * @return True on success, false otherwise. */
	bool SEkey_DeleteAllKeys(std::vector<uint32_t>& keep);
	/** @brief Write a key into the SEcube. The key to be written may still be wrapped with another key. Used only by SEkey, do not use explicitly.
	 * @param [in] key_id The ID of the key to be written.
	 * @param [in] key_len The length of the key to be written.
	 * @param [in] dec_id The ID of the key to be used to unwrapped the key that needs to be written.
	 * @param [in] key_data The value of the key to be written. Can be null if the key must be generated inside the SEcube with the TRNG.
	 * @return True on success, false otherwise. */
	bool SEkey_InsertKey(uint32_t key_id, uint16_t key_len, uint32_t dec_id, std::shared_ptr<uint8_t[]> key_data);
};

#endif
