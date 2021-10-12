///**
//  ******************************************************************************
//  * File Name          : key_distribution.cpp
//  * Description        : Example about how to securely share a symmetric key using RSA.
//  ******************************************************************************
//  *
//  * Copyright 2016-present Blu5 Group <https://www.blu5group.com>
//  *
//  * This library is free software; you can redistribute it and/or
//  * modify it under the terms of the GNU Lesser General Public
//  * License as published by the Free Software Foundation; either
//  * version 3 of the License, or (at your option) any later version.
//  *
//  * This library is distributed in the hope that it will be useful,
//  * but WITHOUT ANY WARRANTY; without even the implied warranty of
//  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//  * Lesser General Public License for more details.
//  *
//  * You should have received a copy of the GNU Lesser General Public
//  * License along with this library; if not, see <https://www.gnu.org/licenses/>.
//  *
//  ******************************************************************************
//  */
//
///*! \file  key_distribution.cpp
// *  \brief Example about how to distribute a symmetric key resorting to RSA encryption
// */
//
//#include "../L1/L1.h"
//#include <memory>
//#include <iostream>
//#include <fstream>
//#include <unistd.h>
//#include <limits.h>
//
//using namespace std;
//
//#define KEY_SIZE 1024/8
//
//int main() {
//	unique_ptr<L0> l0 = make_unique<L0>();
//	unique_ptr<L1> l1 = make_unique<L1>();
//	vector<pair<string, string>> devices;
//	uint8_t empty_serial_number[L0Communication::Size::SERIAL] = {0};
//	int index = 0, sel = 0;
//	int numdevices = l0->GetNumberDevices(); // check how many SEcube devices are connected to the PC
//	cout << "Looking for SEcube devices...\n" << endl;
//	if(numdevices == 0){
//		cout << "No SEcube devices found! Quit." << endl;
//		return -1;
//	}
//	if(l0->GetDeviceList(devices)){ // list of SEcube devices (path, serial number)
//		cout << "Error while searching for SEcube devices! Quit." << endl;
//		return -1;
//	}
//	cout << "Number of SEcube devices found: " << numdevices << endl;
//	cout << "List of SEcube devices (path, serial number):" << endl;
//	for(pair<string, string> p : devices){
//		if(p.second.empty() || memcmp(p.second.data(), empty_serial_number, L0Communication::Size::SERIAL)==0){
//			cout << index << ") " << p.first << " - serial number not available (SEcube requires initialization)" << endl;
//		} else {
//			cout << index << ") " << p.first << " - " << p.second << endl;
//		}
//		index++;
//	}
//	cout << "\nEnter the number corresponding to the SEcube device that you want to use..." << endl;
//	/* warning: if cin does not wait for input in debug mode with eclipse, open the launch configuration and select
//	 * the "use external console for inferior" checkbox under the debugger tab (see https://stackoverflow.com/questions/44283534/c-debug-mode-in-eclipse-causes-program-to-not-wait-for-cin)*/
//	if(!(cin >> sel)){
//		cout << "Input error...quit." << endl;
//		return -1;
//	}
//	if((sel >= 0) && (sel < numdevices)){
//		array<uint8_t, L0Communication::Size::SERIAL> sn = {0};
//		if(devices.at(sel).second.length() > L0Communication::Size::SERIAL){
//			cout << "Unexpected error...quit." << endl;
//			return -1;
//		} else {
//			memcpy(sn.data(), devices.at(sel).second.data(), devices.at(sel).second.length());
//		}
//		l1->Select_SEcube(sn); // select secube with correct serial number
//		cout << "\nDevice " << devices.at(sel).first << " - " << devices.at(sel).second << " selected." << endl;
//
//		array<uint8_t, 32> pin = {'t','e','s','t'}; // customize this PIN according to the PIN that you set on your SEcube device
//		l1->Login(pin, SE3_ACCESS_USER, true); // login to the SEcube
//
//		// let's find a key ID that is not currently used on the SEcube
//		bool found = false;
//		uint32_t keyID = 11; // first ID is arbitrary...could have been 50, 60, 140...
//		do{
//			l1->Find_asymm_key(keyID, found);
//			if(found){
//				keyID++;
//			} else {
//				break;
//			}
//		} while(1);
//
//		cout << "Symmetric key exchange protected by an asymmetric algorithm." << endl;
//		cout << "Alice will encrypt a symmetric key with the public RSA key of Bob." << endl;
//		cout << "Alice sends the encrypted symmetric key to Bob. A secure tunnel is established between the sender and the receiver." << endl;
//		cout << "Bob decrypts the encrypted symmetric key with his private RSA key.\nAlice and Bob are simulated on this device, in the real world they are on two different computers.\n";
//
//		/**** BOB *****/
//		cout << "Bob generates RSA key pair..." << endl;
//		se3AsymmKey BobsKey = {
//				.id = keyID,
//				.length = KEY_SIZE,
//				.type = L1Key::RSAKeyType::SE3_RSA_KEY_GENERIC
//		};
//		try {
//			l1->Edit_asymm_key(BobsKey, L1Commands::KeyOpEdit::SE3_KEY_OP_GENERATE_ASYMM); // public exponent, private exponent, modulus are generated inside the SEcube
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//		cout << "Bob's RSA key pair generated successfully!" << endl;
//
//		cout << "Bob sends public key to Alice..." << endl; // public key = modulus and public exponent
//		cout << "Getting public key from SEcube..." << endl;
//		try {
//			l1->Get_asymm_key(BobsKey);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//
//		/**** ALICE *****/
//		cout << "Alice receives the public key of Bob.\nModulus value: "; // assume Alice receives the content of the BobsKey object created by Bob
//		for (auto i = 0; i < BobsKey.length; i++) {
//			printf("%X ", BobsKey.N[i]);
//		}
//		cout << "\nPublic exponent value: ";
//		for (auto i = 0; i < BobsKey.length; i++) {
//			printf("%X ", BobsKey.E[i]);
//		}
//
//		cout << "\nAlice generates the symmetric key to be shared with Bob..." << endl;
//		shared_ptr<uint8_t[]> symmkey = make_unique<uint8_t[]>(32); // 256-bit symmetric key
//		memset(symmkey.get(), 0xFF, 32); // since this is just an example, we suppose the symmetric key is 0xFF (repeated for 32 bytes)
//		cout << "Hexadecimal value of the symmetric key (fixed for sake of simplicity): ";
//		for(uint16_t i = 0 ; i < 32; ++i ){
//			printf("%02X ", symmkey[i]);
//		}
//		cout << "\nAlice encrypts the symmetric key and sends it to Bob..." << endl;
//		RSA_IO_data encryptedKey;
//		try {
//			l1->RSA_enc_dec(symmkey, 32, encryptedKey, BobsKey, true, true); // true because we use a public key to encrypt, true because we encrypt on the fly, assuming Alice has not stored the public key of Bob on her SEcube
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//		cout << "Encrypted hexadecimal value of the symmetric key: ";
//		for (auto i = 0; i < (int)encryptedKey.data_size; i++) {
//			printf("%X ", encryptedKey.data[i]);
//		}
//		cout << endl;
//
//		/**** BOB *****/
//		cout << "Bob receives the encrypted key sent by Alice and decrypts it..." << endl; // assume Bob receives the content of the encryptedKey object created by Alice
//		std::shared_ptr<uint8_t[]> tmp = std::move(encryptedKey.data);
//		size_t tmpLen = encryptedKey.data_size;
//		encryptedKey.reset();
//		try {
//			l1->RSA_enc_dec(tmp, tmpLen, encryptedKey, BobsKey, false, false); // encryptedKey holds also the decrypted key
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//		cout << "Hexadecimal value of the decrypted symmetric key: ";
//		for(uint16_t i = 0 ; i < (uint16_t)encryptedKey.data_size; i++){
//			printf("%02X ", encryptedKey.data[i]);
//		}
//
//		cout << "\nRSA key distribution example successfully completed. Now Alice and Bob have got a shared symmetric key." << endl;
//	} else {
//	cout << "You entered an invalid number. Quit." << endl;
//	}
//	return 0;
//}
