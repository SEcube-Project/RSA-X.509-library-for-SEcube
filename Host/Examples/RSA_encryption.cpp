///**
//  ******************************************************************************
//  * File Name          : rsa_demo.cpp
//  * Description        : Example about how to encrypt data with RSA.
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
//	cout << "Looking for SEcube devices...\n" << endl;
//	int numdevices = l0->GetNumberDevices();
//	if(numdevices == 0){
//		cout << "No SEcube devices found! Quit." << endl;
//		return -1;
//	}
//	vector<pair<string, string>> devices;
//	if(l0->GetDeviceList(devices)){
//		cout << "Error while searching for SEcube devices! Quit." << endl;
//		return -1;
//	}
//	cout << "Number of SEcube devices found: " << numdevices << endl;
//	cout << "List of SEcube devices (path, serial number):" << endl;
//	int index = 0;
//	uint8_t empty_serial_number[L0Communication::Size::SERIAL] = {0};
//	for(pair<string, string> p : devices){
//		if(p.second.empty() || memcmp(p.second.data(), empty_serial_number, L0Communication::Size::SERIAL)==0){
//			cout << index << ") " << p.first << " - serial number not available (please initialize this SEcube)" << endl;
//		} else {
//			cout << index << ") " << p.first << " - " << p.second << endl;
//		}
//		index++;
//	}
//	int sel = 0;
//	cout << "\nEnter the number corresponding to the SEcube device that you want to use..." << endl;
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
//		array<uint8_t, 32> pin = {'t','e','s','t'};
//		l1->Login(pin, SE3_ACCESS_USER, true);
//
//		const char *input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
//		const size_t messageLen = strlen(input) + 1;
//		shared_ptr<uint8_t[]> message = make_unique<uint8_t[]>(messageLen);
//		memcpy(message.get(), input, messageLen);
//
//		// let's find a key ID that is not currently used on the SEcube
//		bool found;
//		uint32_t keyID = 40; // first ID is arbitrary...could have been 50, 60, 140...
//		while(0){
//			l1->Find_asymm_key(keyID, found);
//			if(found){
//				keyID++;
//			} else {
//				break;
//			}
//		}
//		se3AsymmKey key = {.id = keyID, .length = KEY_SIZE, .N = nullptr, .E = nullptr, .D = nullptr, .type = L1Key::RSAKeyType::SE3_RSA_KEY_GENERIC};
//
//		cout << "Generating new RSA key pair inside the SEcube..." << endl;
//		try {
//			l1->Edit_asymm_key(key, L1Commands::KeyOpEdit::SE3_KEY_OP_GENERATE_ASYMM);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//
//		cout << "Encrypting plaintext with the public key that has just been generated..." << endl;
//		RSA_IO_data RSA_result;
//		try {
//			l1->RSA_enc_dec(message, messageLen, RSA_result, key, true, false);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//		cout << "Plaintext content: " << message.get() << endl;
//		cout << "Ciphertext content: ";
//		for (size_t i = 0; i < RSA_result.data_size; i++) {
//			printf("%X", RSA_result.data[i]);
//		}
//		cout << endl;
//
//		cout << "Decrypting ciphertext with the private key that has just been generated..." << endl;
//		std::shared_ptr<uint8_t[]> encrypted = std::move(RSA_result.data);
//		size_t encryptedsize = RSA_result.data_size;
//		RSA_result.reset(); // we reuse the initial RSA_IO_data object
//		try {
//			l1->RSA_enc_dec(encrypted, encryptedsize, RSA_result, key, false, false);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//		cout << "Decrypted content (should be equal to plaintext): ";
//		for(size_t i = 0 ; i < RSA_result.data_size ; ++i ){
//			printf("%c",RSA_result.data[i]);
//		}
//		cout << endl;
//
//		cout << "\nEncryption example successfully completed" << endl;
//	} else {
//	cout << "You entered an invalid number. Quit." << endl;
//	}
//	return 0;
//}
//
//
//
