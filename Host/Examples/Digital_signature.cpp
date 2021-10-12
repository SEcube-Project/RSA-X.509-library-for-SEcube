///**
//  ******************************************************************************
//  * File Name          : digital_signature.cpp
//  * Description        : Example about how to sign data with RSA.
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
///*! \file  digital_signature.cpp
// *  \brief This file is an example about how to sign some data and verify the signature
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
//	cout << "Looking for SEcube devices...\n" << endl;
//	int numdevices = l0->GetNumberDevices(); // this API checks how many SEcube devices are connected to the PC
//	if(numdevices == 0){
//		cout << "No SEcube devices found! Quit." << endl;
//		return 0;
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
//		array<uint8_t, 32> pin = {'t','e','s','t'}; // customize this PIN according to the PIN that you set on your SEcube device
//		l1->Login(pin, SE3_ACCESS_USER, true); // login to the SEcube
//
//		const char *input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
//				"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in "
//				"voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit "
//				"anim id est laborum.";
//		const size_t messageLen = strlen(input) + 1;
//		shared_ptr<uint8_t[]> message = make_unique<uint8_t[]>(messageLen);
//		memcpy(message.get(), input, messageLen);
//
//		cout << "\n\nDigital signature example: Alice signs computes the hash of a message, then she signs it with her private key." << endl;
//		cout << "Bob receives the message and the signature, then he verifies the signature using the public key of Alice.\n\n" << endl;
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
//		/* ALICE */
//		cout << "Alice generates her RSA private and public key..." << endl;
//		se3AsymmKey key = {
//				.id = keyID,
//				.length = KEY_SIZE,
//				.type = L1Key::RSAKeyType::SE3_RSA_KEY_GENERIC
//		};
//		try {
//			l1->Edit_asymm_key(key, L1Commands::KeyOpEdit::SE3_KEY_OP_GENERATE_ASYMM);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//		cout << "Alice signs the message..." << endl;
//		shared_ptr<uint8_t[]> signature;
//		size_t signLen;
//		try {
//			l1->RSA_sign(message, messageLen, signature, signLen, key, false);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//		cout << "Signature: ";
//		for (auto i = 0; i < KEY_SIZE; i++) {
//			printf("%X", signature[i]);
//		}
//		cout << endl;
//
//		/* BOB */
//		cout << "Bob receives the message and the signature sent by Alice; then he verifies the signature using the public key of Alice..." << endl;
//		bool verified;
//		try {
//			l1->RSA_verify(message, messageLen, signature, signLen, key, false, verified);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//		if(verified){
//			cout << "Signature verified correctly." << endl;
//		} else {
//			cout << "Invalid signature!" << endl;
//		}
//
//		cout << "\nDigital signature successfully completed" << endl;
//	} else {
//	cout << "You entered an invalid number. Quit." << endl;
//	}
//	return 0;
//}
