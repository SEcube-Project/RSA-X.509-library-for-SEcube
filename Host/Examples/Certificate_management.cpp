///**
//  ******************************************************************************
//  * File Name          : certificate_generation.cpp
//  * Description        : Usage example of certificate X.509.
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
///*! \file  certificate_generation.cpp
// *  \brief Example about how to generate a certificate
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
//	int index = 0;
//	uint8_t empty_serial_number[L0Communication::Size::SERIAL] = {0};
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
//
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
//		cout << "In this example we will create 2 RSA key-pairs, each one will be used to sign an X.509 certificate." << endl;
//
//		// let's find a key ID that is not currently used on the SEcube
//		bool found = false;
//		uint32_t keyID = 11; // first ID is arbitrary...could have been 50, 60, 140...
//		uint32_t id1, id2;
//		do{
//			id1 = keyID;
//			l1->Find_asymm_key(keyID, found);
//			if(found){
//				keyID++;
//			} else {
//				keyID++;
//				break;
//			}
//		} while(1);
//		do{
//			id2 = keyID;
//			l1->Find_asymm_key(keyID, found);
//			if(found){
//				keyID++;
//			} else {
//				break;
//			}
//		} while(1);
//
//		cout << "Generating RSA key pairs..." << endl;
//		se3AsymmKey key1 = {
//				.id = id1,
//				.length = KEY_SIZE,
//				.type = L1Key::RSAKeyType::SE3_RSA_KEY_GENERIC
//		};
//		se3AsymmKey key2 = {
//				.id = id2,
//				.length = KEY_SIZE,
//				.type = L1Key::RSAKeyType::SE3_RSA_KEY_GENERIC
//		};
//		try {
//			l1->Edit_asymm_key(key1, L1Commands::KeyOpEdit::SE3_KEY_OP_GENERATE_ASYMM);
//			l1->Edit_asymm_key(key2, L1Commands::KeyOpEdit::SE3_KEY_OP_GENERATE_ASYMM);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//
//		X509_certificate cert1 = {
//				.id = 13,
//				.issuer_key_id = id1,
//				.subject_key_id = id1,
//				.serial_number = "01234567890123456789",
//				.not_before = "20190202171300",
//				.not_after = "20250202171300",
//				.issuer_info = "C=IT,O=PoliTO,CN=PoliTO CA",
//				.subject_info = "C=IT,O=PoliTO,CN=PoliTO CA"
//		};
//		X509_certificate cert2 = {
//				.id = 14,
//				.issuer_key_id = id2,
//				.subject_key_id = id2,
//				.serial_number = "01234567890123333389",
//				.not_before = "20200202171300",
//				.not_after = "20250202171300",
//				.issuer_info = "C=UK,O=PoliMI,CN=PoliMI CA",
//				.subject_info = "C=IT,O=PoliMI,CN=PoliMI CA"
//		};
//
//		cout << "Generating two X.509 certificates on the SEcube..." << endl;
//		try {
//			l1->Edit_certificate(L1Commands::CertOpEdit::SE3_CERT_OP_STORE, cert1);
//			l1->Edit_certificate(L1Commands::CertOpEdit::SE3_CERT_OP_STORE, cert2);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//
//		string cert;
//		cout << "Exporting the first X.509 certificate to a .pem file..." << endl;
//		try {
//			l1->Get_certificate(13, cert);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//		char pwd[PATH_MAX];
//		getcwd(pwd, sizeof(pwd));
//		ofstream certFile;
//		certFile.open("cert.pem");
//		certFile << cert;
//		certFile.close();
//
//		vector<uint32_t> certList;
//		cout << "IDs of X.509 certificates stored on the SEcube:";
//		try {
//			l1->List_certificates(certList);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//		for (auto id : certList){
//			cout << " " << id;
//		}
//		cout << endl;
//
//		cout << "Deleting the two X.509 certificates that were created..." << endl;
//		try {
//			l1->Edit_certificate(L1Commands::CertOpEdit::SE3_CERT_OP_DELETE, cert1);
//			l1->Edit_certificate(L1Commands::CertOpEdit::SE3_CERT_OP_DELETE, cert2);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//
//		certList.clear();
//		cout << "IDs of X.509 certificates stored on the SEcube:";
//		try {
//			l1->List_certificates(certList);
//		} catch (L1Exception& e) {
//			cout << "Failure...quit." << endl;
//			return -1;
//		}
//		for (auto id : certList){
//			cout << " " << id;
//		}
//		cout << endl;
//
//		cout << "\nCertificate usage example successfully completed" << endl;
//	} else {
//	cout << "You entered an invalid number. Quit." << endl;
//	}
//	return 0;
//}
//
//
//
