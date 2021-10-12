#include "L1.h"

using namespace std;

void L1::Select_SEcube(array<uint8_t, L0Communication::Size::SERIAL>& sn){
	uint8_t indx = 0;
	for(uint8_t i = 0; i < this->GetNumberDevices(); i++){
		if(memcmp(this->GetDeviceSn(), sn.data(), L0Communication::Size::SERIAL) == 0){
			indx = i;
			break;
		}
	}
	L1SelectDeviceException selectDevExc;
	if (!this->SwitchToDevice(indx)){
		throw selectDevExc;
	}
	this->base.SwitchToSession(indx);
}

void L1::Select_SEcube(uint8_t indx){
	L1SelectDeviceException selectDevExc;
	if (!this->SwitchToDevice(indx)){
		throw selectDevExc;
	}
	this->base.SwitchToSession(indx);
}

void L1::Factory_init(const std::array<uint8_t, L0Communication::Size::SERIAL>& serialno) {
	DeviceAlreadyInitializedException exA;
	L0FactoryInitException exB;
	uint16_t r = this->L0FactoryInit(serialno);
	if(r == L0ErrorCodes::Error::SE3_ERR_STATE){
		throw exA;
	} else {
		if(r != L0ErrorCodes::Error::OK){
			throw exB;
		}
	}
}

void L1::Get_SEcube_serialNumber(string& sn){
	char *buf = (char*)this->GetDeviceSn();
	sn = string(buf, L0Communication::Size::SERIAL);
}

void L1::Set_admin_pin(std::array<uint8_t, L1Parameters::Size::PIN>& pin) {
	L1Exception exc;
	if(this->AccessType() != SE3_ACCESS_ADMIN){
		throw exc;
	}
	return L1Config(L1Configuration::RecordType::ADMINPIN, L1Configuration::Operation::SET, pin);
}

void L1::Set_user_pin(std::array<uint8_t, L1Parameters::Size::PIN>& pin) {
	L1Exception exc;
	if(this->AccessType() != SE3_ACCESS_ADMIN){
		throw exc;
	}
	return L1Config(L1Configuration::RecordType::USERPIN, L1Configuration::Operation::SET, pin);
}
