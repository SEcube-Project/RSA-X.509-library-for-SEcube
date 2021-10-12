#include "L1.h"

using namespace std;

void L1::Edit_certificate(const L1Commands::CertOpEdit op, const X509_certificate info) {
	L1Exception exc;
	uint8_t op_inner;
	switch(op){
		case L1Commands::CertOpEdit::SE3_CERT_OP_STORE:
			op_inner = L1Commands::RSA_Options::SE3_RSA_X509_GEN;
			break;
		case L1Commands::CertOpEdit::SE3_CERT_OP_DELETE:
			op_inner = L1Commands::RSA_Options::SE3_RSA_X509_DELETE;
			break;
		default:
			throw exc;
	}
	size_t offset = L1Request::Offset::DATA;
	this->base.FillSessionBuffer((unsigned char *)&op_inner, offset, sizeof(op_inner));
	offset += sizeof(op_inner);
	this->base.FillSessionBuffer((unsigned char *)&info.id, offset, sizeof(info.id));
	offset += sizeof(info.id);
	if (op == L1Commands::CertOpEdit::SE3_CERT_OP_STORE) {
		this->base.FillSessionBuffer((unsigned char *)&info.issuer_key_id, offset, sizeof(info.issuer_key_id));
		offset += sizeof(info.issuer_key_id);
		this->base.FillSessionBuffer((unsigned char *)&info.subject_key_id, offset, sizeof(info.subject_key_id));
		offset += sizeof(info.subject_key_id);
		this->base.FillSessionBuffer((unsigned char *)info.serial_number.data(), offset, 20 + 1);
		offset += 20 + 1;
		this->base.FillSessionBuffer((unsigned char *)info.not_before.data(), offset, 14 + 1);
		offset += 14 + 1;
		this->base.FillSessionBuffer((unsigned char *)info.not_after.data(), offset, 14 + 1);
		offset += 14 + 1;
		const uint16_t issuer_name_len = info.issuer_info.length();
		this->base.FillSessionBuffer((unsigned char *)&issuer_name_len, offset, sizeof(issuer_name_len));
		offset += sizeof(issuer_name_len);
		this->base.FillSessionBuffer((unsigned char *)info.issuer_info.c_str(), offset, issuer_name_len + 1);
		offset += issuer_name_len + 1;
		const uint16_t subject_name_len = info.subject_info.length();
		this->base.FillSessionBuffer((unsigned char *)&subject_name_len, offset, sizeof(subject_name_len));
		offset += sizeof(subject_name_len);
		this->base.FillSessionBuffer((unsigned char *)info.subject_info.c_str(), offset, subject_name_len + 1);
		offset += subject_name_len + 1;
	}

	const size_t data_size = offset - L1Request::Offset::DATA;
	uint16_t resp_size;
	try {
		TXRXData(L1Commands::Codes::RSA, data_size, 0, &resp_size);
	} catch(L1Exception &e) {
		throw exc;
	}
	uint8_t *buff = this->base.GetSessionBuffer() + L1Response::Offset::DATA;
	if((resp_size != 2) || (strncmp((const char *)(buff), "OK", 2) != 0)){
		throw exc;
	}
}

void L1::Find_certificate(uint32_t certId, bool& found) {
	L1Exception exc;
	found = false;
	size_t offset = L1Request::Offset::DATA;
	const uint8_t op = L1Commands::RSA_Options::SE3_RSA_X509_FIND;
	this->base.FillSessionBuffer((unsigned char *)&op, offset, sizeof(op));
	offset += sizeof(op);
	this->base.FillSessionBuffer((unsigned char *)&certId, offset, sizeof(certId));
	offset += sizeof(certId);
	const size_t data_size = offset - L1Request::Offset::DATA;
	uint16_t resp_size;
	try {
		TXRXData(L1Commands::Codes::RSA, data_size, 0, &resp_size);
	} catch(L1Exception &e) {
		throw exc;
	}
	uint8_t *buff = this->base.GetSessionBuffer() + L1Response::Offset::DATA;
	if(strncmp((const char *)(buff), "OK", 2) != 0){
		throw exc;
	}
	buff += 2;
	if(*buff){
		found = true;
	} else {
		found = false;
	}
}

void L1::Get_certificate(const uint32_t cert_id, std::string &cert) {
	L1Exception exc;
	size_t offset = L1Request::Offset::DATA;
	const uint8_t op = L1Commands::RSA_Options::SE3_RSA_X509_GET;
	this->base.FillSessionBuffer((unsigned char *)&op, offset, sizeof(op));
	offset += sizeof(op);
	this->base.FillSessionBuffer((unsigned char *)&cert_id, offset, sizeof(cert_id));
	offset += sizeof(cert_id);
	const size_t data_size = (offset - L1Request::Offset::DATA);
	uint16_t resp_size;
	try {
		TXRXData(L1Commands::Codes::RSA, data_size, 0, &resp_size);
	} catch(L1Exception &e) {
		throw exc;
	}
	if(resp_size == 0){
		throw exc;
	}
	uint8_t *buff = this->base.GetSessionBuffer() + L1Response::Offset::DATA;
	string temp((char*)buff, resp_size);
	cert = temp;
}

void L1::List_certificates(std::vector<uint32_t>& certList) {
	L1Exception exc;
	size_t offset = L1Request::Offset::DATA;
	const uint8_t op = L1Commands::RSA_Options::SE3_RSA_X509_LIST;
	this->base.FillSessionBuffer((unsigned char *)&op, offset, sizeof(op));
	offset += sizeof(op);
	const size_t data_size = (offset - L1Request::Offset::DATA);
	uint16_t resp_size;
	try {
		TXRXData(L1Commands::Codes::RSA, data_size, 0, &resp_size);
	} catch(L1Exception &e) {
		throw exc;
	}
	uint8_t *buff = this->base.GetSessionBuffer() + L1Response::Offset::DATA;
	uint32_t certID = 0;
	const uint16_t list_len = (resp_size / 4); // each certificate ID is a 4-byte unsigned integer
	for(uint16_t i=0; i<list_len; i++){
		memcpy(&certID, buff, sizeof(certID));
		buff += sizeof(certID);
		certList.push_back(certID);
	}
}
