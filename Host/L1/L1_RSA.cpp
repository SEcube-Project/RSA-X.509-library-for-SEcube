#include "L1.h"

void RSA_IO_data::reset(){
	this->data.reset();
	this->data_size = 0;
}

X509_certificate::X509_certificate(uint32_t id, uint32_t issuer_key_id, uint32_t subject_key_id, std::string serial_number, std::string not_before, std::string not_after,	std::string issuer_info, std::string subject_info){
	this->id = id;
	this->issuer_key_id = issuer_key_id;
	this->subject_key_id = subject_key_id;
	this->serial_number = serial_number;
	this->not_before = not_before;
	this->not_after = not_after;
	this->issuer_info = issuer_info;
	this->subject_info = subject_info;
}

void L1::Find_asymm_key(uint32_t id, bool& found) {
	L1Exception exc;
	size_t offset = L1Request::Offset::DATA;
	uint8_t rsa_op = L1Commands::RSA_Options::SE3_RSA_KEYFIND;
	this->base.FillSessionBuffer(&rsa_op, offset, sizeof(rsa_op));
	offset += sizeof(rsa_op);
	this->base.FillSessionBuffer((uint8_t *)&id, offset, sizeof(id));
	offset += sizeof(id);
	const size_t data_size = offset - L1Request::Offset::DATA;
	uint16_t resp_size;
	try {
		TXRXData(L1Commands::Codes::RSA, data_size, 0, &resp_size);
	} catch(L1Exception& e) {
		throw exc;
	}
	if(resp_size == 0){
		throw exc;
	} else {
		uint8_t res;
		this->base.ReadSessionBuffer((uint8_t*)&res, L1Response::Offset::DATA, 1);
		if(res){
			found = true;
		} else {
			found = false;
		}
	}
}

void L1::Get_asymm_key(se3AsymmKey& k) {
	L1Exception exc;
	size_t offset = L1Request::Offset::DATA;
	uint8_t rsa_op = L1Commands::RSA_Options::SE3_RSA_KEYGET;
	this->base.FillSessionBuffer(&rsa_op, offset, sizeof(rsa_op));
	offset += sizeof(rsa_op);
	this->base.FillSessionBuffer((uint8_t *)&k.id, offset, sizeof(k.id));
	offset += sizeof(k.id);
	const size_t data_size = offset - L1Request::Offset::DATA;
	uint16_t resp_size;
	try {
		TXRXData(L1Commands::Codes::RSA, data_size, 0, &resp_size);
	} catch(L1Exception& e) {
		throw exc;
	}
	if(resp_size == 0){
		throw exc;
	}
	const uint16_t key_size = (resp_size / 2); // because response includes modulus + public exponent
	k.length = key_size;
	k.D = nullptr; // private exponent is null, because it cannot be exposed outside of the SEcube
	uint8_t *buff = this->base.GetSessionBuffer() + L1Response::Offset::DATA;
	k.N = std::make_unique<uint8_t[]>(key_size);
	k.E = std::make_unique<uint8_t[]>(key_size);
	memcpy(k.N.get(), buff, key_size); // modulus
	buff += key_size;
	memcpy(k.E.get(), buff, key_size); // public exponent
	k.type = L1Key::RSAKeyType::SE3_RSA_KEY_GENERIC;
}

void L1::Edit_asymm_key(se3AsymmKey& k, uint16_t op) {
	L1KeyEditException exc;
	uint8_t rsa_op;
	uint16_t resp_size;
	size_t offset = L1Request::Offset::DATA;
	switch(op){
		case L1Commands::KeyOpEdit::SE3_KEY_OP_INJECT_ASYMM:
			rsa_op = L1Commands::RSA_Options::SE3_RSA_KEYADD;
			this->base.FillSessionBuffer((uint8_t*)&(rsa_op), offset, sizeof(rsa_op));
			offset += sizeof(rsa_op);
			this->base.FillSessionBuffer((uint8_t*)&(k.id), offset, sizeof(k.id));
			offset += sizeof(k.id);
			this->base.FillSessionBuffer((uint8_t*)&(k.length), offset, sizeof(k.length));
			offset += sizeof(k.length);
			this->base.FillSessionBuffer((uint8_t*)&(k.type), offset, sizeof(k.type));
			offset += sizeof(k.type);
			if ((k.N == nullptr) || (k.E == nullptr)) {
				throw exc;
			}
			this->base.FillSessionBuffer((uint8_t *)k.N.get(), offset, k.length); // modulus
			offset += k.length;
			this->base.FillSessionBuffer((uint8_t *)k.E.get(), offset, k.length); // public exponent
			offset += k.length;
			if (k.D != nullptr) {
				this->base.FillSessionBuffer((uint8_t *)k.D.get(), offset, k.length); // private exponent (optional)
				offset += k.length;
			}
			break;
		case L1Commands::KeyOpEdit::SE3_KEY_OP_GENERATE_ASYMM:
			rsa_op = L1Commands::RSA_Options::SE3_RSA_KEYGEN;
			this->base.FillSessionBuffer((uint8_t*)&(rsa_op), offset, sizeof(rsa_op));
			offset += sizeof(rsa_op);
			this->base.FillSessionBuffer((uint8_t*)&(k.id), offset, sizeof(k.id));
			offset += sizeof(k.id);
			this->base.FillSessionBuffer((uint8_t*)&(k.length), offset, sizeof(k.length));
			offset += sizeof(k.length);
			this->base.FillSessionBuffer((uint8_t*)&(k.type), offset, sizeof(k.type));
			offset += sizeof(k.type);
			break;
		case L1Commands::KeyOpEdit::SE3_KEY_OP_DELETE:
			rsa_op = L1Commands::RSA_Options::SE3_RSA_KEYDEL;
			this->base.FillSessionBuffer((uint8_t*)&(rsa_op), offset, sizeof(rsa_op));
			offset += sizeof(rsa_op);
			this->base.FillSessionBuffer((uint8_t*)&(k.id), offset, sizeof(k.id));
			offset += sizeof(k.id);
			break;
		default:
			throw exc;
	}
	const size_t data_size = offset - L1Request::Offset::DATA;
	try {
		if(op != L1Commands::KeyOpEdit::SE3_KEY_OP_GENERATE_ASYMM){
			TXRXData(L1Commands::Codes::RSA, data_size, 0, &resp_size);
		} else {
			TXRXData(L1Commands::Codes::RSA, data_size, 0, &resp_size, SE3_TIMEOUT_RSA_KEYGEN);
		}
	} catch(L1Exception& e) {
		throw exc;
	}
	if((resp_size != 2) || strncmp((const char*)(this->base.GetSessionBuffer() + L1Response::Offset::DATA), "OK", 2) != 0) {
		throw exc;
	}
}

void L1::RSA_enc_dec(std::shared_ptr<uint8_t[]> input, size_t inputLen, RSA_IO_data& output, se3AsymmKey& key, bool public_key, bool on_the_fly) {
	L1AsymmCryptException exc;
	if (input == nullptr) {
		throw exc;
	}
	size_t offset = L1Request::Offset::DATA;
	uint8_t op = L1Commands::RSA_Options::SE3_RSA_DECRYPT;
	if (public_key) {
		op = L1Commands::RSA_Options::SE3_RSA_ENCRYPT;
	}
	this->base.FillSessionBuffer((unsigned char *)&op, offset, sizeof(op));
	offset += sizeof(op);
	uint8_t tmp = 0;
	if(on_the_fly){
		tmp = 1;
	}
	this->base.FillSessionBuffer(&tmp, offset, 1);
	offset += 1;
	if (on_the_fly) {
		this->base.FillSessionBuffer((uint8_t*)&(key.length), offset, sizeof(key.length));
		offset += sizeof(key.length);
		this->base.FillSessionBuffer(key.N.get(), offset, key.length);
		offset += key.length;
		this->base.FillSessionBuffer(key.E.get(), offset, key.length);
		offset += key.length;
		if (op == L1Commands::RSA_Options::SE3_RSA_DECRYPT) {
			this->base.FillSessionBuffer(key.D.get(), offset, key.length);
			offset += key.length;
		}
	} else {
		this->base.FillSessionBuffer((uint8_t*)&(key.id), offset, sizeof(key.id));
		offset += sizeof(key.id);
	}
	this->base.FillSessionBuffer(input.get(), offset, inputLen);
	offset += inputLen;
	const size_t data_size = offset - L1Request::Offset::DATA;
	uint16_t resp_size;
	try {
		TXRXData(L1Commands::Codes::RSA, data_size, 0, &resp_size);
	} catch (L1Exception &e) {
		throw exc;
	}
	if (resp_size == 0) {
		throw exc;
	}
	uint8_t *buff = this->base.GetSessionBuffer() + L1Response::Offset::DATA;
	output.data_size = resp_size;
	output.data = std::make_unique<uint8_t[]>(output.data_size);
	memcpy(output.data.get(), buff, resp_size);
}

void L1::RSA_sign(const std::shared_ptr<uint8_t[]> input, const size_t inputLen, std::shared_ptr<uint8_t[]> &signature, size_t &signature_size, const se3AsymmKey& key, bool on_the_fly) {
	L1SignatureException exc;
	if (input == nullptr || inputLen <= 0) {
		throw exc;
	}
	size_t offset = L1Request::Offset::DATA;
	const uint8_t op = L1Commands::RSA_Options::SE3_RSA_SIGN;
	this->base.FillSessionBuffer((uint8_t*)&op, offset, sizeof(op));
	offset += sizeof(op);
	uint8_t tmp = 0;
	if(on_the_fly){
		tmp = 1;
	}
	this->base.FillSessionBuffer(&tmp, offset, 1);
	offset += 1;
	if (on_the_fly) {
		this->base.FillSessionBuffer((uint8_t*)&(key.length), offset, sizeof(key.length));
		offset += sizeof(key.length);
		this->base.FillSessionBuffer((uint8_t*)key.N.get(), offset, key.length);
		offset += key.length;
		this->base.FillSessionBuffer((uint8_t*)key.E.get(), offset, key.length);
		offset += key.length;
		this->base.FillSessionBuffer((uint8_t*)key.D.get(), offset, key.length);
		offset += key.length;
	} else {
		this->base.FillSessionBuffer((unsigned char *)&(key.id), offset, sizeof(key.id));
		offset += sizeof(key.id);
	}
	this->base.FillSessionBuffer(input.get(), offset, inputLen);
	offset += inputLen;
	const size_t data_size = offset - L1Request::Offset::DATA;
	uint16_t resp_size;
	try {
		TXRXData(L1Commands::Codes::RSA, data_size, 0, &resp_size);
	} catch(L1Exception &e) {
		throw exc;
	}
	if(resp_size == 0) {
		throw exc;
	}
	uint8_t *buff = this->base.GetSessionBuffer() + L1Response::Offset::DATA;
	signature_size = resp_size;
	signature = std::shared_ptr<uint8_t[]>(new uint8_t[signature_size]);
	memcpy(signature.get(), buff, signature_size);
}

void L1::RSA_verify(const std::shared_ptr<uint8_t[]> input, const size_t inputLen, const std::shared_ptr<uint8_t[]> signature, const size_t signature_size, const se3AsymmKey& key, bool on_the_fly, bool &verified) {
	L1SignatureException exc;
	if (input == nullptr ||
		signature == nullptr ||
		inputLen <= 0 ||
		signature_size <= 0) {
		throw exc;
	}
	size_t offset = L1Request::Offset::DATA;
	const uint8_t op = L1Commands::RSA_Options::SE3_RSA_VERIFY;
	this->base.FillSessionBuffer((unsigned char *)&op, offset, sizeof(op));
	offset += sizeof(op);
	uint8_t tmp = 0;
	if(on_the_fly){
		tmp = 1;
	}
	this->base.FillSessionBuffer(&tmp, offset, 1);
	offset += 1;
	if (on_the_fly) {
		this->base.FillSessionBuffer((uint8_t*)&(key.length), offset, sizeof(key.length));
		offset += sizeof(key.length);
		this->base.FillSessionBuffer((uint8_t*)key.N.get(), offset, key.length);
		offset += key.length;
		this->base.FillSessionBuffer((uint8_t*)key.E.get(), offset, key.length);
		offset += key.length;
	} else {
		this->base.FillSessionBuffer((uint8_t*)&(key.id), offset, sizeof(key.id));
		offset += sizeof(key.id);
	}
	this->base.FillSessionBuffer(input.get(), offset, inputLen);
	offset += inputLen;
	this->base.FillSessionBuffer(signature.get(), offset, signature_size);
	offset += signature_size;
	const size_t data_size = offset - L1Request::Offset::DATA;
	uint16_t resp_size;
	try {
		TXRXData(L1Commands::Codes::RSA, data_size, 0, &resp_size);
	} catch(L1Exception &e) {
		throw exc;
	}
	verified = resp_size;
}

