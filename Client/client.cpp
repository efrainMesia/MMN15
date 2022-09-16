#include "client.h"

Client::Client()
{
	_sock = new Socket();
	_rsaDecryptor = new RSAPrivateWrapper();
	_aesDecryptor = nullptr;
	_fileHandler = new FileHandler();
}

Client::~Client()
{
	delete _sock;
}

bool Client::validateHeader(const ResponseHeader& header, const EnumResponseCode expected)
{
	if (header.opcode == RESPONSE_ERROR) {
		std::cerr << "Got error from opcode" << std::endl;
	}
	if (header.opcode != expected) {
		std::cerr << "Unexpected opcode" << std::endl;
	}
	fsize expectedSize = INIT_VAL;
	switch (header.opcode) {
		case RESPONSE_REG: {
			expectedSize = sizeof(ResponseReg) - sizeof(ResponseHeader);
			break;
		}
		case RESPONSE_PAIRING: {
			expectedSize = sizeof(ResponseSymmKey) - sizeof(ResponseHeader);
			break;
		}
		// TODO: add CRC and uploadFile
		
	}
	if (header.payloadSize != expectedSize) {
		std::cerr << "Unexpected payload size " << header.payloadSize << ".Expected was " << expectedSize << std::endl;
		return false;
	}
	return true;
}

bool Client::registerClient(const std::string& username)
{
	RequestReg requestReg;
	ResponseReg responseReg;

	// Check length of username
	if (username.length() >= CLIENT_NAME_SIZE) {
		std::cerr << "Invalid username length" << std::endl;
		return false;
	}

	//check if its only alphanumeric
	for (auto ch : username) {
		if (!std::isalnum(ch)) {
			std::cerr << "Invalid username, Username must contains letters and numbers only" << std::endl;
		}
	}

	// Create request data
	strcpy_s(reinterpret_cast<char*>(requestReg.payload.name), CLIENT_NAME_SIZE, username.c_str());
	requestReg.header.payloadSize = username.length();

	//send the data and receive response
 	if (!_sock->sendReceive(reinterpret_cast<char*>(&requestReg), sizeof(requestReg),
		reinterpret_cast<char*>(&responseReg), sizeof(responseReg))) {
		std::cerr << "failed communicating with server";
		return false;
	}
	
	//checking the header
	if (!validateHeader(responseReg.header, RESPONSE_REG))
		return false;
	
	//setting the Client object
	_self.id = responseReg.payload;
	_self.username = username;
	
	std::cout << _self << std::endl;
	return true;
}




bool Client::registerPublicKey()
{
	RequestPublicKey requestPKey(_self.id);
	ResponseSymmKey responseRegPKey;

	if (!_self.pkeySet) {
		if (!setPublicKey()) {
			std::cerr << "Failed to set public key" << std::endl;
			return false;
		}
	}

	
	//copy the pkey to buffer before sending it
	int i;
	for (i = 0; i < sizeof(requestPKey.payload.publicKey); i++) {
		requestPKey.payload.publicKey[i] = this->_self.pkey[i];
	}
	requestPKey.header.payloadSize = PUBLIC_KEY_SIZE;

	if (!_sock->sendReceive(reinterpret_cast<char*>(&requestPKey), sizeof(requestPKey),
		reinterpret_cast<char*>(&responseRegPKey), sizeof(responseRegPKey))) {
		std::cerr << "failed communicating with server";
		return false;
	}

	//checking the header
	if (!validateHeader(responseRegPKey.header, RESPONSE_PAIRING))
		return false;
	
	_self.symmKey = _rsaDecryptor->decrypt(responseRegPKey.symmKey.symmKey, ENCRYPTED_DATA);
	_aesDecryptor = new AESWrapper(_self.symmKey.c_str(), SYMMETRIC_KEY_SIZE);
	_self.symmKeySet = true;
	return true;
}

bool Client::setPublicKey()
{
	// 1. get the public key
	std::string pubkey = _rsaDecryptor->getPublicKey();
	
	if (pubkey.size() != PUBLIC_KEY_SIZE)
	{
		std::cerr << "Invalid public key length!" << std::endl;
		return false;
	}
	this->_self.pkey = pubkey;
	this->_self.pkeySet = true;

	return true;
}

bool Client::uploadFile() {
	std::string fileToTransfer;
	size_t fileSize;
	size_t sentDataPacket = INIT_VAL;
	// Get the file from path transfer.info
	if (!_fileHandler->open(TRANSFER_INFO)) {
		std::cerr << "[+] ERROR: Couldnt open file: " << TRANSFER_INFO << std::endl;
		return false;
	}

	// Open file and get file path
	if (!_fileHandler->readLine(fileToTransfer)) {
		std::cerr << "[+] ERROR: couldnt read line from file " << TRANSFER_INFO << std::endl;
		return false;
	}
	
	// Open path and get size of file
	if (!_fileHandler->open(fileToTransfer)) {
		std::cerr << "Couldnt open file: " << fileToTransfer << std::endl;
		return false;
	}
	fileSize = _fileHandler->size();

	//read by chunks(use vector)
	while (sentDataPacket <= fileSize) {

	}
	// Encrypt data with AES key
	// Send Data

	// check CRC and continue to next chunk

	return true;
}