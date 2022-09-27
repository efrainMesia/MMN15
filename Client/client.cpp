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
		LOG_ERROR("Got error from opcode");
	}
	if (header.opcode != expected) {
		LOG_ERROR("Unexpected opcode");
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
		LOG_ERROR("Invalid username length");
		return false;
	}

	//check if its only alphanumeric
	for (auto ch : username) {
		if (!std::isalnum(ch)) {
			LOG_ERROR("Invalid username, Username must contains letters and numbers only");
		}
	}

	// Create request data
	strcpy_s(requestReg.payload.name, CLIENT_NAME_SIZE, username.c_str());
	requestReg.header.payloadSize = username.length();

	//send the data and receive response
 	if (!_sock->sendReceive(reinterpret_cast<char*>(&requestReg), sizeof(requestReg),
		reinterpret_cast<char*>(&responseReg), sizeof(responseReg))) {
		LOG_ERROR("failed communicating with server");
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
		LOG_ERROR("failed communicating with server");
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
		LOG_ERROR("Invalid public key length!");
		return false;
	}
	this->_self.pkey = pubkey;
	this->_self.pkeySet = true;

	return true;
}

bool Client::uploadFile() {
	RequestFileUpload fileUpload(_self.id);
	ResponseFileUpload ResFileUpload;
	RequestCRC* crcStatus = nullptr;
	CRC* calcCrc = new CRC();
	std::string fileToTransfer;
	char* buffer = new char[FILE_METADATA];
	std::string encryptedData;
	size_t sentDataPacket = INIT_VAL;
	uint32_t crc = INIT_VAL;

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
	crc = calcCrc->calcCrc(fileToTransfer);
	// Open path and get size of file
	fileUpload.header.payloadSize = _fileHandler->size(fileToTransfer);
	// Getting File Metadata 
	std::string base_filename = fileToTransfer.substr(fileToTransfer.find_last_of("/\\") + 1);
	_aesDecryptor->encryptFile(base_filename);

	// Getting size of encrypted file
	std::string base_filename_encrypted = base_filename + ENCRYPTED_FILE_SUFFIX;
	fileUpload.payload.encryptedFileSize = _fileHandler->size(base_filename_encrypted);

	strcpy_s(fileUpload.payload.filename, FILE_METADATA, base_filename.c_str()); //copy Filename
	
	
	uint8_t retries = INIT_VAL;
	_fileHandler->open(base_filename_encrypted);
	//read by chunks
	while (retries < MAX_RETRIES) {
		fileUpload.header.payloadSize = _fileHandler->readByChunks(fileUpload.payload.encrypteDataPacket, FILE_METADATA);

		if (fileUpload.header.payloadSize == 0) {
			_sock->recv(reinterpret_cast<char*>(&ResFileUpload), sizeof(ResFileUpload));
			if (ResFileUpload.payload.crc != crc) {
				RequestCRC* crcStatus = new RequestCRC(_self.id, CRC_AGAIN);
				_sock->send(reinterpret_cast<char*>(crcStatus), sizeof(RequestCRC));
				retries++;
				_fileHandler->open(base_filename_encrypted);
			}
			else {
				RequestCRC* crcStatus = new RequestCRC(_self.id, CRC_OK);
				_sock->send(reinterpret_cast<char*>(crcStatus), sizeof(RequestCRC));
				break;
			}
		}
		else {
			_sock->send(reinterpret_cast<char*>(&fileUpload), sizeof(fileUpload));
		}
	}
	if (retries == MAX_RETRIES) {
		RequestCRC* crcStatus = new RequestCRC(_self.id, CRC_FAILED);
		_sock->send(reinterpret_cast<char*>(crcStatus), sizeof(RequestCRC));
		LOG_ERROR("Max retries reached, exiting...");
		return false;
	}
	else
		LOG("File has been sent successfully");

	return true;
}
