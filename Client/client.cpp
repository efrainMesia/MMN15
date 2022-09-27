#include "client.h"

Client::Client()
{
	_self = new SClient();
	_sock = new Socket();
	_rsaDecryptor = new RSAPrivateWrapper();
	_aesDecryptor = nullptr;
	_fileHandler = new FileHandler();
}

Client::~Client()
{
	delete _sock;
}

bool Client::loadTransferInfo() {
	std::string buf = "";
	char delimm = ':';
	std::string serverIP = "";
	std::string port = "";

	//open file - transfer.info
	if (!_fileHandler->open(TRANSFER_INFO)) {
		LOG_ERROR("Unable to open file transfer.info");
	}
	LOG("Parsing transfer.info");

	//readline - ip address and port
	if (!_fileHandler->readLine(buf,true)) {
		LOG_ERROR("Failed reading from file transfer.info");
		return false;
	}
	if (countDelim(buf,delimm) == 1) {
		int pos = buf.find(":");
		serverIP = buf.substr(0, pos);
		port = buf.substr(pos+1);
	}
	else {
		LOG_ERROR("Wrong syntax of server ip and port in transfer.info");
		return false;
	}
	
	//readline - client name
	if (!_fileHandler->readLine(buf,true)) {
		LOG_ERROR("Failed reading second line in me.info");
		return false;
	}
	if (buf.length() > CLIENT_NAME_SIZE || !isAlNum(buf)) {
		LOG_ERROR("Username type is not allow, make sure less than 128 and alphanumeric");
		return false;
	}
	_self->username = buf;

	//read line - file name
	if (!_fileHandler->readLine(buf,true)) {
		LOG_ERROR("Failed reading third line in me.info");
		return false;
	}
	_self->fileToSend = buf;
	return true;
}

bool Client::loadClientInfo()
{
	std::string buf = "";
	//Open me.info
	if (!_fileHandler->open(CLIENT_INFO)) {
		LOG_ERROR("Unable to open file me.info");
		return false;
	}

	//read line - username
	if (!_fileHandler->readLine(buf,false)) {
		LOG_ERROR("Failed reading from file me.info");
		return false;
	}
	if (buf.length() > CLIENT_NAME_SIZE || !isAlNum(buf)) {
		LOG_ERROR("Username length over 128");
		return false;
	}
	_self->username = buf;


	// read line - client ID - base in 64
	if (!_fileHandler->readLine(buf,false)) {
		LOG_ERROR("Failed reading second line in me.info");
		return false;
	}
	buf = decodeBase64(buf);
	if (buf.length() > CLIENT_ID_SIZE) {
		LOG_ERROR("ID size its too long");
		return false;
	}
	LOG("UUID: " + buf);
	strcpy_s(_self->id.uuid, CLIENT_ID_SIZE, buf.c_str());

	// read line - Public Key
	if (!_fileHandler->readLine(buf,false)) {
		LOG_ERROR("Failed reading third line in me.info");
		return false;
	}
	_self->pkey = buf;
	_self->pkeySet = true;

	return true;
}


bool Client::writeClientInfo() {
	std::string buf = "";
	//open file - transfer.info for writing
	if (!_fileHandler->open(CLIENT_INFO, true)) {
		LOG_ERROR("Unable to open file me.info");
		return false;
	}

	//writing username 
	if (!_fileHandler->writeLine(_self->username)) {
		LOG_ERROR("Failed writing to file me.info");
		return false;
	}

	//writing UUID
	buf = encodeBase64(_self->id.uuid);
	LOG("UUID in Base64" + buf);
	if (!_fileHandler->writeLine(buf)) {
		LOG_ERROR("Failed writing UUID to file me.info");
		return false;
	}

	//writing publicKey
	buf = encodeBase64(_self->pkey);
	LOG("Private Key in Base64" + buf);
	if (!_fileHandler->writeLine(buf)) {
		LOG_ERROR("Failed writing private Key to file me.info");
		return false;
	}
	return true;
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
	_self->id = responseReg.payload;
	_self->username = username;
	
	std::cout << _self << std::endl;
	return true;
}




bool Client::registerPublicKey()
{
	RequestPublicKey requestPKey(_self->id);
	ResponseSymmKey responseRegPKey;

	if (!_self->pkeySet) {
		if (!setPublicKey()) {
			std::cerr << "Failed to set public key" << std::endl;
			return false;
		}
	}

	
	//copy the pkey to buffer before sending it
	int i;
	for (i = 0; i < sizeof(requestPKey.payload.publicKey); i++) {
		requestPKey.payload.publicKey[i] = _self->pkey[i];
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
	
	_self->symmKey = _rsaDecryptor->decrypt(responseRegPKey.symmKey.symmKey, ENCRYPTED_DATA);
	_aesDecryptor = new AESWrapper(_self->symmKey.c_str(), SYMMETRIC_KEY_SIZE);
	_self->symmKeySet = true;
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
	_self->pkey = pubkey;
	_self->pkeySet = true;

	return true;
}

bool Client::uploadFile() {
	RequestFileUpload fileUpload(_self->id);
	ResponseFileUpload ResFileUpload;
	RequestCRC* crcStatus = nullptr;
	CRC* calcCrc = new CRC();
	char* buffer = new char[FILE_METADATA];
	std::string encryptedData = "";
	size_t sentDataPacket = INIT_VAL;
	uint32_t crc = INIT_VAL;
	uint8_t retries = INIT_VAL;

	crc = calcCrc->calcCrc(_self->fileToSend);
	fileUpload.header.payloadSize = _fileHandler->size(_self->fileToSend);
	_aesDecryptor->encryptFile(_self->fileToSend);

	// Getting size of encrypted file
	std::string base_filename_encrypted = _self->fileToSend + ENCRYPTED_FILE_SUFFIX;
	fileUpload.payload.encryptedFileSize = _fileHandler->size(base_filename_encrypted);

	strcpy_s(fileUpload.payload.filename, FILE_METADATA, _self->fileToSend.c_str()); //copy Filename
	
	
	_fileHandler->open(base_filename_encrypted);

	while (retries < MAX_RETRIES) {
		fileUpload.header.payloadSize = _fileHandler->readByChunks(fileUpload.payload.encrypteDataPacket, FILE_METADATA);

		if (fileUpload.header.payloadSize == 0) {
			_sock->recv(reinterpret_cast<char*>(&ResFileUpload), sizeof(ResFileUpload));
			if (ResFileUpload.payload.crc != crc) {
				RequestCRC* crcStatus = new RequestCRC(_self->id, CRC_AGAIN);
				_sock->send(reinterpret_cast<char*>(crcStatus), sizeof(RequestCRC));
				retries++;
				_fileHandler->open(base_filename_encrypted);
			}
			else {
				RequestCRC* crcStatus = new RequestCRC(_self->id, CRC_OK);
				_sock->send(reinterpret_cast<char*>(crcStatus), sizeof(RequestCRC));
				break;
			}
		}
		else {
			_sock->send(reinterpret_cast<char*>(&fileUpload), sizeof(fileUpload));
		}
	}
	if (retries == MAX_RETRIES) {
		RequestCRC* crcStatus = new RequestCRC(_self->id, CRC_FAILED);
		_sock->send(reinterpret_cast<char*>(crcStatus), sizeof(RequestCRC));
		LOG_ERROR("Max retries reached, exiting...");
		return false;
	}
	else
		LOG("File has been sent successfully");

	return true;
}
