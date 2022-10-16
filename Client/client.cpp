#include "client.h"

Client::Client()
{
	_self = new SClient();
	_sock = new Socket();
	_rsaDecryptor = nullptr;
	_aesDecryptor = nullptr;
	_fileHandler = new FileHandler();
	_serverIP = "";
	_port = INIT_VAL;
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

	if (!_fileHandler->is_file_exist(TRANSFER_INFO)) {
		LOG_ERROR("File transfer.info does not exist.");
		return false;
	}
	//open file - transfer.info
	if (!_fileHandler->open(TRANSFER_INFO)) {
		LOG_ERROR("Unable to open file transfer.info.");
		return false;
	}
	LOG("Parsing transfer.info");

	//readline - ip address and port
	if (!_fileHandler->readLine(buf,true)) {
		LOG_ERROR("Failed reading from file transfer.info.");
		return false;
	}
	if (countDelim(buf,delimm) == 1) {
		int pos = buf.find(":");
		_serverIP = buf.substr(0, pos);
		port = buf.substr(pos+1);
		if (!isNum(port)) {
			LOG_ERROR("Server Port is not numeric.");
			return false;
		}
		_port = std::stoi(port);

	}
	else {
		LOG_ERROR("Wrong syntax of server ip and port in transfer.info.");
		return false;
	}
	buf.clear();

	//readline - client name
	if (!_fileHandler->readLine(buf,true)) {
		LOG_ERROR("Failed reading second line in me.info.");
		return false;
	}
	if (!_fileHandler->is_file_exist(CLIENT_INFO)) {
		if (buf.length() > CLIENT_NAME_SIZE || !isAlNum(buf)) {
			LOG_ERROR("Username type is not allow, make sure less than 128 and alphanumeric.");
			return false;
		}
		_self->username = buf;
	}
	buf.clear();

	//read line - file name
	if (!_fileHandler->readLine(buf,true)) {
		LOG_ERROR("Failed reading third line in me.info.");
		return false;
	}
	if (!_fileHandler->is_file_exist(buf)) {
		LOG_ERROR("File " + buf + " does not exist.");
	}
	_self->fileToSend = buf;
	_fileHandler->close();
	buf.clear();

	return true;
}

bool Client::loadClientInfo()
{
	std::string buf = "";
	std::string decoded = "";

	if (!_fileHandler->is_file_exist(CLIENT_INFO)) {
		LOG("File me.info doesnt exist. loading username from transfer.info.");
		return false;
	}
	//Open me.info
	if (!_fileHandler->open(CLIENT_INFO)) {
		LOG_ERROR("Unable to open file me.info.");
		return false;
	}

	//read line - username
	if (!_fileHandler->readLine(buf,false)) {
		LOG_ERROR("Failed reading from file me.info.");
		return false;
	}
	if (buf.length() > CLIENT_NAME_SIZE || !isAlNum(buf)) {
		LOG_ERROR("Username length over 128.");
		return false;
	}
	_self->username = buf;
	buf.clear();
	// read line - client ID - base in 64
	if (!_fileHandler->readLine(buf,false)) {
		LOG_ERROR("Failed reading second line in me.info.");
		return false;
	}
	LOG("UUID: " + buf);
	buf = ::unhexify(buf);
	if (buf.length() > CLIENT_ID_SIZE) {
		LOG_ERROR("ID size its too long.");
		return false;
	}
	memcpy_s(_self->id.uuid, CLIENT_ID_SIZE, buf.c_str(), CLIENT_ID_SIZE);
	buf.clear();

	// read line - Public Key
	if (!_fileHandler->readLine(buf,false)) {
		LOG_ERROR("Failed reading third line in me.info.");
		return false;
	}
	buf = Base64Wrapper::decode(buf);
	_rsaDecryptor = new RSAPrivateWrapper(buf);
	_self->pkey = _rsaDecryptor->getPublicKey();
	_self->pkeySet = true;

	//closing file
	_fileHandler->close();
	return true;
}

bool Client::writeClientInfo() {
	std::string buf = "";

	//open file - transfer.info for writing
	if (!_fileHandler->open(CLIENT_INFO, true)) {
		LOG_ERROR("Unable to open file me.info.");
		return false;
	}

	//writing username 
	if (!_fileHandler->writeLine(_self->username)) {
		LOG_ERROR("Failed writing to file me.info");
		return false;
	}


	buf = ::hexify(_self->id.uuid, CLIENT_ID_SIZE);
	LOG("UUID in Hex: " + buf);
	if (!_fileHandler->writeLine(buf)) {
		LOG_ERROR("Failed writing UUID to file me.info");
		return false;
	}

	//writing publicKey
	std::string test = _rsaDecryptor->getPrivateKey();
	buf = Base64Wrapper::encode(_rsaDecryptor->getPrivateKey());
	LOG("Private Key in Base64: " + buf);
	if (!_fileHandler->writeLine(buf)) {
		LOG_ERROR("Failed writing private Key to file me.info");
		return false;
	}

	_fileHandler->close(true);
	LOG("Writing me.info finished succesfully.");
	return true;
}

bool Client::validateHeader(const ResponseHeader& header, const EnumResponseCode expected)
{
	if (header.opcode == RESPONSE_ERROR) {
		LOG_ERROR("Got error from opcode");
		return false;
	}
	if (header.opcode != expected) {
		LOG_ERROR("Unexpected opcode" + header.opcode);
		return false;
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
		LOG_ERROR("Unexpected payload size " + header.payloadSize);
		LOG_ERROR("Expected was " + expectedSize);
		return false;
	}
	return true;
}

bool Client::registerClient()
{
	RequestReg* requestReg = new RequestReg();
	ResponseReg* responseReg = new ResponseReg();
	if (!_sock->connect(_serverIP, _port)) {
		LOG_ERROR("Failed connecting to server");
		return false;
	}

	// Create request data
	strcpy_s(requestReg->payload.name, CLIENT_NAME_SIZE, _self->username.c_str());
	requestReg->header.payloadSize = _self->username.length();
	LOG("Sending name: " + _self->username);
	//send the data and receive response
 	if (!_sock->sendReceive(reinterpret_cast<char*>(requestReg), sizeof(RequestReg),
		reinterpret_cast<char*>(responseReg), sizeof(ResponseReg))) {
		LOG_ERROR("failed communicating with server");
		return false;
	}
	
	//checking the header
	if (!validateHeader(responseReg->header, RESPONSE_REG))
		return false;
	
	//setting the Client object
	_self->id = responseReg->payload;
	
	LOG(*_self);
	LOG("Register User has finished successfully");
	return true;
}

bool Client::registerPublicKey()
{
	RequestPublicKey* requestPKey = new RequestPublicKey(_self->id);
	ResponseSymmKey* responseRegPKey = new ResponseSymmKey();


	if (!_self->pkeySet) {
		LOG("Private Key has not been setted, creating a new one...");
		if (!setPublicKey()) {
			LOG_ERROR("Failed to set public key");
			return false;
		}
		LOG("Private key & Public Key have been created.");
	}

	if (!_sock->connect(_serverIP, _port)) {
		LOG_ERROR("Failed connecting to server");
		return false;
	}
	
	memcpy_s(requestPKey->payload.publicKey, sizeof(PublicKey), _self->pkey.c_str(), _self->pkey.length());
	requestPKey->header.payloadSize = PUBLIC_KEY_SIZE;

	if (!_sock->sendReceive(reinterpret_cast<char*>(requestPKey), sizeof(RequestPublicKey),
		reinterpret_cast<char*>(responseRegPKey), sizeof(ResponseSymmKey))) {
		LOG_ERROR("failed communicating with server");
		return false;
	}

	//checking the header
	if (!validateHeader(responseRegPKey->header, RESPONSE_PAIRING))
		return false;

	_self->symmKey = _rsaDecryptor->decrypt(responseRegPKey->symmKey.symmKey, ENCRYPTED_DATA);
	_aesDecryptor = new AESWrapper(_self->symmKey.c_str(), SYMMETRIC_KEY_SIZE);
	_self->symmKeySet = true;
	LOG("AES Key has been received from server.");
	return true;
}

bool Client::setPublicKey()
{
	if (!_self->pkeySet) {
		_rsaDecryptor = new RSAPrivateWrapper();
	}
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
	RequestFileUpload* fileUpload = new RequestFileUpload(_self->id);
	ResponseFileUpload* ResFileUpload = new ResponseFileUpload();
	CRC* calcCrc = new CRC();
	uint32_t crc = INIT_VAL;
	uint8_t retries = INIT_VAL;

	LOG("Upload file procudure has started");
	LOG("File to send: " + _self->fileToSend);
	crc = calcCrc->calcCrc(_self->fileToSend);

	fileUpload->header.payloadSize = _fileHandler->size(_self->fileToSend);
	_aesDecryptor->encryptFile(_self->fileToSend);
	LOG("File has been encrypted.");

	// Getting size of encrypted file
	std::string base_filename_encrypted = _self->fileToSend + ENCRYPTED_FILE_SUFFIX;
	fileUpload->payload.encryptedFileSize = _fileHandler->size(base_filename_encrypted);
	strcpy_s(fileUpload->payload.filename, FILE_METADATA, _self->fileToSend.c_str()); //copy Filename
	_fileHandler->open(base_filename_encrypted);

	if (!_sock->connect(_serverIP, _port)) {
		LOG_ERROR("Failed connecting to server");
		return false;
	}
	LOG("Start sending file...");
	while (retries < MAX_RETRIES) {
		fileUpload->header.payloadSize = _fileHandler->readByChunks(fileUpload->payload.encrypteDataPacket, 742);
		if (fileUpload->header.payloadSize == 0) {
			_sock->recv(reinterpret_cast<char*>(ResFileUpload), sizeof(ResponseFileUpload));
			if (ResFileUpload->payload.crc != crc) {
				RequestCRC* crcStatus = new RequestCRC(_self->id, CRC_AGAIN);
				_sock->send(reinterpret_cast<char*>(crcStatus), sizeof(RequestCRC));
				retries++;
				LOG("Num of retries: " + retries);
				_fileHandler->open(base_filename_encrypted);
				LOG_ERROR("CRC compare failed, sending file again...");
			}
			else {
				RequestCRC* crcStatus = new RequestCRC(_self->id, CRC_OK);
				_sock->send(reinterpret_cast<char*>(crcStatus), sizeof(RequestCRC));
				LOG("CRC compare is okay.");
				break;
			}
		}
		else {
			_sock->send(reinterpret_cast<char*>(fileUpload), sizeof(RequestFileUpload));
			memset(&fileUpload->payload.encrypteDataPacket, '\0', 742);
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

void Client::main() {
	if (!loadClientInfo())
		LOG_ERROR("Loading client info failed...");
	if (!loadTransferInfo()) {
		LOG_ERROR("Loading transfer.info failed, exiting...");
		exit(1);
	}
	if (isEmpty(_self->id.uuid,CLIENT_ID_SIZE)) {
		LOG("Registering user " + _self->username);
		if (!registerClient())
			LOG_ERROR("Register user failed, exiting...");
	}
	if (!registerPublicKey())
		LOG_ERROR("Registering public key has failed, exiting...");
	if (!uploadFile())
		LOG_ERROR("Upload file has failed, exiting...");
	if (!writeClientInfo())
		LOG_ERROR("Writing me.info failed...");
}
