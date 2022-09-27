#pragma once
#include "protocol.h"
#include "socket.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "FileHandler.h"
#include "crc.h"
#include <sstream>



constexpr auto CLIENT_INFO = "me.info";
constexpr auto SERVER_INFO = "server.info";
constexpr auto TRANSFER_INFO = "transfer.info";
constexpr auto MAX_RETRIES = 3;
class Socket;

struct SClient {
	ClientID id;
	std::string username;
	std::string pkey;
	bool pkeySet = false;
	std::string symmKey;
	bool symmKeySet = false;
	std::string fileToSend;
	SClient() : id(), username(""), pkey(""), symmKey(""), fileToSend("") {}
	
	friend std::ostream& operator<<(std::ostream& os, const SClient& c)
	{
		os << "ClientID: " << c.id << std::endl;
		os << "Username: " << c.username << std::endl;
		os << "PublicKey: " << c.pkey << std::endl;
		os << "SymmKey: " << c.symmKey << std::endl;
		return os;
	}
};

struct SMessage {
	std::string username;
	std::string content;
};

class Client {
private:
	SClient* _self;
	RSAPrivateWrapper* _rsaDecryptor;
	AESWrapper* _aesDecryptor;
	FileHandler* _fileHandler;

public:
	Socket* _sock;
	Client();
	~Client();

	bool loadTransferInfo();
	bool loadClientInfo();
	bool writeClientInfo();
	bool validateHeader(const ResponseHeader&, const EnumResponseCode);
	bool registerClient(const std::string&);
	bool registerPublicKey();
	bool setPublicKey();
	bool uploadFile();

};