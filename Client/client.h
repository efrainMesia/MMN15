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
		os << "Client details: " << std::endl;
		os << "\t  --ClientID: " << ::hexify(c.id.uuid,CLIENT_ID_SIZE) << std::endl;
		os << "\t  --Username: " << c.username << std::endl;
		os << "\t  --PublicKey: " << c.pkey << std::endl;
		os << "\t  --SymmKey: " << c.symmKey << std::endl;
		os << "\t  --FileToSend: " << c.fileToSend;
		return os;
	}
};


class Client {
private:
	SClient* _self;
	RSAPrivateWrapper* _rsaDecryptor;
	AESWrapper* _aesDecryptor;
	FileHandler* _fileHandler;
	std::string _serverIP;
	unsigned short int _port;

public:
	Socket* _sock;
	Client();
	~Client();

	bool loadTransferInfo();
	bool loadClientInfo();
	bool writeClientInfo();
	bool validateHeader(const ResponseHeader&, const EnumResponseCode);
	bool registerClient();
	bool registerPublicKey();
	bool setPublicKey();
	bool uploadFile();
	void main();

};