#include "socket.h"

Socket::Socket()
{
	_connected = false;
	sock = INVALID_SOCKET;
	int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	if (result != 0) {
		LOG_ERROR("Error: cannot initialize WinSock");
		WSACleanup();
	}

}

Socket::~Socket() {
	close();
}

bool Socket::connect(std::string endpoint, unsigned short int port) {
	//Initialize socket
	this->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (this->sock == INVALID_SOCKET) {
		LOG_ERROR("Cant create socket " + WSAGetLastError());
		WSACleanup();
		return false;
	}
	// Fill in a hint structure
	sockaddr_in hint;
	hint.sin_family = AF_INET;
	hint.sin_port = htons(port);
	inet_pton(AF_INET, endpoint.c_str(), &hint.sin_addr);

	//Connect to server
	int connResult = ::connect(this->sock, (sockaddr*)&hint, sizeof(hint));
	if (connResult == SOCKET_ERROR) {
		LOG_ERROR("Cant connect to server " + WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return false;
	}
	_connected = true;
	return _connected;
}

int Socket::send(char* data, int numberOfBytes) {
	int status = ::send(this->sock, data, numberOfBytes, 0);
	if (status == SOCKET_ERROR) {
		close();
		WSACleanup();
		return -1;
	}
 	//std::cout << status;
	return status;

}

int Socket::recv(char* buf, int numberOfBytes){
	int result = ::recv(this->sock, buf, numberOfBytes, 0);
	if (result == 0) {
		LOG_ERROR("Error trying to read but socket is closed");
		return 0;
	}
	else if (result < 0) {
		LOG_ERROR("Error: cannot read from socket" + WSAGetLastError());
	}
	return result;
}

bool Socket::sendReceive(char* toSend, const size_t size, char* const response, const size_t resSize) {
	if (!_connected) {
		return false;
	}
	if (!send(toSend, size)) {
		this->close();
		return false;
	}
	if (!recv(response, resSize)) {
		this->close();
		return false;
	}
	this->close();
	return true;

}

bool Socket::close() {
	closesocket(this->sock);
	_connected = false;
	return true;
}

