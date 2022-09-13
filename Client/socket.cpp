#include "socket.h"

Socket::Socket()
{
	int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	if (result != 0) {
		printf("Error: cannot initialize WinSock.\n");
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
		std::cerr << "Cant create socket " << WSAGetLastError() << std::endl;
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
		std::cerr << "Cant connect to server " << WSAGetLastError() << std::endl;
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
 	std::cout << status;
	return status;

}

int Socket::recv(char* buf, int numberOfBytes){
	int result = ::recv(this->sock, buf, numberOfBytes, 0);
	if (result == 0) {
		std::cout << "Error trying to read but socket is closed" << std::endl;
		return 0;
	}
	else if (result < 0) {
		std::cout << "Error: cannot read from socket"<< WSAGetLastError() << std::endl;
	}
	return result;
}

bool Socket::sendReceive(char* toSend, const size_t size, char* const response, const size_t resSize) {
	if (!_connected) {
		return false;
	}
	if (!send(toSend, size)) {
		close();
		return false;
	}
	if (!recv(response, resSize)) {
		close();
		return false;
	}
	close();
	return true;

}

bool Socket::close() {
	closesocket(this->sock);
	_connected = false;
	return true;
}

