#pragma once
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <iostream>
// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
class Socket {
private:
	WSADATA wsa_data;
	SOCKET sock;
	bool _connected;

public:
	Socket();
	~Socket();
	bool closeSocket();
	bool connect(std::string,unsigned short int);
	int send(char*, int);
	int recv(char*, int);
	bool sendReceive(char* , const size_t, char* const, const size_t);
	bool close();
};