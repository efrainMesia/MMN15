#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include "client.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")


#define DEFAULT_BUFLEN 1024
#define DEFAULT_PORT 7777

int main() {
	std::string ipAddress = "127.0.0.1";
	Client* newClient = new Client();

	newClient->_sock->connect(ipAddress, DEFAULT_PORT);
	newClient->registerClient("Testingthismdf");
	newClient->_sock->connect(ipAddress, DEFAULT_PORT);
	newClient->registerPublicKey();
	return 0;
}