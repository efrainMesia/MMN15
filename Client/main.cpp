#pragma once
#define WIN32_LEAN_AND_MEAN

#include "client.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")


#define DEFAULT_BUFLEN 1024
#define DEFAULT_PORT 7777

int main() {
	Client* newClient = new Client();
	newClient->main();
	return 0;
}