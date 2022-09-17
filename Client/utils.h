#pragma once
#include <stdlib.h>
#include <filesystem>
#include <iostream>
#include <zlib.h>


#define LOG_ERROR(x) (std::cerr <<"[+] ERROR:" << x << std::endl)
#define LOG(x) (std::cout << "[+] INFO: "<< x << std::endl)

uint32_t doCrc(uint8_t* bytes, unsigned int bytesLength);
