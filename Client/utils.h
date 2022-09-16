#pragma once
#include <stdlib.h>
#include <iostream>
#include <zlib.h>
#define LOG_ERROR(x) (std::cerr <<"[+] ERROR:" << x << std::endl)
#define LOG(x) (std::cout << "[+] ERROR: "<< x << std::endl)

uint32_t doCrc(uint8_t* bytes,unsigned int bytesLength) {
	uint32_t crc = crc32(0L, Z_NULL, 0);
    for (int i = 0; i < bytesLength; ++i)
    {
        crc = crc32(crc, bytes + i, 1);
    }
    LOG(crc);
    return crc;
}
