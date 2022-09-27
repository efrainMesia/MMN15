#pragma once
#include <cstdint>
#include "FileHandler.h"
class CRC {
private:
	uint32_t crc;
	uint32_t nchar;
	FileHandler* fh;
public:
	CRC();
	~CRC();
	void update(char*,uint32_t);
	uint32_t digest();
	uint32_t calcCrc(std::string);
};