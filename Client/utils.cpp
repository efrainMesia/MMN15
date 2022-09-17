#include "utils.h"

uint32_t doCrc(uint8_t* bytes, unsigned int bytesLength)
{
    uint32_t crc = crc32(0L, Z_NULL, 0);
    for (unsigned int i = 0; i < bytesLength; ++i)
    {
        crc = crc32(crc, bytes + i, 1);
    }
    LOG(crc);
    return crc;
}
