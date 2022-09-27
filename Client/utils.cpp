#include "utils.h"

uint8_t countDelim(std::string str, char delim) {
    uint8_t count = 0;
    for (char& c : str) {
        if (c == delim)
            count++;
    }
    return count;
}


std::string encodeBase64(const std::string& str)
{
    std::string encoded;
    CryptoPP::StringSource ss(str, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded)
        ) // Base64Encoder
    ); // StringSource

    return encoded;
}

std::string decodeBase64(const std::string& str)
{
    std::string decoded;
    CryptoPP::StringSource ss(str, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded)
        ) // Base64Decoder
    ); // StringSource

    return decoded;
}