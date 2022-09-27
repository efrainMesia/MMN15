#pragma once
#include <cstdint>
#include <ostream>
#include <vector>
#include "utils.h"
enum { INIT_VAL = 0};

//Common types
typedef uint16_t opcode_t;
typedef uint32_t fsize;
typedef uint8_t version_t;

// Constants, all sizes are in bytes
constexpr size_t DEFAULT_BUFLEN = 1024;
constexpr size_t CLIENT_ID_SIZE = 16;
constexpr size_t CLIENT_NAME_SIZE = 128; 
constexpr size_t PUBLIC_KEY_SIZE = 160;
constexpr size_t SYMMETRIC_KEY_SIZE = 16;
constexpr size_t ENCRYPTED_DATA = 128;
constexpr size_t CRC_SIZE = 32;
constexpr size_t DATA_PACKET = 64;
constexpr size_t FILE_METADATA = 256;


enum EnumRequestCode {
    REQUEST_REG = 1100,      //uuid ignored
    REQUEST_PAIRING = 1101,  //update keys
    REQUEST_UPLOAD = 1103,
    CRC_OK = 1104,
    CRC_AGAIN = 1105,
    CRC_FAILED = 1106
};

enum EnumResponseCode {
    RESPONSE_REG = 2100,
    RESPONSE_PAIRING = 2102,
    RESPONSE_UPLOAD_CRC_OK = 2103,
    RESPONSE_OK = 2104,
    RESPONSE_ERROR = 2005
};

#pragma pack(push, 1)
struct ClientID {
    char uuid[CLIENT_ID_SIZE];
    ClientID() : uuid{ 0 } {}
    friend std::ostream& operator<<(std::ostream& os, const ClientID& c)
    {
        os << c.uuid << std::endl;
        return os;
    }
};
struct ClientName {
    char name[CLIENT_NAME_SIZE];
    ClientName() : name{ '\0' } {}
    friend std::ostream& operator<<(std::ostream& os, const ClientName& c)
    {
        os << c.name << std::endl;
        return os;
    }
};

struct PublicKey {
    char publicKey[PUBLIC_KEY_SIZE];
    PublicKey(): publicKey{ 0 }{}
    friend std::ostream& operator<<(std::ostream& os, const PublicKey& c)
    {
        os << c.publicKey << std::endl;
        return os;
    }
};

struct SymmKey {
    char symmKey[SYMMETRIC_KEY_SIZE];
    SymmKey() : symmKey{INIT_VAL}{}
    friend std::ostream& operator<<(std::ostream& os, const SymmKey& c)
    {
        os << c.symmKey << std::endl;
        return os;
    }
};

struct EncryptedSymm {
    char symmKey[ENCRYPTED_DATA];
    EncryptedSymm() : symmKey{ INIT_VAL } {}
    friend std::ostream& operator<<(std::ostream& os, const EncryptedSymm& c)
    {
        os << c.symmKey << std::endl;
        return os;
    }
};

struct CRCKey {
    uint32_t crc;
    CRCKey() : crc{ INIT_VAL } {}
    friend std::ostream& operator<<(std::ostream& os, const CRCKey& c)
    {
        os << c.crc << std::endl;
        return os;
    }
};

struct FileDataPacket {
    uint32_t encryptedFileSize;
    char filename[FILE_METADATA];
    char encrypteDataPacket[FILE_METADATA];
    FileDataPacket() : encryptedFileSize(INIT_VAL), filename{ INIT_VAL }, encrypteDataPacket{ INIT_VAL } {}
};



struct RequestHeader {
    ClientID clientId;
    const version_t version;
    const opcode_t opcode;
    fsize payloadSize;
    RequestHeader(const ClientID& id) : version(INIT_VAL), clientId(id), opcode(INIT_VAL), payloadSize(INIT_VAL) {}
    RequestHeader(const opcode_t reqCode) :version(INIT_VAL), opcode(reqCode), payloadSize(INIT_VAL) {}
    RequestHeader(const ClientID& id, const opcode_t reqCode) : version(INIT_VAL),clientId(id), opcode(reqCode), payloadSize(INIT_VAL) {}
};

struct ResponseHeader {
    version_t version;
    const opcode_t opcode;
    fsize payloadSize;
    ResponseHeader() : version(INIT_VAL), opcode(INIT_VAL), payloadSize(INIT_VAL){}
};

struct RequestReg
{
    RequestHeader header;
    ClientName payload;
    RequestReg() : header(REQUEST_REG) {}
};

struct ResponseReg
{
    ResponseHeader header;
    ClientID payload;
};

struct RequestPublicKey {
    RequestHeader header;
    PublicKey payload;
    RequestPublicKey(const ClientID& id) : header(id, REQUEST_PAIRING){}
};

//response of Request Public key, server sends AES key
struct ResponseSymmKey
{
    ResponseHeader header;
    EncryptedSymm symmKey;
};

struct RequestFileUpload {
    RequestHeader header;
    FileDataPacket payload;
    RequestFileUpload(const ClientID& id) : header(id, REQUEST_UPLOAD), payload(){}
};

struct ResponseFileUpload {
    ResponseHeader header;
    CRCKey payload;
};

struct RequestCRC {
    RequestHeader header;
    RequestCRC(const ClientID& id, const opcode_t opcode) :header(id,opcode) {}
};

#pragma pack(pop)
