#pragma once
#include <cstdint>
#include <iostream>
#include <ostream>

enum { INIT_VAL = 0};

//Common types
typedef uint16_t opcode_t;
typedef uint16_t fsize;

// Constants, all sizes are in bytes
constexpr size_t CLIENT_ID_SIZE = 16;
constexpr size_t CLIENT_NAME_SIZE = 128; 
constexpr size_t PUBLIC_KEY_SIZE = 160;
constexpr size_t SYMMETRIC_KEY_SIZE = 16;
constexpr size_t ENCRYPTED_DATA = 128;


enum EnumRequestCode {
    REQUEST_REG = 1000,      //uuid ignored
    REQUEST_PAIRING = 1001,  //update keys
    REQUEST_UPLOAD = 1002,
    REQUEST_CRC = 1003,
};

enum EnumResponseCode {
    RESPONSE_REG = 2000,
    RESPONSE_PAIRING = 2001,
    RESPONSE_UPLOAD = 2002,
    RESPONSE_CRC = 2003,
    RESPONSE_ERROR = 2004
};


enum EnumMessageType {
    MSG_SYMM_KEY_REQ = 1,
    MSG_SYMM_KEY_SEND = 2,
    MSG_FILE = 3,
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

struct RequestHeader {
    ClientID clientId;
    const opcode_t opcode;
    fsize payloadSize;
    RequestHeader(const opcode_t reqCode) :opcode(reqCode), payloadSize(INIT_VAL) {}
    //RequestHeader(const opcode_t reqCode) :opcode(reqCode) {}
    RequestHeader(const ClientID& id, const opcode_t reqCode) : clientId(id), opcode(reqCode), payloadSize(INIT_VAL) {}
    //RequestHeader(const ClientID& id, const opcode_t reqCode) : clientId(id), opcode(reqCode) {}
};

struct ResponseHeader {
    const opcode_t opcode;
    fsize payloadSize;
    ResponseHeader() : opcode(INIT_VAL), payloadSize(INIT_VAL){}
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
#pragma pack(pop)
