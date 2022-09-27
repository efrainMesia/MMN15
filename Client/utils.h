#pragma once
#include <stdlib.h>
#include <filesystem>
#include <iostream>
#include <zlib.h>
#include "Base64Wrapper.h"



#define LOG_ERROR(x) (std::cerr <<"[+] ERROR: " << x << std::endl)
#define LOG(x) (std::cout << "[+] INFO: "<< x << std::endl)

uint8_t countDelim(std::string, char);
std::string encodeBase64(const std::string&);
std::string decodeBase64(const std::string&);

// trim from start (in place)
static inline void ltrim(std::string& s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
        }));
}

// trim from end (in place)
static inline void rtrim(std::string& s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
        }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string& s) {
    ltrim(s);
    rtrim(s);
}

static bool isAlNum(std::string& s) {
    //check if its only alphanumeric
    for (auto ch : s) {
        if (!std::isalnum(ch)) {
            return false;
        }
    }
    return true;
}