#pragma once
#include <string>
#include <fstream>
#include <vector>
#include <iostream>
#include <sys/stat.h>
#include "utils.h"

/* TODO: Change Write 
   
   */
class FileHandler
{
public:
    FileHandler();
    virtual ~FileHandler();


    // file wrapper functions
    bool open(const std::string& filepath, bool write = false);
    uint32_t readByChunks(char*,const size_t) const;
    bool write(const char* src, const size_t bytes) ;
    bool readLine(std::string& line,bool) const;
    bool writeLine(std::string&);
    long size(std::string) const;

    bool is_file_exist(const std::string&);

private:
    std::fstream* _fileStream;
    std::ifstream* _inFileStream;
    std::ofstream* _outFileStream;

    bool _openToWrite;  // indicates whether a file is open.
    bool _openToRead;
};
