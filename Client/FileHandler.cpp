#include "FileHandler.h"

#include <algorithm>


FileHandler::FileHandler()
{
	_inFileStream = nullptr;
	_outFileStream = nullptr;
	_openToRead = false; 
	_openToWrite = false;
}

FileHandler::~FileHandler()
{
	_inFileStream->close();
	_outFileStream->close();
	_openToWrite = false;
	_openToRead = false;
	delete _inFileStream;
	delete _outFileStream;
}


/**
 * Open a file for read/write. Create folders in filepath if do not exist.
 * Relative paths not supported!
 */
bool FileHandler::open(const std::string& filepath, bool write)
{
	const auto flags = write ? (std::ios::binary | std::ios::out) : (std::ios::binary | std::ios::in);
	if (filepath.empty())
		return false;

	try
	{
		// close and clear current fstream before allocating new one.
		if (write) {
			if (_openToWrite)
				_outFileStream->close();
			_outFileStream = new std::ofstream;
			_outFileStream->open(filepath, flags);
			_openToWrite = _outFileStream->is_open();
		}
		else {
			if (_openToRead)
				_inFileStream->close();
			if (!this->is_file_exist(filepath))
				return false;
			_inFileStream = new std::ifstream;
			_inFileStream->open(filepath, flags);
			bool test = _inFileStream->good();
			_openToRead = _inFileStream->is_open();
		}
	}
	catch (...)
	{
		if (write){
			_openToWrite = false;
		}
		else {
			_openToRead = false;
		}
	}
	return write ? _openToWrite : _openToRead;
}

/**
 * Read bytes from fs to dest.
 */
uint32_t FileHandler::readByChunks(char* dest,const size_t bytes) const
{
	if (_inFileStream == nullptr || !_openToRead || _inFileStream->eof())
		return 0;
	try
	{
		uint32_t extracted = _inFileStream->read(dest,bytes).gcount();
		return extracted;
	}
	catch (...)
	{
		std::cerr << "Error: Couldnt read from file" << std::endl;
		return 0;
	}
}


/**
 * Write given bytes from src to fs.
 */
bool FileHandler::write(const char* src, const size_t bytes)
{
	if (_outFileStream == nullptr || !_openToWrite || src == nullptr || bytes == 0)
		return false;
	try
	{
		_outFileStream->write(src, bytes);
		return true;
	}
	catch (...)
	{
		return false;
	}
}


/**
 * Read a single line from fs to line.
 */
bool FileHandler::readLine(std::string& line,bool removeWhiteSpace) const
{
	if (_inFileStream == nullptr || !_openToRead)
		return false;
	try {
		if (!std::getline(*_inFileStream, line) || line.empty())
			return false;
		if (removeWhiteSpace)
			trim(line);
		return true;
	}
	catch (...)
	{
		return false;
	}
}
	
bool FileHandler::writeLine(std::string& line) {
	if (_outFileStream == nullptr || !_openToWrite)
		return false;
	try {
		std::string newLine = line + '\n';
		_outFileStream->write(newLine.c_str(), newLine.size());
	}
	catch (...) {
		return false;
	}
}
/**
 * Calculate the file size which is opened by fs.
 */
long FileHandler::size(std::string filePath) const
{
	if (_inFileStream == nullptr || !_openToRead)
		return 0;
	try
	{
		struct stat stat_buf;
		int rc = stat(filePath.c_str(), &stat_buf);
		return rc == 0 ? stat_buf.st_size : -1;
	}
	catch (...)
	{
		return -1;
	}
}

bool FileHandler::is_file_exist(const std::string& fileName)
{
	struct stat buffer;
	return (stat(fileName.c_str(), &buffer) == 0);
}

void FileHandler::close(bool write) {
	if (write)
		_outFileStream->close();
	else
		_inFileStream->close();
}

