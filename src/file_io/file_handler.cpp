
#include "include/file_io/file_handler.hpp"

using namespace sgc;

FileHandle::~FileHandle() {}

ByteArray FileHandle::read_file(const char* filePath)
{
    // read the file and return the content as a ByteArray

    fstream file(filePath, ios::in | ios::binary | ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + std::string(filePath));
    
    }

    streamoff size = file.tellg();
    file.seekg(0, ios::beg);

    if (size <= 0) {
        file.close();
        return ByteArray();
    }

    ByteArray data(static_cast<unsigned int>(size));
    file.read(reinterpret_cast<char*>(data.getDataPointer()), size);
    file.close();
    return data;

}

void FileHandle::write_file(const char* filePath, ByteArray& data)
{
    // verify if the file already exists, if it does, throw an exception
    std::ifstream existsCheck(filePath, ios::binary);
    if (existsCheck.good()) {
        throw std::runtime_error("File already exists: " + std::string(filePath));
    }

    // create the file and write the data to it
    fstream file(filePath, ios::out | ios::binary | ios::trunc);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + std::string(filePath));
    }

    file.write(reinterpret_cast<char*>(data.getDataPointer()), data.size());
    file.close();

}