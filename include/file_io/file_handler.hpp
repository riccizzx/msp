
#ifndef FILE_HANDLE_HPP
#define FILE_HANDLE_HPP

#include <string>
#include <fstream>
#include <stdexcept>
#include <iostream>

#include <libcryptosec/ByteArray.h>

namespace sgc{

    class FileHandle{

        /*
        This class provides an abstraction for file handling operations, including opening, closing, reading from,
        and writing to files. It encapsulates the file descriptor and provides a simple interface for file I/O operations.

        It will handle the PDF file that will be used for the digital signature process. The class will ensure that the file is properly opened and closed, and it will provide methods to read from and write to the file as needed.
        */

        public:
            ~FileHandle();

            ByteArray read_file(const char* filePath);
            
            void write_file(const char* filePath, ByteArray& data);

    };

}

#endif