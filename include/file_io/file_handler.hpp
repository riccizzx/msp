
#ifndef FILE_HANDLE_HPP
#define FILE_HANDLE_HPP

#include <string>



namespace sgc{

    class FileHandle{

        /*
        This class provides an abstraction for file handling operations, including opening, closing, reading from,
        and writing to files. It encapsulates the file descriptor and provides a simple interface for file I/O operations.

        It will handle the PDF file that will be used for the digital signature process. The class will ensure that the file is properly opened and closed, and it will provide methods to read from and write to the file as needed.
        */

        public:
            FileHandle();
            ~FileHandle();

            void openFile(const std::string& filePath);
            void closeFile();
            std::string readFile();
            void writeFile(const std::string& data);

        private:
            int m_fileDescriptor;
    };

}

#endif