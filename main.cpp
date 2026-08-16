#include <stdio.h>
#include <libcryptosec/MessageDigest.h>

#include "include/agreement/multi_signature.hpp"
#include "include/file_io/file_handler.hpp"
#include "include/operator/operator.hpp"
#include "include/paths/paths.hpp"

using namespace sgc;
using namespace op;

const char* PDF_PATH = "/home/gui/Documents/code/pam/testes/teste.pdf";

int main(int argc, char **argv) {

    // função para rodar o programa
	MessageDigest::loadMessageDigestAlgorithms();
	
    // read pdf file
    FileHandle fileHandler;
    ByteArray document = fileHandler.read_file(PDF_PATH);

    // usuario cria operadores com seus respectivo atributos

    // montar os operator para o cliente

	return 0;
}
