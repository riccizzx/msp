#include <stdio.h>
#include <libcryptosec/MessageDigest.h>

#include "include/agreement/multi_signature.hpp"
#include "include/file_io/file_handler.hpp"
#include "include/operator/operator.hpp"
#include "include/paths/paths.hpp"
#include "include/operator/create_operator.hpp"

using namespace sgc;
using namespace op;

const char* PDF_PATH = "/home/gui/Documents/code/pam/testes/teste.pdf";

int main(int argc, char **argv) {

    // função para rodar o programa
	MessageDigest::loadMessageDigestAlgorithms();
	
    // read pdf file
    FileHandle fileHandler;
    try{
        ByteArray document = fileHandler.read_file(PDF_PATH);
    
    }
    catch(const std::exception &e){
        printf("Erro ao ler o arquivo PDF: %s\n", e.what());
        return 1;
    }


    // teste
    Operator* gui = OperatorCreation::createOperator("Guilherme", "12345678900", "guilherme@labsec.br");
    Certificate* cert = gui->getCertificate();
    std::cout << cert->getPemEncoded() << std::endl;
    
    delete cert;
    delete gui;

	return 0;
}
