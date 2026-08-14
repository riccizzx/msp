#include <stdio.h>
#include <libcryptosec/MessageDigest.h>

#include "include/agreement/multi_signature.hpp"
#include "include/file_io/file_handler.hpp"
#include "include/operator/operator.hpp"
#include "include/paths/paths.hpp"

int main(int argc, char **argv) {

    // função para rodar o programa

    printf("Hello There!\n");
	
	MessageDigest::loadMessageDigestAlgorithms();
	
	return 0;
}
