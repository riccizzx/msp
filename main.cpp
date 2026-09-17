#include <iostream>
#include <stdexcept>
#include <string>
#include "include/service/signature_service.hpp"

namespace {
void printUsage(const char* program){
    std::cout
        << "Usage:\n"
        << "  " << program << " sign <input.pdf> <agreement.p7s>"
        << " [--reject <operator-id>]\n"
        << "  " << program << " verify <agreement.p7s>\n\n"
        << "Signing also writes <agreement.p7s>.trust with the pinned SHA-256\n"
        << "certificate fingerprints required by verification. Keep that trust\n"
        << "file as an out-of-band trust anchor.\n\n"
        << "Demo operators: operator-1, operator-2, operator-3\n";
}


int signDocument(const char* input, const char* output, const std::string& rejected) {
    const sgc::service::SignatureResult result =
        sgc::service::SignatureService().signFile(input, output, rejected);
    if (!result.complete) {
        std::cout << "No agreement: " << result.signedCount << " of "
                  << result.expectedCount << " operators signed. No package was created.\n";
        return 2;
    }
    std::cout << "Agreement complete: all " << result.expectedCount << " signatures are valid.\n"
              << "PKCS#7 package written to " << output << "\n"
              << "Trust pins written to " << output << ".trust\n";
    return 0;
}

int verifyAgreement(const char* path) {
    if (!sgc::service::SignatureService().verifyFile(path)) {
        std::cout << "INVALID: signatures, agreement policy, or trusted signer identities do not match.\n";
        return 3;
    }
    std::cout << "VALID: all 3 trusted operator signatures, the signed policy, and embedded PDF are intact.\n";
    return 0;
}
} // namespace

int main(int argc, char** argv){
    try {
        sgc::service::SignatureService::initialize();
        if (argc >= 2 && std::string(argv[1]) == "sign") {
            if (argc != 4 && argc != 6) {
                printUsage(argv[0]);
                return 1;
            }

            std::string rejectedId;
            if (argc == 6) {
                if (std::string(argv[4]) != "--reject") {
                    printUsage(argv[0]);
                    return 1;
                }
                rejectedId = argv[5];
            }
            return signDocument(argv[2], argv[3], rejectedId);
        }

        if (argc == 3 && std::string(argv[1]) == "verify") {
            return verifyAgreement(argv[2]);
        }

        printUsage(argv[0]);
        return argc == 2 && std::string(argv[1]) == "--help" ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << "\n";
        return 1;
    }
}
