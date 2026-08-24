#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/Pkcs7Factory.h>

#include "include/agreement/agreement.hpp"
#include "include/file_io/file_handler.hpp"
#include "include/operator/create_operator.hpp"

using namespace sgc;
using namespace sgc::agreement;
using namespace sgc::op;

namespace {

std::vector<std::string> demoOperatorIds(){
    std::vector<std::string> ids;
    ids.push_back("operator-1");
    ids.push_back("operator-2");
    ids.push_back("operator-3");
    return ids;
}

std::vector<Operator*> createDemoOperators(){
    std::vector<Operator*> operators;
    try {
        operators.push_back(OperatorCreation::createOperator(
            "Guilherme Ricci", "operator-1", "guilherme.ricci@example.test"
        ));
        operators.push_back(OperatorCreation::createOperator(
            "Heitor Kaxu", "operator-2", "heitor.kaxu@example.test"
        ));
        operators.push_back(OperatorCreation::createOperator(
            "Henrique Rofl", "operator-3", "henrique.rofl@example.test"
        ));
    } catch (...) {
        for (size_t i = 0; i < operators.size(); ++i) {
            delete operators[i];
        }
        throw;
    }

    return operators;
}

void destroyOperators(std::vector<Operator*>& operators){
    for (size_t i = 0; i < operators.size(); ++i) {
        delete operators[i];
    }
    operators.clear();
}

std::vector<std::string> operatorFingerprints(
    const std::vector<Operator*>& operators
){
    std::vector<std::string> fingerprints;
    for (size_t i = 0; i < operators.size(); ++i) {
        std::auto_ptr<Certificate> certificate(operators[i]->getCertificate());
        fingerprints.push_back(
            certificate->getFingerPrint(MessageDigest::SHA256).toHex()
        );
    }
    return fingerprints;
}

std::string trustPathFor(const std::string& packagePath){
    return packagePath + ".trust";
}

void writeTrustFile(
    FileHandle& fileHandler,
    const std::string& packagePath,
    const std::vector<std::string>& ids,
    const std::vector<std::string>& fingerprints
){
    if (ids.size() != fingerprints.size()) {
        throw std::runtime_error("invalid trust store data");
    }

    std::ostringstream out;
    out << "MSP-TRUST/1\n";
    for (size_t i = 0; i < ids.size(); ++i) {
        out << ids[i] << "=" << fingerprints[i] << "\n";
    }

    ByteArray data(out.str());
    const std::string trustPath = trustPathFor(packagePath);
    fileHandler.write_file(trustPath.c_str(), data);
}

std::vector<std::string> readTrustFile(
    FileHandle& fileHandler,
    const std::string& packagePath,
    const std::vector<std::string>& expectedIds
){
    const std::string trustPath = trustPathFor(packagePath);
    ByteArray data = fileHandler.read_file(trustPath.c_str());
    const std::string text(
        reinterpret_cast<const char*>(data.getDataPointer()),
        static_cast<std::string::size_type>(data.size())
    );

    std::istringstream in(text);
    std::string line;
    if (!std::getline(in, line) || line != "MSP-TRUST/1") {
        throw std::runtime_error("invalid trust store header");
    }

    std::vector<std::string> fingerprints;
    for (size_t i = 0; i < expectedIds.size(); ++i) {
        if (!std::getline(in, line)) {
            throw std::runtime_error("trust store is incomplete");
        }

        const std::string prefix = expectedIds[i] + "=";
        if (line.compare(0, prefix.size(), prefix) != 0 || line.size() == prefix.size()) {
            throw std::runtime_error("trust store identity does not match expected operator");
        }
        fingerprints.push_back(line.substr(prefix.size()));
    }

    if (std::getline(in, line) && !line.empty()) {
        throw std::runtime_error("trust store contains unexpected identities");
    }

    return fingerprints;
}

bool isPdf(const ByteArray& document){
    static const char PDF_HEADER[] = "%PDF-";
    if (document.size() < 5) return false;

    for (int i = 0; i < 5; ++i) {
        if (document.at(i) != PDF_HEADER[i]) return false;
    }
    return true;
}

bool containsId(const std::vector<std::string>& ids, const std::string& wanted){
    for (size_t i = 0; i < ids.size(); ++i) {
        if (ids[i] == wanted) return true;
    }
    return false;
}

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

int signDocument(
    const char* inputPath,
    const char* outputPath,
    const std::string& rejectedId
){
    const std::vector<std::string> expectedIds = demoOperatorIds();
    if (!rejectedId.empty() && !containsId(expectedIds, rejectedId)) {
        throw std::invalid_argument("unknown operator passed to --reject");
    }

    FileHandle fileHandler;
    ByteArray document = fileHandler.read_file(inputPath);
    if (!isPdf(document)) {
        throw std::invalid_argument("input is not a PDF document");
    }

    std::vector<Operator*> operators = createDemoOperators();
    try {
        const std::vector<std::string> trustedFingerprints = operatorFingerprints(operators);
        Agreement agreement(document, expectedIds);

        for (size_t i = 0; i < operators.size(); ++i) {
            const std::string id = operators[i]->getId();
            std::cout << "Presenting " << id << " ("
                      << operators[i]->getName() << ")... ";

            if (id == rejectedId) {
                std::cout << "REFUSED\n";
                agreement.abort();
                break;
            }

            if (!agreement.sign(*operators[i])) {
                throw std::runtime_error("operator signature was not accepted");
            }
            std::cout << "SIGNED\n";
        }

        if (agreement.getState() != Agreement::COMPLETE) {
            std::cout << "No agreement: " << agreement.signedCount()
                      << " of " << agreement.expectedCount()
                      << " operators signed. No package was created.\n";
            destroyOperators(operators);
            return 2;
        }

        std::auto_ptr<Pkcs7SignedData> package(agreement.finalPackage());
        if (!Agreement::verifyPackage(*package, expectedIds, trustedFingerprints)) {
            throw std::runtime_error("generated signatures could not be verified");
        }

        ByteArray encoded = package->getDerEncoded();
        fileHandler.write_file(outputPath, encoded);
        writeTrustFile(fileHandler, outputPath, expectedIds, trustedFingerprints);

        std::cout << "Agreement complete: all " << expectedIds.size()
                  << " signatures are valid.\n"
                  << "PKCS#7 package written to " << outputPath << "\n"
                  << "Trust pins written to " << trustPathFor(outputPath) << "\n";
    } catch (...) {
        destroyOperators(operators);
        throw;
    }

    destroyOperators(operators);
    return 0;
}

int verifyAgreement(const char* packagePath){
    FileHandle fileHandler;
    ByteArray encoded = fileHandler.read_file(packagePath);
    std::auto_ptr<Pkcs7> package(Pkcs7Factory::fromDerEncoded(encoded));

    if (package->getType() != Pkcs7::SIGNED) {
        throw std::invalid_argument("file is not a PKCS#7 SignedData package");
    }

    Pkcs7SignedData* signedPackage = static_cast<Pkcs7SignedData*>(package.get());
    const std::vector<std::string> expectedIds = demoOperatorIds();
    const std::vector<std::string> trustedFingerprints =
        readTrustFile(fileHandler, packagePath, expectedIds);

    if (!Agreement::verifyPackage(*signedPackage, expectedIds, trustedFingerprints)) {
        std::cout << "INVALID: signatures, agreement policy, or trusted signer identities do not match.\n";
        return 3;
    }

    std::cout << "VALID: all " << expectedIds.size()
              << " trusted operator signatures, the signed policy, and embedded PDF are intact.\n";
    return 0;
}

} // namespace

int main(int argc, char** argv){
    MessageDigest::loadMessageDigestAlgorithms();

    try {
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
