
/*
    
    This code use a legacy version of libcryptosec.
    For this case, i use C++ 98 to implement the signature service, because the current version of libcryptosec is not compatible with C++11.
    Because of this, this code is implemented in C++98.
    
*/

#include "include/service/signature_service.hpp"

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

std::vector<std::string> demoIds(){
    std::vector<std::string> ids;
    ids.push_back("operator-1");
    ids.push_back("operator-2");
    ids.push_back("operator-3");
    return ids;
}

/*

    Operadores pre definidos para o serviço de assinatura. Estes operadores são usados para assinar documentos PDF de demonstração.
    Em uma aplicação real, os operadores seriam criados dinamicamente e armazenados em um banco de dados seguro.
    Algo que sera implementado no futuro, mas por enquanto, para fins de demonstração, os operadores são pré-definidos e usados para assinar documentos PDF.

*/

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
    
    }
    catch (...) {
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

std::vector<std::string> operatorFingerprints(const std::vector<Operator*>& operators){
    std::vector<std::string> fingerprints;
    
    for (size_t i = 0; i < operators.size(); ++i) {
        std::auto_ptr<Certificate> certificate(operators[i]->getCertificate());
    
        fingerprints.push_back(certificate->getFingerPrint(MessageDigest::SHA256).toHex()
    
        );
    }

    return fingerprints;

}

std::string trustPathFor(const std::string& packagePath){
    return packagePath + ".trust";

}

std::vector<std::string> readTrustFile(
    FileHandle& fileHandler, // get file and read into ByteArray type - see libcryptosec documentation for ByteArray class
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

bool containsId(const std::vector<std::string>& ids, const std::string& wanted){
    for (size_t i = 0; i < ids.size(); ++i) {
        if (ids[i] == wanted) return true;
    }
    return false;
}


} // namespace

namespace sgc {
namespace service {

void SignatureService::initialize() {
    MessageDigest::loadMessageDigestAlgorithms();
}

std::vector<std::string> SignatureService::demoOperatorIds() {
    return demoIds();
}

SignatureResult SignatureService::signPdf(
    const std::string& pdf, const std::vector<op::Operator*>& operators,
    const std::string& rejectedId
) const {
    
    if (pdf.compare(0, 5, "%PDF-") != 0) {
        throw std::invalid_argument("input is not a PDF document");
    }
    
    std::vector<std::string> ids;
    
    for (size_t i = 0; i < operators.size(); ++i) {
        if (!operators[i]) throw std::invalid_argument("missing operator");
        ids.push_back(operators[i]->getId());
    }

    if (!rejectedId.empty() && !containsId(ids, rejectedId)) {
        throw std::invalid_argument("unknown operator passed to --reject");
    }

    const std::vector<std::string> pins = operatorFingerprints(operators);
    ByteArray document(pdf);
    Agreement agreement(document, ids);
    
    for (size_t i = 0; i < operators.size(); ++i) {
        if (operators[i]->getId() == rejectedId) {
            agreement.abort();
            break;
        }
    
        if (!agreement.sign(*operators[i])) {
            throw std::runtime_error("operator signature was not accepted");
        }
    
    }
    
    SignatureResult result;
    result.signedCount = agreement.signedCount();
    result.expectedCount = agreement.expectedCount();
    
    if (agreement.getState() != Agreement::COMPLETE) return result;

    std::auto_ptr<Pkcs7SignedData> package(agreement.finalPackage());
    
    if (!Agreement::verifyPackage(*package, ids, pins)) {
        throw std::runtime_error("generated signatures could not be verified");
    
    }
    
    ByteArray encoded = package->getDerEncoded();
    result.package.assign(reinterpret_cast<const char*>(encoded.getDataPointer()), encoded.size());
    std::ostringstream trust;
    trust << "MSP-TRUST/1\n";
    
    for (size_t i =0; i<ids.size(); ++i){

        trust << ids[i] << "=" << pins[i] << "\n";

    };

    result.trust = trust.str();
    result.complete = true;
    
    return result;

}

SignatureResult SignatureService::signFile(
    const char* inputPath, const char* outputPath, const std::string& rejectedId
)
const {
    
    if (!rejectedId.empty() && !containsId(demoIds(), rejectedId)) {
        throw std::invalid_argument("unknown operator passed to --reject");
    }
    
    FileHandle files;
    ByteArray document = files.read_file(inputPath);
    
    if (document.size() < 5) {
        throw std::invalid_argument("input is not a PDF document");
    }
    
    const std::string pdf(reinterpret_cast<const char*>(document.getDataPointer()), document.size());
    
    if (pdf.compare(0, 5, "%PDF-") != 0) {
        throw std::invalid_argument("input is not a PDF document");
    }
    
    std::vector<Operator*> operators = createDemoOperators();
    SignatureResult result;
    
    try {
        result = signPdf(pdf, operators, rejectedId);
        if (result.complete) {
            ByteArray encoded(result.package);
            ByteArray trust(result.trust);
            
            files.write_file(outputPath, encoded);
            files.write_file(trustPathFor(outputPath).c_str(), trust);
    
        }
    }
    catch (...) {
        destroyOperators(operators);
        throw;
    }
    
    destroyOperators(operators);
    
    return result;

}

bool SignatureService::verifyFile(const char* packagePath) const {
    FileHandle files;
    ByteArray encoded = files.read_file(packagePath);
    
    std::auto_ptr<Pkcs7> package(Pkcs7Factory::fromDerEncoded(encoded));
    
    if (package->getType() != Pkcs7::SIGNED) {
        throw std::invalid_argument("file is not a PKCS#7 SignedData package");
    }
    
    const std::vector<std::string> ids = demoIds();
    const std::vector<std::string> pins = readTrustFile(files, packagePath, ids);
    
    return Agreement::verifyPackage(*static_cast<Pkcs7SignedData*>(package.get()), ids, pins);

}

} // namespace service
} // namespace sgc