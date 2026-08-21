
#include "include/agreement/agreement.hpp"

#include <stdexcept>

#include <libcryptosec/certificate/RDNSequence.h>

using namespace sgc;

agreement::Agreement::Agreement(ByteArray& document, const std::vector<std::string>& expectedIds)
    : document(document), expectedIds(expectedIds), state(PENDING) {
    
    if (document.size() == 0) {
        throw std::invalid_argument("this can't be NULL");
    }

    if (expectedIds.empty()) {
        throw std::invalid_argument("Create an operator");
    }

    for (size_t i = 0; i < expectedIds.size(); ++i) {
        
        if (expectedIds[i].empty()) {
            throw std::invalid_argument("this can't be NULL");
        
        }
        
        for (size_t j = i + 1; j < expectedIds.size(); ++j) {
            if (expectedIds[i] == expectedIds[j]) {
                throw std::invalid_argument("duplicated IDs");
            }
        }
    }
}

bool agreement::Agreement::sign(const op::Operator& signer){
    
    if (this->state != PENDING) {
        return false;
    }

    const std::string id = signer.getId();

    for (size_t i = 0; i < this->signedIds.size(); ++i) {
        if (this->signedIds[i] == id) return false;
    }

    bool expected = false;
    
    for (size_t i = 0; i < this->expectedIds.size(); ++i) {
        if (this->expectedIds[i] == id) { expected = true; break; }
    }

    if (!expected) return false;

    if (!this->engine.isInitialized()) {
        this->engine.addFirstSigner(signer, this->document);
    } else {
        this->engine.addSigner(signer);
    }

    this->signedIds.push_back(id); // push the object .id to signedIds

    if (this->signedIds.size() == this->expectedIds.size()) {
        this->state = COMPLETE;
    }

    return true;
}

void agreement::Agreement::abort(){
    if (this->state == PENDING) this->state = ABORTED;
}

agreement::Agreement::State agreement::Agreement::getState() const { return this->state; }
unsigned int agreement::Agreement::signedCount() const { return this->signedIds.size(); }
unsigned int agreement::Agreement::expectedCount() const { return this->expectedIds.size(); }

Pkcs7SignedData* agreement::Agreement::finalPackage(){
    if (this->state != COMPLETE) {
        throw std::runtime_error("The agreement does not contain all the signatures");
    }

    Pkcs7SignedData* package = this->engine.build();
    this->state = FINALIZED;
    return package;
}

bool agreement::Agreement::verifyPackage(
    Pkcs7SignedData& package,
    const std::vector<std::string>& expectedIds
){
    if (expectedIds.empty() || !package.verify(false)) {
        return false;
    }

    std::vector<Certificate*> certificates = package.getCertificates();
    std::vector<std::string> packageIds;
    bool valid = certificates.size() == expectedIds.size();

    try {

        for (size_t i = 0; i < certificates.size(); ++i) {
            RDNSequence subject = certificates[i]->getSubject();
            std::vector<std::string> ids = subject.getEntries(RDNSequence::SERIAL_NUMBER);
        
            if (ids.size() != 1) {
                valid = false;
            } else {
                packageIds.push_back(ids[0]);
            }
        }
    } catch (...) {
        valid = false;
    }

    for (size_t i = 0; i < certificates.size(); ++i) {
        delete certificates[i];
    }

    if (!valid || packageIds.size() != expectedIds.size()) {
        return false;
    }

    for (size_t i = 0; i < expectedIds.size(); ++i) {
        unsigned int occurrences = 0;
        for (size_t j = 0; j < packageIds.size(); ++j) {
            if (expectedIds[i] == packageIds[j]) {
                ++occurrences;
            }
        }
        if (occurrences != 1) {
            return false;
        }
    }

    return true;
}
