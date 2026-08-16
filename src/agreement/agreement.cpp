
#include "include/agreement/agreement.hpp"

using namespace sgc;

agreement::Agreement::Agreement(ByteArray& document, const std::vector<std::string>& expectedCpfs)
    : document(document), expectedCpfs(expectedCpfs), state(PENDING) {}

bool agreement::Agreement::sign(const op::Operator& signer){
    if (this->state != PENDING) {
        return false;
    }

    const std::string cpf = signer.getCpf();

    for (size_t i = 0; i < this->signedCpfs.size(); ++i) {
        if (this->signedCpfs[i] == cpf) return false; // já assinou
    }

    bool expected = false;
    for (size_t i = 0; i < this->expectedCpfs.size(); ++i) {
        if (this->expectedCpfs[i] == cpf) { expected = true; break; }
    }
    if (!expected) return false;

    if (!this->engine.isInitialized()) {
        this->engine.addFirstSigner(signer, this->document);
    } else {
        this->engine.addSigner(signer);
    }

    this->signedCpfs.push_back(cpf);

    if (this->signedCpfs.size() == this->expectedCpfs.size()) {
        this->state = COMPLETE;
    }

    return true;
}

void agreement::Agreement::abort(){
    if (this->state == PENDING) this->state = ABORTED;
}

agreement::Agreement::State agreement::Agreement::getState() const { return this->state; }
unsigned int agreement::Agreement::signedCount() const { return this->signedCpfs.size(); }
unsigned int agreement::Agreement::expectedCount() const { return this->expectedCpfs.size(); }

Pkcs7SignedData* agreement::Agreement::finalPackage(){
    return this->engine.build();
}