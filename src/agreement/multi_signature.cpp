
#include "include/agreement/multi_signature.hpp"
#include <memory>
#include <stdexcept>

using namespace sgc;

static const MessageDigest::Algorithm DIGEST_ALG = MessageDigest::SHA256;

agreement::MultiSignature::MultiSignature()
    : builder(NULL), m_signerCount(0), finalized(false) {}

agreement::MultiSignature::~MultiSignature(){

    delete this->builder; // deconstructor

}

void agreement::MultiSignature::addFirstSigner(const op::Operator& signer, ByteArray& document, bool attachContent){
    
    if (this->builder != NULL || this->finalized) {
        throw std::runtime_error("MultiSignature is already used");
    }

    std::auto_ptr<Certificate> cert(signer.getCertificate());
    std::auto_ptr<PrivateKey> privKey(signer.getPrivateKey());
    std::auto_ptr<Pkcs7SignedDataBuilder> newBuilder(
        new Pkcs7SignedDataBuilder(DIGEST_ALG, *cert, *privKey, attachContent)
    );

    this->builder = newBuilder.release();
    this->document = document;

    this->m_signerCount = 1;
}

void agreement::MultiSignature::addSigner(const op::Operator& signer){
    
    if (this->builder == NULL || this->finalized) {
        throw std::runtime_error("call addFirstSigner() before");
    }

    std::auto_ptr<Certificate> cert(signer.getCertificate());
    std::auto_ptr<PrivateKey> privKey(signer.getPrivateKey());

    this->builder->addSigner(DIGEST_ALG, *cert, *privKey);

    this->m_signerCount++;

}

bool agreement::MultiSignature::isInitialized() const {
    return this->builder != NULL && !this->finalized;
}

bool agreement::MultiSignature::isFinalized() const {
    return this->finalized;
}

unsigned int agreement::MultiSignature::signerCount() const {
    return this->m_signerCount;
}

Pkcs7SignedData* agreement::MultiSignature::build(){

    if (this->builder == NULL || this->m_signerCount == 0) {
        throw std::runtime_error("no subscribers added");
    }
    if (this->finalized) {
        throw std::runtime_error("the package is already finished");
    }

    // feed the document after every signer has been registered, during finalization.
    Pkcs7SignedData* package = this->builder->doFinal(this->document);
    this->finalized = true;
    return package;
}
