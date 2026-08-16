// src/agreement/multi_signature.cpp
#include "include/agreement/multi_signature.hpp"
#include <stdexcept>

using namespace sgc;

static const MessageDigest::Algorithm DIGEST_ALG = MessageDigest::SHA256;

agreement::MultiSignature::MultiSignature() : builder(NULL), m_signerCount(0) {}

agreement::MultiSignature::~MultiSignature(){
    delete this->builder;
}

void agreement::MultiSignature::addFirstSigner(const op::Operator& signer, ByteArray& document, bool attachContent){
    if (this->builder != NULL) {
        throw std::runtime_error("MultiSignature ja foi inicializado");
    }

    Certificate* cert = signer.getCertificate();
    PrivateKey* privKey = signer.getPrivateKey();

    this->builder = new Pkcs7SignedDataBuilder(DIGEST_ALG, *cert, *privKey, attachContent);
    this->builder->update(document);

    delete cert;
    delete privKey;

    this->m_signerCount = 1;
}

void agreement::MultiSignature::addSigner(const op::Operator& signer){
    if (this->builder == NULL) {
        throw std::runtime_error("chame addFirstSigner() antes");
    }

    Certificate* cert = signer.getCertificate();
    PrivateKey* privKey = signer.getPrivateKey();

    this->builder->addSigner(DIGEST_ALG, *cert, *privKey);

    delete cert;
    delete privKey;

    this->m_signerCount++;
}

bool agreement::MultiSignature::isInitialized() const {
    return this->builder != NULL;
}

unsigned int agreement::MultiSignature::signerCount() const {
    return this->m_signerCount;
}

Pkcs7SignedData* agreement::MultiSignature::build(){
    if (this->builder == NULL) {
        throw std::runtime_error("nenhum assinante adicionado");
    }
    return this->builder->doFinal();
}