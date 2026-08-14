
#include "include/operator/operator.hpp"

using namespace sgc;

op::Operator::Operator(const Operator& op){
    
    // copy constructor implementation
    this->name = op.name;
    this->cpf = op.cpf;
    this->email = op.email;
    
    this->keyPair = NULL;
    this->publicKey = NULL;
    this->privateKey = NULL;
    this->certificate = NULL;

    if (publicKey != NULL) {
        std::string pem = op.publicKey->getPemEncoded();
        this->publicKey = new PublicKey(pem);
    
    }

    if (privateKey != NULL){
        std::string pem = op.privateKey->getPemEncoded();
        this->privateKey = new PrivateKey(pem);
    
    }

    if (op.certificate != NULL){
        this->certificate = new Certificate(op.certificate->getPemEncoded());
    
    }
    
}

op::Operator::Operator(
    const std::string nome,
    const std::string cpf,
    const std::string email,
    RSAKeyPair* keyPair,
    PublicKey* publicKey,
    PrivateKey* privateKey,
    Certificate* certificate

) : name(nome), cpf(cpf), email(email), publicKey(publicKey), privateKey(privateKey), certificate(certificate) {
    // constructor implementation

};

// deconstruction
op::Operator::~Operator(){
    
    delete this->publicKey;
    delete this->privateKey;
    delete this->certificate;

};

std::string op::Operator::getName() const {
    return this->name;
}

std::string op::Operator::getCpf() const {
    return this->cpf;
}

std::string op::Operator::getEmail() const {
    return this->email;
}

PublicKey* op::Operator::getPublicKey() const {
 
    std::string pem = this->publicKey->getPemEncoded();
    return new RSAPublicKey(pem);

}

PrivateKey* op::Operator::getPrivateKey() const {

    std::string pem = this->privateKey->getPemEncoded();
    return new RSAPrivateKey(pem);

}

Certificate* op::Operator::getCertificate() const {

    return new Certificate(*this->certificate);

}

