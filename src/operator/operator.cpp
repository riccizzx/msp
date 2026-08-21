
#include "include/operator/operator.hpp"

using namespace sgc;

op::Operator::Operator(
    const std::string& name,
    const std::string& id,
    const std::string& email,
    RSAKeyPair* keyPair,
    Certificate* certificate
) : name(name), id(), email(email), keyPair(keyPair), certificate(certificate) {

}

op::Operator::Operator(const Operator& other){
    this->name = other.name;
    this->id = other.id;
    this->email = other.email;

    this->keyPair = (other.keyPair != NULL) ? new KeyPair(*other.keyPair) : NULL;
    this->certificate = (other.certificate != NULL) ? new Certificate(*other.certificate) : NULL;
}

op::Operator& op::Operator::operator=(const Operator& other){
    if (this == &other) {
        return *this;
    }

    this->release();

    this->name = other.name;
    this->id = other.id;
    this->email = other.email;

    this->keyPair = (other.keyPair != NULL) ? new KeyPair(*other.keyPair) : NULL;
    this->certificate = (other.certificate != NULL) ? new Certificate(*other.certificate) : NULL;

    return *this;
}

void op::Operator::release(){
    delete this->keyPair;
    delete this->certificate;
    this->keyPair = NULL;
    this->certificate = NULL;
}

op::Operator::~Operator(){
    this->release();
}

std::string op::Operator::getName() const {
    return this->name;
}

std::string op::Operator::getId() const {
    return this->id;
}

std::string op::Operator::getEmail() const {
    return this->email;
}

PublicKey* op::Operator::getPublicKey() const {
    return this->keyPair->getPublicKey();
}

PrivateKey* op::Operator::getPrivateKey() const {
    return this->keyPair->getPrivateKey();
}

Certificate* op::Operator::getCertificate() const {
    return new Certificate(*this->certificate);
}