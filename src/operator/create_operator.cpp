
#include "include/operator/create_operator.hpp"

#include <ctime>
#include <memory>

#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>

using namespace sgc;

// i based it on my implementation that i create to resolve the SGC challenge
// src: https://github.com/riccizzx/sgc-challange/blob/personal-solutions/src/milestones/ThirdMilestone.cpp

op::Operator* op::OperatorCreation::createOperator(
    const std::string& name,
    const std::string& id,
    const std::string& email
){
    std::auto_ptr<RSAKeyPair> keyPair(OperatorCreation::createOperatorKey());
    std::auto_ptr<Certificate> certificate(
        OperatorCreation::createOperatorCert(name, id, email, *keyPair));
    Operator* result = new Operator(name, id, email, keyPair.get(), certificate.get());
    keyPair.release();
    certificate.release();
    return result;
}

RSAKeyPair* op::OperatorCreation::createOperatorKey(){
    return new RSAKeyPair(OperatorCreation::OPERATOR_KEY_SIZE);
}

Certificate* op::OperatorCreation::createOperatorCert(
    const std::string& name,
    const std::string& id,
    const std::string& email,
    RSAKeyPair& keyPair
){
    RDNSequence subject;
    subject.addEntry(RDNSequence::COMMON_NAME, name);
    subject.addEntry(RDNSequence::EMAIL, email);
    subject.addEntry(RDNSequence::SERIAL_NUMBER, id);

    CertificateBuilder builder;
    builder.setSubject(subject);
    builder.setIssuer(subject); // autosigned: emissor == titular

    /*
    
    NOTE: time(NULL) is sufficient for a prototype, but... if the user creates many operators within
    the same second, collisions may occur. In a more robust implementation for a real-world system, use a counter
    or combine it with rand().
    
    */
    
    builder.setSerialNumber((long) time(NULL));

    DateTime notBefore((time_t) time(NULL));
    DateTime notAfter((time_t) (time(NULL) + 60 * 60 * 24 * 365)); // validade de 1 ano

    builder.setNotBefore(notBefore);
    builder.setNotAfter(notAfter);

    std::auto_ptr<PublicKey> publicKey(keyPair.getPublicKey());
    builder.setPublicKey(*publicKey);

    std::auto_ptr<PrivateKey> privateKey(keyPair.getPrivateKey());
    Certificate* certificate = builder.sign(*privateKey, MessageDigest::SHA256); // in this case, the private key
    // who sign the certificate is the same user private key, not a Certificate Autorathy

    // Certificate* cert = builder.sign(*ca->privateKey, SHA256);

    return certificate;
}
