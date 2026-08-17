
#include "include/operator/create_operator.hpp"

#include <ctime>

#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>

using namespace sgc;

op::Operator* op::OperatorCreation::createOperator(
    const std::string& name,
    const std::string& cpf,
    const std::string& email
){
    RSAKeyPair* keyPair = OperatorCreation::createOperatorKey();
    Certificate* certificate = OperatorCreation::createOperatorCert(name, cpf, email, *keyPair);

    // Operator assume a posse de keyPair e certificate (ver operator.hpp)
    return new Operator(name, cpf, email, keyPair, certificate);
}

RSAKeyPair* op::OperatorCreation::createOperatorKey(){
    return new RSAKeyPair(OperatorCreation::OPERATOR_KEY_SIZE);
}

Certificate* op::OperatorCreation::createOperatorCert(
    const std::string& name,
    const std::string& cpf,
    const std::string& email,
    RSAKeyPair& keyPair
){
    RDNSequence subject;
    subject.addEntry(RDNSequence::COMMON_NAME, name);
    subject.addEntry(RDNSequence::EMAIL, email);
    subject.addEntry(RDNSequence::SERIAL_NUMBER, cpf); // usamos SERIAL_NUMBER pra carregar o CPF

    CertificateBuilder builder;
    builder.setSubject(subject);
    builder.setIssuer(subject); // autoassinado: emissor == titular

    // NOTA: time(NULL) como serial é só o bastante pro protótipo. Se você
    // criar vários operadores no mesmo segundo, pode colidir. Numa versão
    // mais séria, use um contador incremental ou combine com rand().
    builder.setSerialNumber((long) time(NULL));

    DateTime notBefore((time_t) time(NULL));
    DateTime notAfter((time_t) (time(NULL) + 60 * 60 * 24 * 365)); // validade de 1 ano

    builder.setNotBefore(notBefore);
    builder.setNotAfter(notAfter);

    PublicKey* publicKey = keyPair.getPublicKey();
    builder.setPublicKey(*publicKey);
    delete publicKey;

    PrivateKey* privateKey = keyPair.getPrivateKey();
    Certificate* certificate = builder.sign(*privateKey, MessageDigest::SHA256);
    delete privateKey;

    return certificate;
}