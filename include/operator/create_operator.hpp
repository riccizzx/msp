#ifndef OPERATOR_CREATION_HPP
#define OPERATOR_CREATION_HPP

#include <string>

#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/Certificate.h>

#include "operator.hpp"

namespace sgc {
namespace op {

// Factory responsible for creating the key material and certificate used by
// an Operator. The prototype certificates are deliberately self-signed; they
// prove key possession, not membership in an external PKI.
class OperatorCreation {
public:
    static Operator* createOperator(
        const std::string& name,
        const std::string& id,
        const std::string& email
    );

    static RSAKeyPair* createOperatorKey();

    static Certificate* createOperatorCert(
        const std::string& name,
        const std::string& id,
        const std::string& email,
        RSAKeyPair& keyPair
    );

private:
    OperatorCreation();

    static const int OPERATOR_KEY_SIZE = 2048;
};

} // namespace op
} // namespace sgc

#endif
