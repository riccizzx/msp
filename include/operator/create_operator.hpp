
#ifndef OPERATOR_CREATION_HPP
#define OPERATOR_CREATION_HPP

#include <string>

#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/Certificate.h>

#include "operator.hpp"

namespace sgc{
    namespace op{

        // Factory responsible for generating the RSA key pair and the
        // identifying digital certificate for an operator, packaging
        // everything into a ready-to-use Operator object.
        //
        // DELIBERATE SIMPLIFICATION in this prototype: the generated
        // certificate is SELF-SIGNED (the operator signs their own
        // certificate using their own private key). In a real PKI—such
        // as the one described in Hawa's thesis—a Certificate Authority
        // signs the end-user's certificate, never the user themselves.
        // It is worth noting this difference in the report and
        // explaining the reason for the simplification.
        
        class OperatorCreation{

            public:
                static Operator* createOperator(
                    const std::string& name,
                    const std::string& id,
                    const std::string& email
                );

                static RSAKeyPair* createOperatorKey(){

                    // create operator KeyPairs based on OPERATOR_KEY_SIZE;
                    // return a RSAKeyPair type

                };
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
    }
}

#endif