
#ifndef APP_OPERATOR_HPP
#define APP_OPERATOR_HPP

/* o operador sera uma "pessoa" da empresa, que tera nome cpf e demais informações... o operador ira assinar
 o documento de criacao do container, e sera responsavel por criar o container, e tambem sera responsavel por
 assinar o documento de criacao do container, e tambem sera responsavel por assinar o documento de criacao do container
*/

#include <string.h>
#include <iostream>

#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/Certificate.h>

namespace sgc{

    namespace op{

        class Operator{
                // cada operador tem seu par de chaves RSA 2048 bits, e seu certificado digital, que sera usado para assinar o documento de criacao do container
            public:
                Operator(
                    const std::string nome,
                    const std::string cpf,
                    const std::string email,
                    
                    RSAKeyPair* keyPair,
                    PublicKey* publicKey,
                    PrivateKey* privateKey,
                    Certificate* certificate
                );
                
                Operator(const Operator& op);
                
                ~Operator();

                // métodos
                std::string getName() const;
                std::string getCpf() const;
                std::string getEmail() const;

                PublicKey* getPublicKey() const;
                PrivateKey* getPrivateKey() const;
                Certificate* getCertificate() const;

            private:

                std::string name;
                std::string cpf;
                std::string email;

                RSAKeyPair* keyPair;
                PublicKey* publicKey;
                PrivateKey* privateKey;
                Certificate* certificate;

        };

    }

}

#endif