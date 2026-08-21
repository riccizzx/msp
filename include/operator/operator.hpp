
#ifndef APP_OPERATOR_HPP
#define APP_OPERATOR_HPP

#include <string>

#include <libcryptosec/KeyPair.h>
#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/Certificate.h>

namespace sgc{

    namespace op{

        class OperatorCreation;

        class Operator{

            // criação do objeto Operator*, sera utilizado para assinar o documneto digital.
            
            public:
                Operator(const Operator& other);
                Operator& operator=(const Operator& other);

                ~Operator();

                std::string getName() const;
                std::string getId() const;
                std::string getEmail() const;

                PublicKey* getPublicKey() const;
                PrivateKey* getPrivateKey() const;
                Certificate* getCertificate() const;

            private:
                friend class OperatorCreation;

                Operator(
                    const std::string& name,
                    const std::string& id,
                    const std::string& email,
                    RSAKeyPair* keyPair,
                    Certificate* certificate
                );

                void release();

                std::string name;
                std::string id;
                std::string email;

                KeyPair* keyPair;
                Certificate* certificate;
        };

    }

}

#endif
