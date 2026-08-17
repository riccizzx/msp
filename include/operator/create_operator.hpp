
#ifndef OPERATOR_CREATION_HPP
#define OPERATOR_CREATION_HPP

#include <string>

#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/certificate/Certificate.h>

#include "operator.hpp"

namespace sgc{
    namespace op{

        // Fábrica responsável por gerar, pra um operador, o par de chaves RSA
        // e o certificado digital que o identifica, empacotando tudo num
        // Operator pronto pra uso.
        //
        // SIMPLIFICAÇÃO DELIBERADA deste protótipo: o certificado gerado é
        // AUTOASSINADO (o operador assina o próprio certificado com a
        // própria chave privada). Numa ICP real -- como a que você leu no
        // TCC do Hawa -- é uma Autoridade Certificadora quem assina o
        // certificado do usuário final, nunca ele mesmo. Vale registrar essa
        // diferença no relatório, explicando o porquê da simplificação.
        class OperatorCreation{

            public:
                static Operator* createOperator(
                    const std::string& name,
                    const std::string& cpf,
                    const std::string& email
                );

                static RSAKeyPair* createOperatorKey();

                static Certificate* createOperatorCert(
                    const std::string& name,
                    const std::string& cpf,
                    const std::string& email,
                    RSAKeyPair& keyPair
                );

            private:
                OperatorCreation(); // não declarado -- impede instanciação

                static const int OPERATOR_KEY_SIZE = 2048;
        };
    }
}

#endif