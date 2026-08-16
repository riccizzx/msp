// include/agreement/multi_signature.hpp
#ifndef MULTI_SIGNATURE_HPP
#define MULTI_SIGNATURE_HPP

#include <libcryptosec/Pkcs7SignedDataBuilder.h>
#include <libcryptosec/Pkcs7SignedData.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/ByteArray.h>

#include "include/operator/operator.hpp"

namespace sgc{
namespace agreement{

    // Encapsula o pacote PKCS7 SignedData. Não sabe quantos operadores
    // são esperados nem quem já assinou -- isso é responsabilidade da Agreement.
    class MultiSignature{

        public:
            MultiSignature();
            ~MultiSignature();

            // chame para o PRIMEIRO operador (inicializa o pacote com o documento).
            void addFirstSigner(const op::Operator& signer, ByteArray& document, bool attachContent = true);

            // chame para os operadores seguintes.
            void addSigner(const op::Operator& signer);

            bool isInitialized() const;
            unsigned int signerCount() const;

            // só chame depois de todos os assinantes adicionados.
            // devolve objeto novo; quem chama é dono do ponteiro.
            Pkcs7SignedData* build();

        private:
            Pkcs7SignedDataBuilder* builder;
            unsigned int m_signerCount;
            
    };

}
}
#endif