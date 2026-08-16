// include/agreement/agreement.hpp
#ifndef AGREEMENT_HPP
#define AGREEMENT_HPP

#include <vector>
#include <string>

#include "include/operator/operator.hpp"
#include "include/agreement/multi_signature.hpp"

namespace sgc{
namespace agreement{

    // Uma rodada do protocolo: um documento + o conjunto de operadores
    // que precisam assiná-lo. Implementa a regra "só existe conjunto de
    // assinaturas se TODOS assinarem".
    class Agreement{

        public:
            enum State { PENDING, COMPLETE, ABORTED };

            Agreement(ByteArray& document, const std::vector<std::string>& expectedCpfs);

            // Retorna false se o operador não é esperado, já assinou,
            // ou o acordo já não está mais PENDING.
            bool sign(const op::Operator& signer);

            void abort();

            State getState() const;
            unsigned int signedCount() const;
            unsigned int expectedCount() const;

            // só chame quando getState() == COMPLETE. Dono do ponteiro é o chamador.
            Pkcs7SignedData* finalPackage();

        private:
            ByteArray document;
            std::vector<std::string> expectedCpfs;
            std::vector<std::string> signedCpfs;
            MultiSignature engine;
            State state;
    };

}
}

#endif