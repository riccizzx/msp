
#ifndef MULTI_SIGNATURE_HPP
#define MULTI_SIGNATURE_HPP

#include <libcryptosec/Pkcs7SignedDataBuilder.h>
#include <libcryptosec/Pkcs7SignedData.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/ByteArray.h>

#include "include/operator/operator.hpp"

namespace sgc{

namespace agreement{

    // Encapsulates the PKCS7 SignedData package. It does not know how many
    // operators are expected or who has already signed—that is the responsibility of the Agreement.
    
    class MultiSignature{

        public:
            MultiSignature();
            ~MultiSignature();

            // call for the first operator (initialize the first packed with the document)
            void addFirstSigner(const op::Operator& signer, ByteArray& document, bool attachContent = true);

            // call for other operators
            void addSigner(const op::Operator& signer);

            bool isInitialized() const;
            bool isFinalized() const;
            unsigned int signerCount() const;

            // only call after all the signers beign add
            Pkcs7SignedData* build();

        private:

            MultiSignature(const MultiSignature&);
            MultiSignature& operator=(const MultiSignature&);

            Pkcs7SignedDataBuilder* builder;
            ByteArray document;
            unsigned int m_signerCount;
            bool finalized;
            
    };

}
}
#endif
