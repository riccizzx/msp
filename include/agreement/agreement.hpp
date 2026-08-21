
#ifndef AGREEMENT_HPP
#define AGREEMENT_HPP

#include <vector>
#include <string>

#include "include/operator/operator.hpp"
#include "include/agreement/multi_signature.hpp"

namespace sgc{
namespace agreement{

    // One round of the protocol: a document + the set of operators
    // who need to sign it. The agreement exists only when EVERYONE signs.
    
    class Agreement{

        public:
            enum State { PENDING, COMPLETE, ABORTED, FINALIZED };

            Agreement(ByteArray& document, const std::vector<std::string>& expectedIds);
            
            bool sign(const op::Operator& signer){

                /*
                Returns false if the operator is not expected, has already signed,
                or the agreement is no longer PENDING.
                */

            };

            void abort();

            State getState() const;
            unsigned int signedCount() const;
            unsigned int expectedCount() const;

            Pkcs7SignedData* finalPackage(){

                /*
                Can only be called once and when the state is COMPLETE. 
                The caller assumes ownership of the returned pointer..
                */

            };


            static bool verifyPackage(
                Pkcs7SignedData& package,
                const std::vector<std::string>& expectedIds
            )
            {

                /*
                Verifies the cryptographic signatures and whether the package contains
                exactly the certificates of the expected operators.
                */

            };

        private:

            Agreement(const Agreement&);
            Agreement& operator=(const Agreement&);

            ByteArray document;
            std::vector<std::string> expectedIds;
            std::vector<std::string> signedIds;
            MultiSignature engine;
            State state;
    };

}
}

#endif
