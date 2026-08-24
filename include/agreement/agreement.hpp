#ifndef AGREEMENT_HPP
#define AGREEMENT_HPP

#include <string>
#include <vector>

#include "include/operator/operator.hpp"
#include "include/agreement/multi_signature.hpp"

namespace sgc {
namespace agreement {

// One protocol round: a document and the operators authorized to sign it.
// The current policy is unanimity: every expected operator must sign.
class Agreement {
public:
    enum State { PENDING, COMPLETE, ABORTED, FINALIZED };

    Agreement(ByteArray& document, const std::vector<std::string>& expectedIds);

    // Returns false when the signer is not expected, already signed, or the
    // agreement is no longer pending.
    bool sign(const op::Operator& signer);

    void abort();

    State getState() const;
    unsigned int signedCount() const;
    unsigned int expectedCount() const;

    // Can only be called once and after all expected operators have signed.
    // Ownership of the returned pointer is transferred to the caller.
    Pkcs7SignedData* finalPackage();

    // Verifies the CMS signatures and requires exactly one SignerInfo for each
    // expected operator identity.
    static bool verifyPackage(
        Pkcs7SignedData& package,
        const std::vector<std::string>& expectedIds
    );

private:
    Agreement(const Agreement&);
    Agreement& operator=(const Agreement&);

    ByteArray document;
    std::vector<std::string> expectedIds;
    std::vector<std::string> signedIds;
    MultiSignature engine;
    State state;
};

} // namespace agreement
} // namespace sgc

#endif
