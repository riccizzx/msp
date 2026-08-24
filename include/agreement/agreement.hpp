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

    bool sign(const op::Operator& signer);
    void abort();

    State getState() const;
    unsigned int signedCount() const;
    unsigned int expectedCount() const;

    Pkcs7SignedData* finalPackage();

    // trustedFingerprints must be parallel to expectedIds and contain the
    // SHA-256 fingerprint of each trusted signer certificate.
    static bool verifyPackage(
        Pkcs7SignedData& package,
        const std::vector<std::string>& expectedIds,
        const std::vector<std::string>& trustedFingerprints
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
