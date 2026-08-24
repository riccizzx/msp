#include "include/agreement/agreement.hpp"

#include <stdexcept>

#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <libcryptosec/certificate/RDNSequence.h>

using namespace sgc;

namespace {

bool containsExactlyOnce(
    const std::vector<std::string>& values,
    const std::string& expected
){
    unsigned int occurrences = 0;
    for (size_t i = 0; i < values.size(); ++i) {
        if (values[i] == expected) {
            ++occurrences;
        }
    }
    return occurrences == 1;
}

} // namespace

agreement::Agreement::Agreement(ByteArray& document, const std::vector<std::string>& expectedIds)
    : document(document), expectedIds(expectedIds), state(PENDING) {

    if (document.size() == 0) {
        throw std::invalid_argument("document cannot be empty");
    }

    if (expectedIds.empty()) {
        throw std::invalid_argument("at least one operator is required");
    }

    for (size_t i = 0; i < expectedIds.size(); ++i) {
        if (expectedIds[i].empty()) {
            throw std::invalid_argument("operator id cannot be empty");
        }

        for (size_t j = i + 1; j < expectedIds.size(); ++j) {
            if (expectedIds[i] == expectedIds[j]) {
                throw std::invalid_argument("duplicated operator id");
            }
        }
    }
}

bool agreement::Agreement::sign(const op::Operator& signer){
    if (this->state != PENDING) {
        return false;
    }

    const std::string id = signer.getId();

    for (size_t i = 0; i < this->signedIds.size(); ++i) {
        if (this->signedIds[i] == id) return false;
    }

    bool expected = false;
    for (size_t i = 0; i < this->expectedIds.size(); ++i) {
        if (this->expectedIds[i] == id) {
            expected = true;
            break;
        }
    }

    if (!expected) return false;

    if (!this->engine.isInitialized()) {
        this->engine.addFirstSigner(signer, this->document);
    } else {
        this->engine.addSigner(signer);
    }

    this->signedIds.push_back(id);

    if (this->signedIds.size() == this->expectedIds.size()) {
        this->state = COMPLETE;
    }

    return true;
}

void agreement::Agreement::abort(){
    if (this->state == PENDING) this->state = ABORTED;
}

agreement::Agreement::State agreement::Agreement::getState() const { return this->state; }
unsigned int agreement::Agreement::signedCount() const { return this->signedIds.size(); }
unsigned int agreement::Agreement::expectedCount() const { return this->expectedIds.size(); }

Pkcs7SignedData* agreement::Agreement::finalPackage(){
    if (this->state != COMPLETE) {
        throw std::runtime_error("agreement does not contain all required signatures");
    }

    Pkcs7SignedData* package = this->engine.build();
    this->state = FINALIZED;
    return package;
}

bool agreement::Agreement::verifyPackage(
    Pkcs7SignedData& package,
    const std::vector<std::string>& expectedIds
){
    if (expectedIds.empty() || !package.verify(false)) {
        return false;
    }

    // Parse a private OpenSSL copy of the CMS object. Counting certificates is
    // insufficient: CMS certificates and SignerInfo entries are independent.
    // The protocol policy must therefore be checked against the actual
    // SignerInfo records that were cryptographically verified above.
    ByteArray der = package.getDerEncoded();
    const unsigned char* cursor = der.getDataPointer();
    PKCS7* raw = d2i_PKCS7(NULL, &cursor, static_cast<long>(der.size()));
    if (raw == NULL) {
        return false;
    }

    bool valid = true;
    std::vector<std::string> signerIds;

    STACK_OF(PKCS7_SIGNER_INFO)* signerInfos = PKCS7_get_signer_info(raw);
    const int signerCount = signerInfos == NULL ? 0 : sk_PKCS7_SIGNER_INFO_num(signerInfos);

    if (signerCount != static_cast<int>(expectedIds.size())) {
        valid = false;
    }

    for (int i = 0; valid && i < signerCount; ++i) {
        PKCS7_SIGNER_INFO* signerInfo = sk_PKCS7_SIGNER_INFO_value(signerInfos, i);
        X509* signerX509 = PKCS7_cert_from_signer_info(raw, signerInfo);
        if (signerX509 == NULL) {
            valid = false;
            break;
        }

        try {
            Certificate signerCertificate(X509_dup(signerX509));
            RDNSequence subject = signerCertificate.getSubject();
            std::vector<std::string> ids = subject.getEntries(RDNSequence::SERIAL_NUMBER);
            if (ids.size() != 1 || ids[0].empty()) {
                valid = false;
            } else {
                signerIds.push_back(ids[0]);
            }
        } catch (...) {
            valid = false;
        }
    }

    PKCS7_free(raw);

    if (!valid || signerIds.size() != expectedIds.size()) {
        return false;
    }

    // Require a one-to-one match. This rejects duplicates, unexpected signers,
    // and signature-stripping attacks that leave a certificate in the package
    // but remove its SignerInfo.
    for (size_t i = 0; i < expectedIds.size(); ++i) {
        if (!containsExactlyOnce(signerIds, expectedIds[i])) {
            return false;
        }
    }

    for (size_t i = 0; i < signerIds.size(); ++i) {
        if (!containsExactlyOnce(expectedIds, signerIds[i])) {
            return false;
        }
    }

    return true;
}
