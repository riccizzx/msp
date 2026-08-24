#include "include/agreement/agreement.hpp"

#include <sstream>
#include <stdexcept>

#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/certificate/RDNSequence.h>

using namespace sgc;

namespace {

void validateExpectedIds(const std::vector<std::string>& expectedIds){
    if (expectedIds.empty()) {
        throw std::invalid_argument("at least one operator is required");
    }

    for (size_t i = 0; i < expectedIds.size(); ++i) {
        if (expectedIds[i].empty()) {
            throw std::invalid_argument("operator id cannot be empty");
        }
        if (expectedIds[i].find('\n') != std::string::npos ||
            expectedIds[i].find('\r') != std::string::npos) {
            throw std::invalid_argument("operator id contains an invalid line break");
        }

        for (size_t j = i + 1; j < expectedIds.size(); ++j) {
            if (expectedIds[i] == expectedIds[j]) {
                throw std::invalid_argument("duplicated operator id");
            }
        }
    }
}

std::string buildPolicyHeader(const std::vector<std::string>& expectedIds){
    std::ostringstream header;
    header << "MSP-POLICY/1\n";
    header << "mode=unanimous\n";
    header << "required=" << expectedIds.size() << "\n";
    for (size_t i = 0; i < expectedIds.size(); ++i) {
        header << "signer=" << expectedIds[i] << "\n";
    }
    header << "--PDF--\n";
    return header.str();
}

ByteArray buildSignedPayload(
    ByteArray& pdf,
    const std::vector<std::string>& expectedIds
){
    if (pdf.size() == 0) {
        throw std::invalid_argument("document cannot be empty");
    }
    validateExpectedIds(expectedIds);

    const std::string header = buildPolicyHeader(expectedIds);
    std::string payload(header);
    payload.append(
        reinterpret_cast<const char*>(pdf.getDataPointer()),
        static_cast<std::string::size_type>(pdf.size())
    );
    return ByteArray(payload);
}

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

int indexOf(
    const std::vector<std::string>& values,
    const std::string& wanted
){
    for (size_t i = 0; i < values.size(); ++i) {
        if (values[i] == wanted) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

bool embeddedPolicyMatches(
    Pkcs7SignedData& package,
    const std::vector<std::string>& expectedIds
){
    std::ostringstream extracted;
    if (!package.verifyAndExtract(&extracted)) {
        return false;
    }

    const std::string payload = extracted.str();
    const std::string expectedHeader = buildPolicyHeader(expectedIds);
    if (payload.size() < expectedHeader.size() + 5) {
        return false;
    }
    if (payload.compare(0, expectedHeader.size(), expectedHeader) != 0) {
        return false;
    }
    return payload.compare(expectedHeader.size(), 5, "%PDF-") == 0;
}

} // namespace

agreement::Agreement::Agreement(ByteArray& document, const std::vector<std::string>& expectedIds)
    : document(buildSignedPayload(document, expectedIds)),
      expectedIds(expectedIds),
      state(PENDING) {
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
    const std::vector<std::string>& expectedIds,
    const std::vector<std::string>& trustedFingerprints
){
    if (expectedIds.empty() || trustedFingerprints.size() != expectedIds.size()) {
        return false;
    }

    try {
        validateExpectedIds(expectedIds);
    } catch (...) {
        return false;
    }

    // First validate every cryptographic signature over the attached payload.
    // Certificate-chain validation is deliberately replaced in this prototype
    // by explicit SHA-256 certificate pinning below.
    if (!package.verify(false) || !embeddedPolicyMatches(package, expectedIds)) {
        return false;
    }

    // Parse a private OpenSSL copy of the CMS object. Counting certificates is
    // insufficient because certificates and SignerInfo entries are independent.
    ByteArray der = package.getDerEncoded();
    const unsigned char* cursor = der.getDataPointer();
    PKCS7* raw = d2i_PKCS7(NULL, &cursor, static_cast<long>(der.size()));
    if (raw == NULL) {
        return false;
    }

    bool valid = true;
    std::vector<std::string> signerIds;
    std::vector<std::string> signerFingerprints;

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
                break;
            }

            signerIds.push_back(ids[0]);
            signerFingerprints.push_back(
                signerCertificate.getFingerPrint(MessageDigest::SHA256).toHex()
            );
        } catch (...) {
            valid = false;
        }
    }

    PKCS7_free(raw);

    if (!valid || signerIds.size() != expectedIds.size()) {
        return false;
    }

    // Require a one-to-one SignerInfo -> expected identity mapping and pin each
    // identity to an out-of-band trusted certificate fingerprint.
    for (size_t i = 0; i < expectedIds.size(); ++i) {
        if (!containsExactlyOnce(signerIds, expectedIds[i])) {
            return false;
        }

        const int signerIndex = indexOf(signerIds, expectedIds[i]);
        if (signerIndex < 0 ||
            signerFingerprints[static_cast<size_t>(signerIndex)] != trustedFingerprints[i]) {
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
