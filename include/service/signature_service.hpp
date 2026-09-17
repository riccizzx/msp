
#ifndef MSP_SIGNATURE_SERVICE_HPP
#define MSP_SIGNATURE_SERVICE_HPP

#include <string>
#include <vector>

namespace sgc {
namespace op { class Operator; }
namespace service {

struct SignatureResult {
    bool complete;
    unsigned int signedCount;
    unsigned int expectedCount;
    std::string package;
    std::string trust;
    SignatureResult() : complete(false), signedCount(0), expectedCount(0) {}
};

// C++98 application boundary: no HTTP, accounts, or presentation concerns.
class SignatureService {
public:
    static void initialize();
    static std::vector<std::string> demoOperatorIds();
    SignatureResult signPdf(const std::string& pdf,
        const std::vector<op::Operator*>& operators,
        const std::string& rejectedId = "") const;
    SignatureResult signFile(const char* inputPath, const char* outputPath,
        const std::string& rejectedId = "") const;
    bool verifyFile(const char* packagePath) const;
};

} // namespace service
} // namespace sgc
#endif
