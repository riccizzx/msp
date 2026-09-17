
#ifndef MSP_LOCAL_SIGNATURE_SERVICE_HPP
#define MSP_LOCAL_SIGNATURE_SERVICE_HPP

#include <map>
#include <memory>
#include "include/model/user.hpp"
#include "include/service/signature_service.hpp"

namespace sgc {

    // Web application use case; deliberately independent of HTTP.
    class LocalSignatureService {

        public:
            static const std::size_t maxPdfBytes = 10 * 1024 * 1024;
            explicit LocalSignatureService(service::SignatureService& signatures);
        
            ~LocalSignatureService();
        
            static void validatePdf(const std::string& pdf);
            void sign(const User& user, const std::string& pdf);
            const service::SignatureResult* latest(const User& user) const;
        
        private:
            service::SignatureService& signatures_;
        
            std::map<std::string, std::unique_ptr<op::Operator>> operators_;
            std::map<std::string, service::SignatureResult> results_;
};

}

#endif
