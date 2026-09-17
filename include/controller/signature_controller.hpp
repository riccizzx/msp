
#ifndef MSP_SIGNATURE_CONTROLLER_HPP
#define MSP_SIGNATURE_CONTROLLER_HPP

#include "include/controller/web_support.hpp"
#include "include/service/local_signature_service.hpp"

namespace sgc {

    class SignatureController {

        public:

        SignatureController(AuthService& auth, LocalSignatureService& signatures, const WebViews& views)
        : auth_(auth), signatures_(signatures), views_(views) {}
        
        void registerRoutes(httplib::Server& server);

        private:
        void sign(const httplib::Request& request, httplib::Response& response);
        void download(const httplib::Request& request, httplib::Response& response, bool trust);

        AuthService& auth_;

        LocalSignatureService& signatures_;

        const WebViews& views_;
};

}

#endif
