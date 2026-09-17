
#ifndef MSP_AUTH_CONTROLLER_HPP
#define MSP_AUTH_CONTROLLER_HPP

#include "include/controller/web_support.hpp"

namespace sgc {

    class AuthController {

        public:

        AuthController(AuthService& auth, const WebViews& views) : auth_(auth), views_(views) {}

        void registerRoutes(httplib::Server& server);

        private:

        void login(const httplib::Request& request, httplib::Response& response);

        void registerUser(const httplib::Request& request, httplib::Response& response);


        AuthService& auth_;

        const WebViews& views_;
};

}

#endif
