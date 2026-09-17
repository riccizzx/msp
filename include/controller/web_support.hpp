
#ifndef MSP_WEB_SUPPORT_HPP
#define MSP_WEB_SUPPORT_HPP

#include <map>
#include <string>
#include "include/service/auth_service.hpp"

namespace httplib { class Server; struct Request; struct Response; }

namespace sgc {

    class WebViews {

        public:
        explicit WebViews(const std::string& root);
    
        void show(httplib::Response& response, const std::string& page,
        const std::map<std::string, std::string>& values = {}, int status = 200) const;

        void error(httplib::Response& response, int status, const std::string& message) const;
        void stylesheet(httplib::Response& response) const;

        private:
        std::map<std::string, std::string> pages_;
        std::string css_;

};

std::string sessionToken(const httplib::Request& request);

bool requireUser(AuthService& auth, const httplib::Request& request,
    httplib::Response& response, User& user);

bool isAccountForm(const httplib::Request& request);

void configureHttp(httplib::Server& server, const WebViews& views);

}

#endif
