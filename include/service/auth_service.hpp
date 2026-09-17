
#ifndef MSP_AUTH_SERVICE_HPP
#define MSP_AUTH_SERVICE_HPP

#include <chrono>
#include <map>
#include "include/repository/user_repository.hpp"

namespace sgc {

    class AuthService {

        public:

        explicit AuthService(UserRepository& users,
            std::chrono::seconds lifetime = std::chrono::seconds(1800));

            void registerUser(const std::string& name, const std::string& email,
                const std::string& password);

                // Empty token means invalid credentials. Every login creates a fresh token.
                std::string login(const std::string& email, const std::string& password);
                bool currentUser(const std::string& token, User& user);
                void logout(const std::string& token);

                private:
                struct Session {

                    std::string email;

                    std::chrono::steady_clock::time_point expires;

                };

                void removeExpiredSessions();

                UserRepository& users_;
                std::chrono::seconds lifetime_;
                std::map<std::string, Session> sessions_;
};

}

#endif
