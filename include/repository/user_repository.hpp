
#ifndef MSP_USER_REPOSITORY_HPP
#define MSP_USER_REPOSITORY_HPP

#include <map>
#include "include/model/user.hpp"

namespace sgc {

    class UserRepository {

        public:

        virtual ~UserRepository() {}
        virtual bool findByEmail(const std::string& email, User& user) const = 0;
        virtual bool insert(const User& user) = 0;

};

// Access is serialized by the web server's single worker.
class InMemoryUserRepository : public UserRepository {

    public:
        bool findByEmail(const std::string& email, User& user) const override;
        bool insert(const User& user) override;

    private:
        std::map<std::string, User> users_;
};

}

#endif
