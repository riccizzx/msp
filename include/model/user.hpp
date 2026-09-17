
#ifndef MSP_USER_HPP
#define MSP_USER_HPP

#include <string>

namespace sgc {
// Application account. Private signing keys belong to Operator, never User.

struct User {
    std::string name;
    std::string email;
    std::string operatorId;
    std::string passwordSalt;
    std::string passwordHash;
    int passwordIterations = 600000;
};

}

#endif
