#include "include/repository/user_repository.hpp"
#include <stdexcept>

namespace sgc {
bool InMemoryUserRepository::findByEmail(const std::string& email, User& user) const {
    const auto found = users_.find(email);
    if (found == users_.end()) return false;
    user = found->second;
    return true;
}

bool InMemoryUserRepository::insert(const User& user) {
    if (users_.count(user.email)) return false;
    if (users_.size() >= 32) throw std::runtime_error("Local account limit reached");
    return users_.emplace(user.email, user).second;
}
}
