#include "include/service/auth_service.hpp"

#include <algorithm>
#include <stdexcept>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace {

std::string randomBytes(int size) {
    std::string value(size, '\0');
    
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&value[0]), size) != 1)
        throw std::runtime_error("Random generation failed");
    return value;

}

std::string randomHex(int size) {
    const std::string bytes = randomBytes(size);
    const char* digits = "0123456789abcdef";
    std::string text;

    for (unsigned char byte : bytes) {
        text += digits[byte >> 4];
        text += digits[byte & 15];

    }

    return text;

}

std::string normalizeEmail(std::string email) {

    for (char& ch : email) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
    return email;

}

bool validEmail(const std::string& email) {

    const auto at = email.find('@');

    if (email.size() > 254 || at == std::string::npos || at == 0 || at + 1 == email.size())
        return false;

    if (email.find('@', at + 1) != std::string::npos) return false;
    
    for (unsigned char ch : email) if (ch <= 32 || ch >= 127) return false;
    
    return true;

}

std::string derive(const std::string& password, const std::string& salt, int iterations) {

    std::string hash(32, '\0');

    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char*>(salt.data()), static_cast<int>(salt.size()),
        iterations, EVP_sha256(), 32, reinterpret_cast<unsigned char*>(&hash[0])) != 1)
        throw std::runtime_error("Password derivation failed");

    return hash;

}

}

namespace sgc {

AuthService::AuthService(UserRepository& users, std::chrono::seconds lifetime)
    : users_(users), lifetime_(lifetime) {}

void AuthService::registerUser(const std::string& name, const std::string& email,
    const std::string& password) {

    if (name.empty() || name.size() > 100 ||
        std::all_of(name.begin(), name.end(), [](unsigned char ch) { return ch <= 32; }))
        throw std::invalid_argument("Informe um nome de até 100 bytes.");
    
    for (unsigned char ch : name) if (ch < 32 || ch == 127)
        throw std::invalid_argument("O nome contém caracteres inválidos.");
    
    if (!validEmail(email)) throw std::invalid_argument("Informe um email válido.");
    
    if (password.size() < 12 || password.size() > 128)
        throw std::invalid_argument("A senha deve ter entre 12 e 128 bytes.");
    
    User user;
    user.name = name;
    user.email = normalizeEmail(email);
    user.operatorId = "user-" + randomHex(16);
    user.passwordSalt = randomBytes(16);
    user.passwordHash = derive(password, user.passwordSalt, user.passwordIterations);
    
    if (!users_.insert(user)) throw std::invalid_argument("Este email já está cadastrado.");

}

std::string AuthService::login(const std::string& email, const std::string& password) {

    if (!validEmail(email) || password.size() > 128) return "";
    User user;

    const bool found = users_.findByEmail(normalizeEmail(email), user);
    
    // perform the same derivation for an unknown account.
    const std::string hash = derive(password, found ? user.passwordSalt : std::string(16, '\0'),
        user.passwordIterations);

    if (!found || user.passwordHash.size() != hash.size() ||
        CRYPTO_memcmp(hash.data(), user.passwordHash.data(), hash.size()) != 0) return "";
    
    removeExpiredSessions();
    
    if (sessions_.size() >= 128) throw std::runtime_error("Local session limit reached");
    std::string token;
    
    do {
        token = randomHex(32);
    }
    
    while(sessions_.count(token));

    sessions_.emplace(token, Session{user.email, std::chrono::steady_clock::now() + lifetime_});
    
    return token;

}

void AuthService::removeExpiredSessions() {
    const auto now = std::chrono::steady_clock::now();
    
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (it->second.expires <= now) it = sessions_.erase(it);
        else ++it;
    
    }

}

bool AuthService::currentUser(const std::string& token, User& user) {
    removeExpiredSessions();
    const auto found = sessions_.find(token);

    return found != sessions_.end() && users_.findByEmail(found->second.email, user);

}

void AuthService::logout(const std::string& token) { sessions_.erase(token); }
}