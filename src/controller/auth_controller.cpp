#include "include/controller/auth_controller.hpp"
#include "httplib.h"
#include <stdexcept>

namespace sgc {
void AuthController::registerRoutes(httplib::Server& server) {
    server.Get("/", [](const httplib::Request&, httplib::Response& response) {
        response.set_redirect("/dashboard", 303);
    });
    server.Get("/login", [this](const httplib::Request& request, httplib::Response& response) {
        views_.show(response, "login", {{"message", request.get_param_value("registered") == "1"
            ? "Conta criada. Entre para continuar." : ""}});
    });
    server.Get("/register", [this](const httplib::Request&, httplib::Response& response) {
        views_.show(response, "register");
    });
    server.Post("/login", [this](const httplib::Request& request, httplib::Response& response) {
        login(request, response);
    });
    server.Post("/register", [this](const httplib::Request& request, httplib::Response& response) {
        registerUser(request, response);
    });
    server.Post("/logout", [this](const httplib::Request& request, httplib::Response& response) {
        auth_.logout(sessionToken(request));
        response.set_header("Set-Cookie", "msp_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
        response.set_redirect("/login", 303);
    });
}

void AuthController::login(const httplib::Request& request, httplib::Response& response) {
    if (!isAccountForm(request) || request.get_param_value_count("email") != 1 ||
        request.get_param_value_count("password") != 1) {
        views_.error(response, 400, "Envie email e senha pelo formulário.");
        return;
    }
    const auto token = auth_.login(request.get_param_value("email"), request.get_param_value("password"));
    if (token.empty()) {
        views_.show(response, "login", {{"message", "Email ou senha inválidos."}}, 401);
        return;
    }
    auth_.logout(sessionToken(request));
    response.set_header("Set-Cookie", "msp_session=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800");
    response.set_redirect("/dashboard", 303);
}

void AuthController::registerUser(const httplib::Request& request, httplib::Response& response) {
    if (!isAccountForm(request) || request.get_param_value_count("name") != 1 ||
        request.get_param_value_count("email") != 1 || request.get_param_value_count("password") != 1) {
        views_.error(response, 400, "Preencha nome, email e senha pelo formulário.");
        return;
    }
    try {
        auth_.registerUser(request.get_param_value("name"), request.get_param_value("email"),
            request.get_param_value("password"));
        response.set_redirect("/login?registered=1", 303);
    } catch (const std::invalid_argument& error) {
        views_.show(response, "register", {{"message", error.what()}}, 400);
    }
}
}
