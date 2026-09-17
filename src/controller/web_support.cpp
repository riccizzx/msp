#include "include/controller/web_support.hpp"
#include "include/service/local_signature_service.hpp"
#include "httplib.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace {
std::string readText(const std::string& path) {
    std::ifstream file(path.c_str(), std::ios::binary);
    if (!file) throw std::runtime_error("Cannot load web asset: " + path);
    std::ostringstream text;
    text << file.rdbuf();
    if (file.bad()) throw std::runtime_error("Cannot read web asset: " + path);
    return text.str();
}

std::string escapeHtml(const std::string& text) {
    std::string escaped;
    for (char ch : text) {
        switch (ch) {
        case '&': escaped += "&amp;"; break;
        case '<': escaped += "&lt;"; break;
        case '>': escaped += "&gt;"; break;
        case '"': escaped += "&quot;"; break;
        case '\'': escaped += "&#39;"; break;
        default: escaped += ch;
        }
    }
    return escaped;
}
}

namespace sgc {
WebViews::WebViews(const std::string& root) {
    for (const char* page : {"login", "register", "dashboard", "sign", "error"})
        pages_.emplace(page, readText(root + "/views/" + page + ".html"));
    css_ = readText(root + "/public/css/style.css");
}

void WebViews::show(httplib::Response& response, const std::string& page,
    const std::map<std::string, std::string>& values, int status) const {
    const std::string& source = pages_.at(page);
    std::string rendered;
    std::size_t position = 0;
    // Scan the template once; substituted text is never interpreted as markup or tokens.
    while (position < source.size()) {
        const auto start = source.find("{{", position);
        if (start == std::string::npos) { rendered += source.substr(position); break; }
        rendered += source.substr(position, start - position);
        const auto end = source.find("}}", start + 2);
        if (end == std::string::npos) throw std::runtime_error("Invalid view placeholder");
        const auto value = values.find(source.substr(start + 2, end - start - 2));
        if (value != values.end()) rendered += escapeHtml(value->second);
        position = end + 2;
    }
    response.status = status;
    response.set_content(rendered, "text/html; charset=utf-8");
}

void WebViews::error(httplib::Response& response, int status, const std::string& message) const {
    show(response, "error", {{"status", std::to_string(status)}, {"message", message}}, status);
}

void WebViews::stylesheet(httplib::Response& response) const {
    response.set_content(css_, "text/css; charset=utf-8");
}

std::string sessionToken(const httplib::Request& request) {
    std::istringstream cookies(request.get_header_value("Cookie"));
    std::string part, token;
    bool seen = false;
    while (std::getline(cookies, part, ';')) {
        const auto start = part.find_first_not_of(" \t");
        if (start == std::string::npos || part.compare(start, 12, "msp_session=") != 0) continue;
        if (seen) return "";
        seen = true;
        token = part.substr(start + 12);
    }
    if (token.size() != 64 || token.find_first_not_of("0123456789abcdef") != std::string::npos)
        return "";
    return token;
}

bool requireUser(AuthService& auth, const httplib::Request& request,
    httplib::Response& response, User& user) {
    if (auth.currentUser(sessionToken(request), user)) return true;
    response.set_redirect("/login", 303);
    return false;
}

bool isAccountForm(const httplib::Request& request) {
    const auto type = request.get_header_value("Content-Type");
    return request.body.size() <= 8192 &&
        type.substr(0, type.find(';')) == "application/x-www-form-urlencoded";
}

void configureHttp(httplib::Server& server, const WebViews& views) {
    // OpenSSL 1.0.2 and in-memory services are only accessed by this worker.
    server.new_task_queue = [] { return new httplib::ThreadPool(1, 1, 16); };
    server.set_payload_max_length(LocalSignatureService::maxPdfBytes + 64 * 1024);
    server.set_read_timeout(10, 0);
    server.set_write_timeout(10, 0);
    server.set_keep_alive_max_count(10);
    server.set_default_headers({
        {"Cache-Control", "no-store"}, {"X-Content-Type-Options", "nosniff"},
        {"Content-Security-Policy", "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"},
        // no-referrer makes browsers send Origin: null on ordinary form POSTs.
        // Preserve the origin for local forms while omitting cross-origin referrers.
        {"Referrer-Policy", "same-origin"}
    });
    server.set_pre_routing_handler([&views](const httplib::Request& request, httplib::Response& response) {
        const auto host = request.get_header_value("Host");
        const auto origin = request.get_header_value("Origin");
        if (host != "127.0.0.1:8080" ||
            (!origin.empty() && origin != "http://127.0.0.1:8080")) {
            views.error(response, 403, "Use a aplicação em http://127.0.0.1:8080.");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });
    server.set_exception_handler([&views](const httplib::Request&, httplib::Response& response,
        std::exception_ptr) {
        std::cerr << "Web request failed with an internal error.\n";
        views.error(response, 500, "Não foi possível concluir a operação. Tente novamente.");
    });
    server.set_error_handler([&views](const httplib::Request&, httplib::Response& response) {
        if (!response.body.empty()) return;
        views.error(response, response.status, response.status == 413
            ? "O envio excede o limite permitido de 10 MiB para o PDF."
            : "Requisição inválida ou recurso não encontrado.");
    });
    server.Get("/public/css/style.css", [&views](const httplib::Request&, httplib::Response& response) {
        views.stylesheet(response);
    });
}
}
