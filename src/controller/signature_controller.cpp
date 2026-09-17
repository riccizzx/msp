#include "include/controller/signature_controller.hpp"
#include "httplib.h"
#include <stdexcept>

namespace sgc {
void SignatureController::registerRoutes(httplib::Server& server) {
    server.Get("/dashboard", [this](const httplib::Request& request, httplib::Response& response) {
        User user;
        if (!requireUser(auth_, request, response, user)) return;
        views_.show(response, "dashboard", {{"name", user.name}, {"email", user.email},
            {"operator", user.operatorId}, {"status", signatures_.latest(user)
                ? "Você tem uma assinatura disponível para download." : "Nenhuma assinatura nesta conta ainda."}});
    });
    server.Get("/sign", [this](const httplib::Request& request, httplib::Response& response) {
        User user;
        if (!requireUser(auth_, request, response, user)) return;
        views_.show(response, "sign", {{"message", signatures_.latest(user)
            ? "Assinatura concluída e verificada. O último resultado está disponível abaixo."
            : "Selecione um PDF para começar."}});
    });
    server.Post("/sign", [this](const httplib::Request& request, httplib::Response& response) {
        sign(request, response);
    });
    server.Get("/sign/package", [this](const httplib::Request& request, httplib::Response& response) {
        download(request, response, false);
    });
    server.Get("/sign/trust", [this](const httplib::Request& request, httplib::Response& response) {
        download(request, response, true);
    });
}

void SignatureController::sign(const httplib::Request& request, httplib::Response& response) {
    User user;
    if (!requireUser(auth_, request, response, user)) return;
    if (!request.is_multipart_form_data() || request.form.files.size() != 1 ||
        !request.form.has_file("pdf") || !request.form.fields.empty()) {
        views_.show(response, "sign", {{"message", "Envie exatamente um arquivo PDF pelo formulário."}}, 400);
        return;
    }
    const auto& pdf = request.form.files.begin()->second;
    if (pdf.content.size() > LocalSignatureService::maxPdfBytes) {
        views_.error(response, 413, "O PDF excede o limite de 10 MiB.");
        return;
    }
    try {
        signatures_.sign(user, pdf.content);
        response.set_redirect("/sign", 303);
    } catch (const std::invalid_argument& error) {
        views_.show(response, "sign", {{"message", error.what()}}, 400);
    }
}

void SignatureController::download(const httplib::Request& request, httplib::Response& response, bool trust) {
    User user;
    if (!requireUser(auth_, request, response, user)) return;
    const auto result = signatures_.latest(user);
    if (!result) {
        views_.error(response, 404, "Esta conta ainda não possui uma assinatura.");
        return;
    }
    response.set_header("Content-Disposition", trust
        ? "attachment; filename=agreement.p7s.trust" : "attachment; filename=agreement.p7s");
    response.set_content(trust ? result->trust : result->package,
        trust ? "text/plain; charset=utf-8" : "application/pkcs7-mime");
}
}
