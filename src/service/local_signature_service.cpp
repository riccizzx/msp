#include "include/service/local_signature_service.hpp"
#include "include/operator/create_operator.hpp"
#include <stdexcept>

namespace sgc {
LocalSignatureService::LocalSignatureService(service::SignatureService& signatures)
    : signatures_(signatures) {}

LocalSignatureService::~LocalSignatureService() {}

void LocalSignatureService::validatePdf(const std::string& pdf) {

    /*
    
        this validation can be better if use a PDF parser library, but for this case, i use a simple validation to check if the PDF is valid.
        the validation only check if the PDF is valid by checking the header and the EOF marker.
        this validation is not a security measure, but a basic check to avoid processing invalid PDFs.
    
    */

    if (pdf.empty() || pdf.size() > maxPdfBytes)
        throw std::invalid_argument("Selecione um PDF de até 10 MiB.");
    
    // this is a basic envelope checks, not a complete PDF parser or malware scanner.
    if (pdf.size() < 14 || pdf.compare(0, 5, "%PDF-") != 0 ||
        (pdf[5] != '1' && pdf[5] != '2') || pdf[6] != '.' ||
        pdf[7] < '0' || pdf[7] > '9' || (pdf[8] != '\r' && pdf[8] != '\n'))
        throw std::invalid_argument("O conteúdo não possui um cabeçalho PDF válido.");
    
    const auto eof = pdf.rfind("%%EOF");
    
    if (eof == std::string::npos || pdf.size() - eof > 1024)
        throw std::invalid_argument("O PDF está incompleto: marcador final ausente.");
    
    for (std::size_t i = eof + 5; i < pdf.size(); ++i)
        if (pdf[i] != '\r' && pdf[i] != '\n' && pdf[i] != ' ' && pdf[i] != '\t')
            throw std::invalid_argument("O PDF contém dados inesperados após o marcador final.");

}

void LocalSignatureService::sign(const User& user, const std::string& pdf) {
    validatePdf(pdf);

    if (user.operatorId.empty()) throw std::invalid_argument("Conta sem operador associado.");
    auto found = operators_.find(user.operatorId);

    if (found == operators_.end()) {
        std::unique_ptr<op::Operator> signer(op::OperatorCreation::createOperator(
            user.name, user.operatorId, user.email));
        found = operators_.emplace(user.operatorId, std::move(signer)).first;
    }

    std::vector<op::Operator*> signers{found->second.get()};
    
    service::SignatureResult result = signatures_.signPdf(pdf, signers);
    
    if (!result.complete) throw std::runtime_error("Agreement was not completed");
    results_[user.operatorId] = std::move(result);

}

const service::SignatureResult* LocalSignatureService::latest(const User& user) const {
    const auto found = results_.find(user.operatorId);
    return found == results_.end() ? nullptr : &found->second;
}

}