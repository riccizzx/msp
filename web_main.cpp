
#include <iostream>
#include "httplib.h"
#include "include/controller/auth_controller.hpp"
#include "include/controller/signature_controller.hpp"

int main(int argc, char** argv) {
    
    if (argc > 2) {
        std::cerr << "Usage: " << argv[0] << " [asset-directory]\n";
        return 1;
    }
    
    try {
        sgc::service::SignatureService::initialize();
        sgc::InMemoryUserRepository users;
        sgc::AuthService auth(users);
        sgc::service::SignatureService core;
        sgc::LocalSignatureService signatures(core);
        sgc::WebViews views(argc == 2 ? argv[1] : ".");
        sgc::AuthController authController(auth, views);
        sgc::SignatureController signatureController(auth, signatures, views);
        httplib::Server server;
        sgc::configureHttp(server, views);
        authController.registerRoutes(server);
        signatureController.registerRoutes(server);
 
        if (!server.bind_to_port("127.0.0.1", 8080)) {
            std::cerr << "Could not bind to 127.0.0.1:8080.\n";
            return 1;
        }

        std::cout << "MSP local: http://127.0.0.1:8080\n"
                  << "Demo: accounts, sessions, keys and results exist only in memory.\n" << std::flush;
        return server.listen_after_bind() ? 0 : 1;
    } 
    catch (const std::exception& error) {
        std::cerr << "Could not start MSP web: " << error.what() << "\n";
        return 1;
    
    }

}
