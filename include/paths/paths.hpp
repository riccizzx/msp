
#ifndef PATHS_HPP
#define PATHS_HPP

#include <string>

namespace sgc{

    namespace paths{

        // create the paths when the container is created, and the operator will be able to use these paths to store the keys and the signature of the document that will be used to create the container.

        const std::string key_path = "/home/sgc/pam/keys/";

        const std::string SIGNATURE_PATH = "/home/sgc/pam/signature/";

    }

}

#endif