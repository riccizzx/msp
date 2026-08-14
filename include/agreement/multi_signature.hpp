
#ifndef MULTI_SIGNATURE_HPP
#define MULTI_SIGNATURE_HPP

#include <string>
#include <libcryptosec/Pkcs7SignedDataBuilder.h>

#include <libcryptosec/ByteArray.h>

namespace sgc{

namespace agreement{

    class MultiSignature{

        /* classe que ficara responsavel pela logica das assinaturas de multiplos operadores, e que sera responsavel por armazenar as
        assinaturas dos operadores, e tambem sera responsavel por verificar se todas as assinaturas estao presentes, e tambem sera 
        responsavel por gerar o arquivo final assinado com todas as assinaturas.
        */

        public:
            MultiSignature();
            ~MultiSignature();

            

        private:
            std::vector<std::string> signatures;
        
    };

}

}

#endif