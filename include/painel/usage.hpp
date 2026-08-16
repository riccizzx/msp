
#ifndef USAGE_HPP
#define USAGE_HPP

namespace sgc{

    namespace us{ // mean "usage"

        // This class will be used to track the usage of the application, including the number of times the application has been used, and the number of times the application has been used to sign a document. This information will be used to determine if the application is being used in a legitimate manner, and if not, it will be used to disable the application.

        class Usage{
                // this class will print a painel, that the user can use to see the usage of the application, and the number of times the application has been used to sign a document. This information will be used to determine if the application is being used in a legitimate manner, and if not, it will be used to disable the application.
            public:
                Usage();
                ~Usage();

                void showPainel();
                
        };

    }

}

#endif