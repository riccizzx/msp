# MSP — multi-party signature protocol prototype

A C++98 prototype built with LabSEC's LibCryptoSEC and OpenSSL. Three demo
operators each receive an RSA-2048 key pair and a self-signed X.509
certificate. An agreement succeeds only when every expected operator signs the
same protocol payload.

The payload is not just the PDF. MSP first creates a canonical signed policy
containing the protocol version, unanimous mode, required signer count, and the
expected operator identifiers, then appends the PDF. The complete payload is
stored in one attached PKCS#7 `SignedData` package encoded as DER.

Verification checks:

- the CMS cryptographic signatures;
- the signed agreement policy;
- the actual CMS `SignerInfo` entries, not merely certificates embedded in the package;
- exactly one signer for every expected operator;
- SHA-256 certificate pins from an external trust file.

The certificates remain self-signed because this is a prototype. The generated
`<agreement>.trust` file therefore acts as the out-of-band trust anchor. In a
production PKI this should be replaced by normal X.509 chain/policy/revocation
validation against a trusted CA or another protected trust-store mechanism.

## Build inside the existing container

The container contains the compatible OpenSSL and LibCryptoSEC versions:

```sh
docker start 4153446c448c
docker exec -it 4153446c448c bash
cd /home/sgc/pam
make clean build
```

## Run

Create and immediately verify a unanimous agreement:

```sh
./build/pam sign document/test.pdf build/agreement.p7s
```

This creates both:

```text
build/agreement.p7s
build/agreement.p7s.trust
```

Keep the `.trust` file protected and distribute it independently from an
untrusted agreement package when it is being used as a real trust anchor.

Verify a stored agreement again:

```sh
./build/pam verify build/agreement.p7s
```

Simulate an operator refusing to sign. Exit status `2` means no agreement, and
neither the package nor the trust file is produced:

```sh
./build/pam sign document/test.pdf build/refused.p7s --reject operator-2
```

Run the success, refusal, package-tampering, and trust-pin scenarios:

```sh
make test
```

## Security scope

MSP currently implements **CMS co-signatures with an application-level
unanimity policy**. It is not a threshold-signature scheme such as FROST or
MuSig and does not aggregate private-key shares into one cryptographic
signature.

See [REPORT.md](REPORT.md) for the protocol and design explanation.

## Interface web local

A interface oferece cadastro, login, painel, upload de PDF, assinatura e logout
em **http://127.0.0.1:8080**. São páginas HTML tradicionais com CSS, formulários
e redirects 303. Não é necessário JavaScript, Node.js ou um banco de dados.

### Arquitetura e arquivos

```text
include/
├── agreement/                     # Agreement e MultiSignature existentes
├── operator/                      # Operator e OperatorCreation existentes
├── file_io/                       # leitura/escrita usada pelo CLI
├── controller/
│   ├── auth_controller.hpp
│   ├── signature_controller.hpp
│   └── web_support.hpp
├── service/
│   ├── signature_service.hpp
│   ├── local_signature_service.hpp
│   └── auth_service.hpp
├── model/
│   └── user.hpp
└── repository/
    └── user_repository.hpp
src/
├── agreement/                     # sem mudanças no protocolo
├── operator/                      # pequeno ajuste de RAII na fábrica
├── file_io/
├── controller/
│   ├── auth_controller.cpp
│   ├── signature_controller.cpp
│   └── web_support.cpp
├── service/
│   ├── signature_service.cpp
│   ├── local_signature_service.cpp
│   └── auth_service.cpp
└── repository/
    └── user_repository.cpp
views/
├── login.html
├── register.html
├── dashboard.html
├── sign.html
└── error.html
public/css/style.css
third_party/cpp-httplib/            # header fixado em v0.56.0, licença e origem
tests/
├── run_tests.sh                    # cenários originais preservados
├── service_tests.cpp
├── web_tests.cpp
├── run_web_tests.sh
└── browser_smoke.py                # teste opcional em navegador real
.vscode/c_cpp_properties.json       # includes e compilador do IntelliSense
main.cpp                           # CLI existente
web_main.cpp                       # composição dos objetos e listen local
Makefile
Dockerfile
```

- **Domínio:** `Operator` possui chaves/certificado; `Agreement` coordena a
  unanimidade; `MultiSignature` produz o pacote. `User` representa somente a
  conta, com hash/salt da senha e um `operatorId`, sem possuir chaves privadas.
- **Services:** `SignatureService` extrai a orquestração do antigo `main.cpp`
  e atende ambas as interfaces. `AuthService` gerencia contas e sessões.
  `LocalSignatureService` valida o PDF, mantém o operador associado e guarda
  o último resultado de cada conta. Nenhum service depende de httplib.
- **Repository:** a interface `UserRepository` permite substituir a
  implementação em memória sem mudar controllers. Uma migração persistente
  também deverá resolver o armazenamento das chaves associadas às contas.
- **Controllers:** recebem dados HTTP, validam o formato básico, verificam a
  sessão, chamam services e respondem com HTML, redirects ou downloads.
  `web_support` reúne cookies, renderização com escape HTML e configuração HTTP.
- **Views:** arquivos estáticos com poucos marcadores de texto escapado. A
  página adicional `error.html` centraliza os erros; `User` não precisa de um
  `.cpp` e não há diretório JavaScript porque os formulários atendem ao fluxo.

### Compilar e executar

Use as mesmas versões de OpenSSL/LibCryptoSEC do CLI. O núcleo,
`signature_service.cpp` e `main.cpp` continuam compilados como **C++98**;
`web_main.cpp`, controllers, autenticação, repository, service local e novos
testes usam **C++11**. Os headers de `User` e das camadas web também exigem
C++11. Não houve migração global nem atualização de OpenSSL/LibCryptoSEC.

```sh
make build web msp-cli
./build/msp-web
# Abra http://127.0.0.1:8080/login; Ctrl+C encerra o servidor.
```

Os alvos geram `build/libmsp-core.a`, `build/pam`, o alias `build/msp-cli` e
`build/msp-web`. `make` sozinho continua compilando apenas o CLI. Execute da
raiz do projeto; de outro diretório, informe o caminho dos assets:

```sh
/caminho/msp/build/msp-web /caminho/msp
```

Se as dependências estiverem em outro prefixo, os parâmetros anteriores do
Makefile continuam disponíveis:

```sh
make build web OPENSSL_PREFIX=/caminho/openssl \
  LIBCRYPTOSEC_PREFIX=/caminho/libcryptosec LIBP11_PREFIX=/caminho/libp11
```

No ambiente deste repositório, o host possui OpenSSL moderno incompatível com
a LibCryptoSEC legada. O build e os testes foram executados no container
`4153446c448c` (imagem `sgc`), com GCC 7.5 e OpenSSL 1.0.2k, em uma cópia
isolada do projeto. Para usar essa imagem com os arquivos atuais e abrir a
interface no navegador do host Linux:

```sh
docker run --rm -it --network host \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/home/sgc/pam" -w /home/sgc/pam sgc \
  sh -c 'make build web && exec ./build/msp-web'
```

O modo de rede do host é necessário aqui porque o processo escuta apenas em
`127.0.0.1`, inclusive dentro de containers; publicar uma porta com `-p` não
alcança esse loopback. Essa receita é para Docker no Linux. O Dockerfile
original agora também copia a camada web e seus assets; se reconstruir a
imagem com outro nome, use esse nome no comando acima.

### Fluxo de POST /sign

```text
Browser: formulário multipart/form-data, campo pdf e cookie de sessão
  → cpp-httplib: limite do corpo HTTP (10 MiB + 64 KiB de envelope)
  → SignatureController: sessão válida, um arquivo, limite de 10 MiB
  → LocalSignatureService: cabeçalho %PDF-x.y e marcador %%EOF
      → operador da conta (criado na primeira assinatura)
      → dois operadores automáticos de demonstração
  → SignatureService::signPdf: define participantes e pins de confiança
  → Agreement: política MSP-POLICY/1 + PDF, unanimidade dos três operadores
  → MultiSignature → LibCryptoSEC/OpenSSL: assinaturas CMS/PKCS#7
  → Agreement::verifyPackage: verifica assinaturas, política e pins
  → LocalSignatureService: guarda pacote e trust da conta em memória
  → Controller: 303 /sign → HTML com mensagem e links de download
```

Rotas disponíveis:

| Método | Caminho | Uso |
| --- | --- | --- |
| GET / POST | `/register` | Cadastro |
| GET / POST | `/login` | Login |
| GET | `/dashboard` | Painel autenticado |
| GET / POST | `/sign` | Formulário e operação de assinatura |
| GET | `/sign/package` | Download autenticado do último `.p7s` |
| GET | `/sign/trust` | Download autenticado do respectivo `.trust` |
| POST | `/logout` | Revoga sessão e remove cookie |

Uploads nunca são gravados usando o nome informado pelo navegador. O MIME e a
extensão não substituem a validação do conteúdo; um PDF válido pode ser aceito
mesmo quando o navegador informa `application/octet-stream`. Um envio inválido
preserva o resultado anterior. Os downloads consultam exclusivamente a conta
resolvida pela sessão, sem aceitar identificadores de outro usuário.

### Testes

```sh
make test       # os cinco cenários originais do CLI
make test-web   # services reais + servidor e cliente HTTP locais
```

O teste HTTP inicia e encerra seu próprio servidor e exige a porta 8080 livre.
Os testes verificam cadastro, senha incorreta, salt/hash, expiração e revogação
de sessões, escape HTML, isolamento por conta, PDF inválido/vazio/incompleto,
limites de upload, assinatura real, pins adulterados, downloads e logout.
`make test-web` não exige Python, curl nem navegador.

O teste opcional `tests/browser_smoke.py` usa Chromium real para verificar
cadastro, login, assinatura, downloads e logout pelos formulários HTML.
Execute-o no host contra uma instância descartável do servidor em
`http://127.0.0.1:8080` (iniciada com o comando Docker acima). Ele cria uma
conta temporária; encerrar o servidor depois do teste elimina esse estado.
Playwright é apenas uma ferramenta opcional de teste, sem dependência para
compilar ou executar a aplicação C++:

```sh
python3 -m venv /tmp/msp-browser-tests
/tmp/msp-browser-tests/bin/pip install playwright
/tmp/msp-browser-tests/bin/python -m playwright install chromium
/tmp/msp-browser-tests/bin/python tests/browser_smoke.py
```

Se já houver Chromium instalado, pode-se omitir a instalação do navegador e
passar `--chromium /caminho/para/chromium` ao script.

### Erro 403 nos formulários e includes no VS Code

A política HTTP é `Referrer-Policy: same-origin`. A opção anterior,
`no-referrer`, fazia o navegador enviar `Origin: null` nos POSTs dos
formulários, rejeitados pela validação de origem. A política atual preserva
a origem das submissões locais; origens externas e `null` continuam sendo
rejeitadas. Esse comportamento é descrito na
[documentação de Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy#effect_on_the_origin_header).
Depois de atualizar, execute `make web` dentro do container, reinicie o
servidor e recarregue `/register` com Ctrl+Shift+R antes de submeter o formulário.
Use exatamente `http://127.0.0.1:8080`, não `localhost` ou um IP da rede.

No VS Code, abra a raiz `msp`, que contém o Makefile e `.vscode`.
`c_cpp_properties.json` declara `/usr/bin/g++`, a raiz do projeto, o diretório
de cpp-httplib e C++11 para a camada web. Os headers do compilador são
descobertos pelo próprio IntelliSense. Após a atualização, use
`Developer: Reload Window`; se necessário, `C/C++: Reset IntelliSense Database`.
Isso configura o editor; o Makefile continua compilando o núcleo em C++98.
Para analisar os arquivos criptográficos legados, o editor também precisa
ter acesso aos headers compatíveis disponíveis no container.

### Limitações intencionais

- Uso educacional local, somente HTTP; o cookie tem identificador aleatório
  de 256 bits, `HttpOnly`, `SameSite=Strict`, `Path=/` e duração de 30 minutos.
  Não tem `Secure`, pois não há HTTPS. A expiração é absoluta no servidor.
- Senhas são derivadas com PBKDF2-HMAC-SHA256, salt aleatório de 128 bits e
  600.000 iterações, com comparação em tempo constante. Contas, sessões,
  chaves e resultados desaparecem ao encerrar o processo. Há limite de 32
  contas e 128 sessões ativas para conter o estado desta demonstração.
- Um único worker e fila limitada serializam as operações, inclusive o acesso
  ao OpenSSL 1.0.2. Isso simplifica o legado, mas uma assinatura ou cliente
  lento pode atrasar outras requisições. Os services não são thread-safe;
  aumentar o número de workers exige revisar sincronização e OpenSSL.
- Há verificações de Host/Origin e cookie SameSite, mas ainda não há tokens
  CSRF, limitação de tentativas de login, recuperação de senha, verificação de
  email, auditoria nem gestão segura/persistente de chaves. As versões
  criptográficas legadas foram preservadas, não modernizadas para produção.
- O upload passa apenas por validação básica do envelope PDF; não há parser
  completo nem análise de malware. Somente o último resultado de cada conta
  é conservado. Baixe o par de arquivos antes de solicitar nova assinatura.
- O servidor controla os três assinantes; os dois coassinantes automáticos
  não representam consentimento de pessoas independentes. Seus certificados
  são recriados por operação; a identidade da conta é reutilizada durante a
  execução. O resultado é CMS com política MSP, não PAdES nem PDF com selo visual.
- O verificador CLI conserva os três IDs fixos da demonstração CLI. Pacotes
  web usam `user-…`, `operator-2` e `operator-3`, são verificados no service ao
  serem produzidos e não são entradas para esse comando CLI de demonstração.
  Uma futura interface de verificação deverá receber participantes e pins
  esperados de uma fonte confiável, como faz `Agreement::verifyPackage`.

Referências das dependências: [cpp-httplib](https://github.com/yhirose/cpp-httplib/tree/v0.56.0)
e [RAND_bytes no OpenSSL 1.0.2](https://docs.openssl.org/1.0.2/man3/RAND_bytes/).
