# Relatório — protocolo de assinaturas múltiplas

## Visão geral

A aplicação simula um acordo unânime entre três operadores. Cada operador
possui um par de chaves RSA de 2048 bits e um certificado X.509 autoassinado
que contém seu identificador (`operator-1`, `operator-2` ou `operator-3`).

Os certificados autoassinados continuam sendo uma simplificação deliberada do
protótipo. Para que a identidade do assinante não seja aceita apenas porque o
próprio certificado afirma possuir determinado identificador, o MSP mantém um
arquivo externo de confiança com o fingerprint SHA-256 esperado de cada
certificado. Em uma implantação real, esse mecanismo deve ser substituído por
validação X.509 contra uma cadeia de certificação confiável, incluindo as
políticas e os mecanismos de revogação aplicáveis.

## Conteúdo efetivamente assinado

O documento de entrada deve ser um PDF. Antes da criação do `SignedData`, o MSP
constrói um payload canônico que contém a política do acordo e o PDF:

```text
MSP-POLICY/1
mode=unanimous
required=3
signer=operator-1
signer=operator-2
signer=operator-3
--PDF--
<bytes do PDF>
```

Dessa forma, cada assinatura autentica não apenas os bytes do documento, mas
também a versão do protocolo, o modo de aprovação, a quantidade exigida de
assinaturas e a lista de participantes. Isso impede que uma assinatura válida
do mesmo PDF seja reutilizada sob uma política de acordo diferente sem que a
assinatura deixe de ser válida.

Se qualquer operador recusar, o acordo é abortado e nenhum pacote é produzido.
O pacote só pode ser finalizado depois da terceira assinatura.

## Armazenamento das assinaturas

As assinaturas são armazenadas em um único pacote PKCS#7 `SignedData` com
conteúdo anexado. O pacote contém:

- o payload MSP com a política e o PDF;
- um registro `SignerInfo` para cada operador;
- o certificado X.509 de cada assinante;
- a assinatura RSA/SHA-256 de cada operador.

O arquivo final usa codificação DER e extensão `.p7s`.

## Verificação

A verificação é dividida em propriedades diferentes:

1. A LibCryptoSEC/OpenSSL verifica criptograficamente os registros de assinatura
   sobre o conteúdo anexado.
2. O conteúdo extraído deve começar exatamente com a política canônica esperada
   e conter um PDF após o marcador `--PDF--`.
3. O MSP enumera os registros `SignerInfo` reais do PKCS#7. A presença de um
   certificado no campo `certificates` não é usada como prova de que esse
   certificado assinou o conteúdo.
4. Cada `SignerInfo` é associado ao seu certificado e deve fornecer exatamente
   um identificador de operador esperado.
5. Deve existir exatamente um `SignerInfo` para cada operador esperado, sem
   duplicações nem signatários extras.
6. O fingerprint SHA-256 do certificado associado a cada `SignerInfo` deve
   coincidir com o valor previamente confiado no arquivo `.trust`.

A distinção entre certificados e `SignerInfo` é importante: em CMS, os
certificados transportados pelo pacote e os registros que representam
assinaturas são estruturas diferentes. Assim, deixar o certificado de um
operador no pacote não é suficiente para satisfazer a política caso o
`SignerInfo` desse operador seja removido.

## Arquivo de confiança

Ao gerar `build/agreement.p7s`, o protótipo também gera:

```text
build/agreement.p7s.trust
```

O formato é simples:

```text
MSP-TRUST/1
operator-1=<SHA-256 do certificado>
operator-2=<SHA-256 do certificado>
operator-3=<SHA-256 do certificado>
```

Esse arquivo deve ser tratado como um trust store externo: se um atacante puder
substituir simultaneamente o PKCS#7 e o arquivo `.trust`, o pinning deixa de
fornecer identidade confiável. O objetivo desta etapa é tornar explícita a
âncora de confiança do protótipo, e não substituir uma ICP completa.

## Execução prática

Criar o acordo:

```sh
./build/pam sign document/test.pdf build/agreement.p7s
```

Verificar novamente o pacote e os fingerprints confiados:

```sh
./build/pam verify build/agreement.p7s
```

Simular a recusa de um operador:

```sh
./build/pam sign document/test.pdf build/refused.p7s --reject operator-2
```

Nesse caso a aplicação retorna o código `2` e não grava um conjunto parcial de
assinaturas nem um arquivo de confiança.

## Escopo criptográfico

O MSP implementa co-assinaturas CMS com uma política de unanimidade na camada
da aplicação. Apesar do nome "multi-signature", o protótipo não implementa
criptografia de limiar, agregação de chaves ou uma única assinatura coletiva
como ocorre em protocolos como FROST ou MuSig.
