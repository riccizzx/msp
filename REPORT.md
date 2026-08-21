# Relatório — protocolo de assinaturas múltiplas

## Visão geral

A aplicação simula um acordo unânime entre três operadores. Cada operador
possui um par de chaves RSA de 2048 bits e um certificado X.509 autoassinado
que contém seu identificador. Os certificados autoassinados são uma
simplificação deliberada para a simulação; em produção, seriam emitidos e
validados por uma autoridade certificadora confiável.

O documento de entrada deve ser um PDF. Os operadores se apresentam em uma
ordem definida (`operator-1`, `operator-2` e `operator-3`) e assinam exatamente
os mesmos bytes. Se qualquer operador recusar, o acordo é abortado e nenhum
pacote é produzido. O pacote só pode ser finalizado depois da terceira
assinatura.

## Armazenamento das assinaturas

As assinaturas são armazenadas em um único pacote PKCS#7 `SignedData` com
conteúdo anexado. O pacote contém:

- o PDF original;
- um registro `SignerInfo` para cada operador;
- o certificado X.509 de cada assinante;
- a assinatura RSA/SHA-256 de cada operador.

Esse formato evita arquivos de assinatura separados e liga todas as
assinaturas ao mesmo conteúdo. O arquivo final usa codificação DER e extensão
`.p7s`.

## Geração e verificação

Na geração, a LibCryptoSEC calcula o resumo SHA-256 do PDF e cada operador
assina o valor correspondente usando sua chave privada RSA. A chave privada
nunca é incluída no pacote; apenas o certificado com a chave pública é
armazenado.

Na verificação, `PKCS7_verify` recalcula o resumo do conteúdo anexado e verifica
todos os registros de assinatura com as chaves públicas dos certificados. A
aplicação também exige exatamente os três identificadores esperados, uma única
vez cada. Qualquer alteração no PDF, nas assinaturas ou na estrutura do pacote
faz a verificação falhar.

Como os certificados do protótipo são autoassinados, a verificação demonstra
integridade, posse das chaves privadas e correspondência com os operadores da
simulação; ela não demonstra confiança em uma ICP externa.

## Execução prática

O comando abaixo cria as chaves e certificados, apresenta os operadores em
ordem, coleta as três assinaturas, verifica o resultado e grava o pacote:

```sh
./build/pam sign document/test.pdf build/agreement.p7s
```

Um pacote salvo pode ser verificado novamente com:

```sh
./build/pam verify build/agreement.p7s
```

A recusa de um operador pode ser simulada com:

```sh
./build/pam sign document/test.pdf build/refused.p7s --reject operator-2
```

Nesse caso a aplicação informa que não foi possível entrar em acordo, retorna
o código `2` e não grava um conjunto parcial de assinaturas.
