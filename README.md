# Multi-signature agreement prototype

A small C++98 simulation of the LabSEC 2020 digital-signature challenge. Three
demo operators each receive an RSA-2048 key pair and a self-signed certificate.
An agreement succeeds only when every operator signs the same PDF.

The signatures, signer certificates, and PDF are stored together in one
attached PKCS#7 `SignedData` file encoded as DER.

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

Verify a stored agreement again:

```sh
./build/pam verify build/agreement.p7s
```

Simulate an operator refusing to sign. Exit status `2` means no agreement, and
no package is written:

```sh
./build/pam sign document/test.pdf build/refused.p7s --reject operator-2
```

Run all success, refusal, and tampering scenarios:

```sh
make test
```

See [REPORT.md](REPORT.md) for the protocol and design explanation.
