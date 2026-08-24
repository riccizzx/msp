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
