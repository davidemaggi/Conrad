# PKCS#11 / HSM

Conrad can keep CA private keys inside a PKCS#11 token (YubiHSM 2, Nitrokey HSM, SoftHSM, a cloud HSM, …) so they never touch the disk. Use the `-pkcs11` image or build with `CGO_ENABLED=1 go build -tags pkcs11 ./cmd/conrad`. The default static build does not include it.

## Configuration

```sh
CONRAD_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
CONRAD_PKCS11_TOKEN_LABEL=conrad
CONRAD_PKCS11_PIN_FILE=/run/secrets/hsm_pin   # optional: unlock at start
```

With PKCS#11 enabled, the **PIN replaces the passphrase**: you enter it during setup and to unlock. Keys are generated on the token, labelled `conrad-<name>`, and are not extractable. Supported algorithms: ECDSA P-256 and P-384, RSA 2048, 3072 and 4096. Importing an existing key is not supported in this mode.

## Docker

Mount the vendor library and, if needed, its device or socket:

```yaml
services:
  conrad:
    image: ghcr.io/davidemaggi/conrad:latest-pkcs11
    environment:
      CONRAD_PKCS11_MODULE: /hsm/libvendor-pkcs11.so
      CONRAD_PKCS11_TOKEN_LABEL: conrad
      CONRAD_PKCS11_PIN_FILE: /run/secrets/hsm_pin
    volumes:
      - /opt/vendor/lib:/hsm:ro
      - conrad-data:/data
```

## Trying it with SoftHSM

```sh
softhsm2-util --init-token --free --label conrad --pin 1234 --so-pin 1234
```

The tests run against SoftHSM: `docker build -f deploy/Dockerfile.pkcs11 --target test .`
