# gocrypt (PoC)

A minimal proof of concept showing how to emit OpenPGP-encrypted messages compatible with **RFC 9580 (IETF, v6)** and with the **LibrePGP draft (Tag 20 OCBED)**. This PoC focuses on encryption and ASCII armor. It supports:

- v6 PKESK with X25519 or X448 (Concat-KDF + AES-KW)
- v2 SEIPD (Tag 18) using AEAD=OCB
- LibrePGP OCBED (Tag 20) using AEAD=OCB
- Armor (`--armor`) enabled by default

> ⚠️ This is a teaching-oriented PoC. It does **not** implement full key/cert parsing, signature verification, recipient preference negotiation, multi-chunk AEAD, or full KDF parameter encoding. See code comments for what to harden next before production use.

## Build

```bash
cd gocrypt
go mod tidy
go build ./cmd/gocrypt
```

## Usage

### Generate a key pair

```bash
./gocrypt keygen -pkalg=x448 -armor -out keys/x448
```

This creates `keys/x448.pub.asc` and `keys/x448.key.asc`. The `.asc` files are
OpenPGP-armored Tag 6/Tag 5 packets that carry the raw X448 material expected
by the CLI.

### Encrypt using a public key file

```bash
echo 'hello' | ./gocrypt \
  -format=rfc9580 \
  -sym=aes256 \
  -pubfile=keys/x448.pub.asc \
  -out msg.asc
```

`-pubfile` accepts either the armored output shown above or the raw base64
(`keys/x448.pub`) produced when `-armor` is omitted. The tool automatically
detects whether the key is X25519 or X448; use `-pkalg` only if you need to
override detection.

### Decrypt using the matching private key

```bash
./gocrypt decrypt \
  -keyfile=keys/x448.key.asc \
  -out plaintext.txt \
  msg.asc
```

`-keyfile` mirrors `-pubfile` and supports `.key.asc` as well as the raw
`keys/x448.key` file. The command writes the decrypted message to `stdout` when
`-out` is omitted.

If you already have the raw base64 strings, the original `-pk=<BASE64>` flag is
still available for both encryption (public key) and `decrypt` (private key);
pass `-pkalg` to choose between X25519 and X448 in that mode.

## Notes

- RFC 9580 references:
  - v6 PKESK, ECDH KDF and AES-KW (§5.1, §11.4, §11.5).
  - v2 SEIPD (AEAD-OCB) with HKDF, salt, chunk size, and final tag on empty string (§5.13.2).
- LibrePGP draft references:
  - OCB Encrypted Data Packet (Tag 20), AAD layout and final tag (§5.16).
