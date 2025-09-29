# gocrypt (PoC)

A minimal proof of concept showing how to emit OpenPGP-encrypted messages compatible with **RFC 9580 (IETF, v6)** and with the **LibrePGP draft (Tag 20 OCBED)**. This PoC focuses on encryption and ASCII armor. It supports:

- v6 PKESK with X25519 or X448 (Concat-KDF + AES-KW)
- v2 SEIPD (Tag 18) using AEAD=OCB
- LibrePGP OCBED (Tag 20) using AEAD=OCB
- Armor (`-a/--armor`) enabled by default

> ⚠️ This is a teaching-oriented PoC. It does **not** implement full key/cert parsing, signature verification, recipient preference negotiation, multi-chunk AEAD, or full KDF parameter encoding. See code comments for what to harden next before production use.

## Build

```bash
cd gocrypt
go mod tidy
go build ./cmd/gocrypt
```

## Usage

Recipient key is passed as raw base64 of X25519/X448 public key bytes (not a full OpenPGP certificate):

```bash
# Example (uses random message; replace PK with actual raw public key)
echo 'hello' | ./gocrypt -format=ietf -pkalg=x448 -pk=<BASE64> -sym=aes256 -out msg.asc
```

## Notes

- RFC 9580 references:
  - v6 PKESK, ECDH KDF and AES-KW (§5.1, §11.4, §11.5).
  - v2 SEIPD (AEAD-OCB) with HKDF, salt, chunk size, and final tag on empty string (§5.13.2).
- LibrePGP draft references:
  - OCB Encrypted Data Packet (Tag 20), AAD layout and final tag (§5.16).
