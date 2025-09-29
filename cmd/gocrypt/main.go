package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"example.com/gocrypt/pkg/armor"
	"example.com/gocrypt/pkg/pgp"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
)

var outPath string

func writeOut(b []byte) error {
	if outPath == "" {
		_, err := os.Stdout.Write(b)
		return err
	}
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(b)
	return err
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func fatalf(format string, a ...interface{}) { fmt.Fprintf(os.Stderr, format+"\n", a...); os.Exit(1) }

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		keygen(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "decrypt" {
		decrypt(os.Args[2:])
		return
	}
	encrypt(os.Args[1:])
}

func encrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	var outArmor bool
	var format string
	var sym string
	var pkalg string
	var pkb64 string
	fs.BoolVar(&outArmor, "armor", false, "ASCII armor output (default: binary)")
	fs.StringVar(&format, "format", "rfc9580", "container format: rfc9580|librepgp")
	fs.StringVar(&sym, "sym", "aes256", "symmetric: aes128|aes192|aes256")
	fs.StringVar(&pkalg, "pkalg", "x448", "recipient alg: x25519|x448")
	fs.StringVar(&pkb64, "pk", "", "recipient public key (raw) base64")
	fs.StringVar(&outPath, "out", "", "output file (default: stdout)")
	fatalIf(fs.Parse(args))

	if pkb64 == "" {
		fatalf("missing -pk")
	}

	// Read plaintext: positional file or stdin
	var plaintext []byte
	if rest := fs.Args(); len(rest) > 0 && rest[0] != "-" {
		inFile := rest[0]
		data, err := os.ReadFile(inFile)
		fatalIf(err)
		plaintext = data
		if outPath == "" {
			if outArmor {
				outPath = inFile + ".asc"
			} else {
				outPath = inFile + ".pgp"
			}
		}
	} else {
		data, err := io.ReadAll(os.Stdin)
		fatalIf(err)
		plaintext = data
	}

	// Decode recipient public key
	pubRaw, err := base64.StdEncoding.DecodeString(pkb64)
	fatalIf(err)

	// Symmetric algorithm and session key
	var symID int
	var cekLen int
	switch strings.ToLower(sym) {
	case "aes128":
		symID = pgp.SYM_AES128
		cekLen = 16
	case "aes192":
		symID = pgp.SYM_AES192
		cekLen = 24
	case "aes256":
		symID = pgp.SYM_AES256
		cekLen = 32
	default:
		fatalf("unsupported -sym: %s", sym)
	}
	cek := make([]byte, cekLen)
	_, err = rand.Read(cek)
	fatalIf(err)

	// PKESK (v6) for X25519/X448
	var pkesk []byte
	switch strings.ToLower(pkalg) {
	case "x25519":
		if len(pubRaw) != 32 {
			fatalf("x25519 pub must be 32 bytes (raw base64)")
		}
		pkesk, err = pgp.BuildPKESKv6_X(pgp.PKALG_X25519, pubRaw, cek)
	case "x448":
		if len(pubRaw) != 56 {
			fatalf("x448 pub must be 56 bytes (raw base64)")
		}
		pkesk, err = pgp.BuildPKESKv6_X(pgp.PKALG_X448, pubRaw, cek)
	default:
		fatalf("unsupported -pkalg: %s", pkalg)
	}
	fatalIf(err)

	// Content packet
	const chunkBits = 16 // 4 MiB chunks
	var content []byte
	if strings.ToLower(format) == "rfc9580" {
		content, err = pgp.BuildSEIPDv2OCB(symID, chunkBits, cek, plaintext)
	} else if strings.ToLower(format) == "librepgp" {
		content, err = pgp.BuildOCBED(symID, chunkBits, cek, plaintext)
	} else {
		fatalf("unsupported -format: %s", format)
	}
	fatalIf(err)

	container := append(pkesk, content...)

	// Output
	if outArmor {
		var arm []byte
		if strings.ToLower(format) == "rfc9580" {
			arm = armor.ArmorPGPMessageNoCRC(container, nil)
		} else {
			arm = armor.ArmorPGPMessage(container, nil)
		}
		fatalIf(writeOut(arm))
	} else {
		fatalIf(writeOut(container))
	}
}

func decrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	var format string
	var pkalg string
	var pkb64 string
	fs.StringVar(&format, "format", "rfc9580", "container format")
	fs.StringVar(&pkalg, "pkalg", "x448", "recipient alg: x25519|x448")
	fs.StringVar(&pkb64, "pk", "", "recipient private key (raw) base64")
	fs.StringVar(&outPath, "out", "", "output file (default: stdout)")
	fatalIf(fs.Parse(args))

	// Input: positional filename or stdin
	var inData []byte
	if rest := fs.Args(); len(rest) > 0 && rest[0] != "-" {
		b, err := os.ReadFile(rest[0])
		fatalIf(err)
		inData = b
	} else {
		b, err := io.ReadAll(os.Stdin)
		fatalIf(err)
		inData = b
	}
	if pkb64 == "" {
		fatalf("missing -pk (private key base64)")
	}
	priv, err := base64.StdEncoding.DecodeString(pkb64)
	fatalIf(err)

	msg := inData
	if dec, ok := armor.DecodePGPMessage(msg); ok {
		msg = dec
	}

	tag, body, rest, err := pgp.ReadPacket(msg)
	fatalIf(err)
	if tag != 1 {
		fatalf("first packet is not PKESK")
	}
	cek, err := pgp.DecodePKESK_X(body, pkalg, priv)
	fatalIf(err)

	tag2, body2, _, err := pgp.ReadPacket(rest)
	fatalIf(err)
	switch tag2 {
	case 18:
		pt, err := pgp.DecryptSEIPDv2OCB(body2, cek)
		fatalIf(err)
		fatalIf(writeOut(pt))
	case 20:
		pt, err := pgp.DecryptOCBED(body2, cek)
		fatalIf(err)
		fatalIf(writeOut(pt))
	default:
		fatalf("unsupported data tag: %d", tag2)
	}
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	var algo string
	var out string
	var armorOut bool
	fs.StringVar(&algo, "pkalg", "x448", "key algorithm: x25519|x448")
	fs.StringVar(&out, "out", "", "file prefix to write keys (*.pub.asc / *.key.asc and/or *.pub / *.key)")
	fs.BoolVar(&armorOut, "armor", false, "print OpenPGP Key Block armor to stdout (default prints base64 raw keys)")
	fatalIf(fs.Parse(args))

	switch strings.ToLower(algo) {
	case "x25519":
		var sk, pk x25519.Key
		_, err := rand.Read(sk[:])
		fatalIf(err)
		x25519.KeyGen(&pk, &sk)
		pubB64 := base64.StdEncoding.EncodeToString(pk[:])
		privB64 := base64.StdEncoding.EncodeToString(sk[:])
		if armorOut {
			pubPkt, err := pgp.BuildPublicKeyV6(pgp.PKALG_X25519, pk[:])
			fatalIf(err)
			secPkt, err := pgp.BuildSecretKeyV6(pgp.PKALG_X25519, pk[:], sk[:])
			fatalIf(err)
			armPub := armor.ArmorEncode("PGP PUBLIC KEY BLOCK", pubPkt, nil)
			armSec := armor.ArmorEncode("PGP PRIVATE KEY BLOCK", secPkt, nil)
			if out == "" {
				os.Stdout.Write(armPub)
				os.Stdout.Write(armSec)
			}
			if out != "" {
				writeKeyArmor(out, armPub, armSec)
				writeKeyFiles(out, pubB64, privB64)
			}
		} else {
			if out == "" {
				fmt.Printf("PUBLIC=%s\nPRIVATE=%s\n", pubB64, privB64)
			}
			if out != "" {
				writeKeyFiles(out, pubB64, privB64)
			}
		}
	case "x448":
		var sk, pk x448.Key
		_, err := rand.Read(sk[:])
		fatalIf(err)
		x448.KeyGen(&pk, &sk)
		pubB64 := base64.StdEncoding.EncodeToString(pk[:])
		privB64 := base64.StdEncoding.EncodeToString(sk[:])
		if armorOut {
			pubPkt, err := pgp.BuildPublicKeyV6(pgp.PKALG_X448, pk[:])
			fatalIf(err)
			secPkt, err := pgp.BuildSecretKeyV6(pgp.PKALG_X448, pk[:], sk[:])
			fatalIf(err)
			armPub := armor.ArmorEncode("PGP PUBLIC KEY BLOCK", pubPkt, nil)
			armSec := armor.ArmorEncode("PGP PRIVATE KEY BLOCK", secPkt, nil)
			if out == "" {
				os.Stdout.Write(armPub)
				os.Stdout.Write(armSec)
			}
			if out != "" {
				writeKeyArmor(out, armPub, armSec)
				writeKeyFiles(out, pubB64, privB64)
			}
		} else {
			if out == "" {
				fmt.Printf("PUBLIC=%s\nPRIVATE=%s\n", pubB64, privB64)
			}
			if out != "" {
				writeKeyFiles(out, pubB64, privB64)
			}
		}
	default:
		fatalf("unsupported pkalg: %s", algo)
	}
}
func writeKeyFiles(prefix, pubB64, privB64 string) {
	_ = os.MkdirAll(filepath.Dir(prefix), 0o755)
	_ = os.WriteFile(prefix+".pub", []byte(pubB64+"\n"), 0644)
	f := prefix + ".key"
	fd, err := os.OpenFile(f, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	fatalIf(err)
	defer fd.Close()
	_, err = fd.Write([]byte(privB64 + "\n"))
	fatalIf(err)
}

func writeKeyArmor(prefix string, pubAsc, secAsc []byte) {
	_ = os.MkdirAll(filepath.Dir(prefix), 0o755)
	_ = os.WriteFile(prefix+".pub.asc", pubAsc, 0644)
	_ = os.WriteFile(prefix+".key.asc", secAsc, 0600)
}
