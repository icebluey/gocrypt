package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"example.com/gocrypt/pkg/armor"
	"example.com/gocrypt/pkg/crypto/kem/mlkem"
	"example.com/gocrypt/pkg/pgp"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
)

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func fatalf(format string, a ...interface{}) { fmt.Fprintf(os.Stderr, format+"\n", a...); os.Exit(1) }

type stringFlag struct {
	value string
	set   bool
}

func (s *stringFlag) String() string { return s.value }

func (s *stringFlag) Set(v string) error {
	s.value = v
	s.set = true
	return nil
}

func parsePKAlg(name string) (int, error) {
	switch strings.ToLower(name) {
	case "x25519":
		return pgp.PKALG_X25519, nil
	case "x448":
		return pgp.PKALG_X448, nil
	default:
		return 0, fmt.Errorf("unsupported -pkalg: %s", name)
	}
}

func pkAlgName(alg int) string {
	switch alg {
	case pgp.PKALG_X25519:
		return "x25519"
	case pgp.PKALG_X448:
		return "x448"
	default:
		return fmt.Sprintf("alg-%d", alg)
	}
}

func loadPublicKeyFromFile(path string) ([]byte, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("public key file %s is empty", path)
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		blockType, _, raw, ok := armor.ArmorDecode(data)
		if !ok || blockType != "PGP PUBLIC KEY BLOCK" {
			return nil, 0, fmt.Errorf("%s: expected PGP PUBLIC KEY BLOCK", path)
		}
		data = raw
	}
	if len(data) > 0 && (data[0]&0xC0) == 0xC0 {
		alg, pub, err := pgp.ParsePublicKeyV6(data)
		if err != nil {
			return nil, 0, err
		}
		return append([]byte(nil), pub...), alg, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(data)))
	if err != nil {
		return nil, 0, fmt.Errorf("invalid public key encoding in %s: %w", path, err)
	}
	switch len(decoded) {
	case 32:
		return decoded, pgp.PKALG_X25519, nil
	case 56:
		return decoded, pgp.PKALG_X448, nil
	default:
		return nil, 0, fmt.Errorf("public key length %d in %s not recognized", len(decoded), path)
	}
}

func loadPrivateKeyFromFile(path string) ([]byte, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("private key file %s is empty", path)
	}
	if bytes.Contains(data, []byte("-----BEGIN")) {
		blockType, _, raw, ok := armor.ArmorDecode(data)
		if !ok || blockType != "PGP PRIVATE KEY BLOCK" {
			return nil, 0, fmt.Errorf("%s: expected PGP PRIVATE KEY BLOCK", path)
		}
		data = raw
	}
	if len(data) > 0 && (data[0]&0xC0) == 0xC0 {
		alg, _, priv, err := pgp.ParseSecretKeyV6(data)
		if err != nil {
			return nil, 0, err
		}
		return append([]byte(nil), priv...), alg, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(data)))
	if err != nil {
		return nil, 0, fmt.Errorf("invalid private key encoding in %s: %w", path, err)
	}
	switch len(decoded) {
	case 32:
		return decoded, pgp.PKALG_X25519, nil
	case 56:
		return decoded, pgp.PKALG_X448, nil
	default:
		return nil, 0, fmt.Errorf("private key length %d in %s not recognized", len(decoded), path)
	}
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "keygen":
			keygen(os.Args[2:])
			return
		case "decrypt":
			decrypt(os.Args[2:])
			return
		case "kemgen":
			kemgen(os.Args[2:])
			return
		case "kemwrap":
			kemwrap(os.Args[2:])
			return
		case "kemunwrap":
			kemunwrap(os.Args[2:])
			return
		}
	}
	encrypt(os.Args[1:])
}

func encrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	var outArmor bool
	var format string
	var sym string
	var pkb64 string
	var pubFile string
	var outPath string
	var pkalg stringFlag
	pkalg.value = "x448"
	fs.BoolVar(&outArmor, "armor", false, "ASCII armor output (default: binary)")
	fs.StringVar(&format, "format", "rfc9580", "container format: rfc9580|librepgp")
	fs.StringVar(&sym, "sym", "aes256", "symmetric: aes128|aes192|aes256")
	fs.Var(&pkalg, "pkalg", "recipient alg: x25519|x448 (used with -pk or to override autodetect)")
	fs.StringVar(&pkb64, "pk", "", "recipient public key (raw) base64")
	fs.StringVar(&pubFile, "pubfile", "", "recipient public key file (.pub|.pub.asc)")
	fs.StringVar(&outPath, "out", "", "output file (default: stdout)")
	fatalIf(fs.Parse(args))

	if pkb64 != "" && pubFile != "" {
		fatalf("use either -pk or -pubfile")
	}
	if pkb64 == "" && pubFile == "" {
		fatalf("missing -pk or -pubfile")
	}

	var input io.Reader
	var inputCloser io.Closer
	if rest := fs.Args(); len(rest) > 0 && rest[0] != "-" {
		f, err := os.Open(rest[0])
		fatalIf(err)
		input = f
		inputCloser = f
		if outPath == "" {
			if outArmor {
				outPath = rest[0] + ".asc"
			} else {
				outPath = rest[0] + ".pgp"
			}
		}
	} else {
		input = os.Stdin
	}
	if inputCloser != nil {
		defer inputCloser.Close()
	}
	plainReader := bufio.NewReader(input)

	var pubRaw []byte
	var pkAlgID int
	var err error
	if pkb64 != "" {
		pubRaw, err = base64.StdEncoding.DecodeString(pkb64)
		fatalIf(err)
		pkAlgID, err = parsePKAlg(pkalg.value)
		fatalIf(err)
	} else {
		pubRaw, pkAlgID, err = loadPublicKeyFromFile(pubFile)
		fatalIf(err)
		if pkalg.set {
			want, err := parsePKAlg(pkalg.value)
			fatalIf(err)
			if want != pkAlgID {
				fatalf("public key algorithm mismatch: file is %s but -pkalg=%s", pkAlgName(pkAlgID), pkalg.value)
			}
			pkAlgID = want
		}
	}

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

	var pkesk []byte
	switch pkAlgID {
	case pgp.PKALG_X25519:
		if len(pubRaw) != 32 {
			fatalf("x25519 pub must be 32 bytes (raw base64)")
		}
		pkesk, err = pgp.BuildPKESKv6_X(pgp.PKALG_X25519, pubRaw, cek)
	case pgp.PKALG_X448:
		if len(pubRaw) != 56 {
			fatalf("x448 pub must be 56 bytes (raw base64)")
		}
		pkesk, err = pgp.BuildPKESKv6_X(pgp.PKALG_X448, pubRaw, cek)
	default:
		fatalf("unsupported public key algorithm: %d", pkAlgID)
	}
	fatalIf(err)

	var outFile *os.File
	var outWriter io.Writer
	if outPath == "" {
		outWriter = os.Stdout
	} else {
		outFile, err = os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		fatalIf(err)
		outWriter = outFile
	}

	var armorWriter *armor.MessageWriter
	formatLower := strings.ToLower(format)
	if outArmor {
		includeCRC := formatLower != "rfc9580"
		armorWriter, err = armor.NewPGPMessageWriter(outWriter, nil, includeCRC)
		fatalIf(err)
		outWriter = armorWriter
	}

	tmp, err := os.CreateTemp("", "gocrypt-content-*.bin")
	fatalIf(err)
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	const chunkBits = 22
	var bodyLen int64
	var contentTag byte
	switch formatLower {
	case "rfc9580":
		bodyLen, err = pgp.WriteSEIPDv2OCBStream(tmp, symID, chunkBits, cek, plainReader)
		contentTag = 18
	case "librepgp":
		bodyLen, err = pgp.WriteOCBEDStream(tmp, symID, chunkBits, cek, plainReader)
		contentTag = 20
	default:
		fatalf("unsupported -format: %s", format)
	}
	fatalIf(err)

	_, err = tmp.Seek(0, io.SeekStart)
	fatalIf(err)
	if bodyLen > int64(math.MaxInt) {
		fatalf("content too large")
	}

	if _, err := outWriter.Write(pkesk); err != nil {
		fatalIf(err)
	}
	fatalIf(pgp.WritePacketHeader(outWriter, contentTag, int(bodyLen)))
	if _, err := io.CopyN(outWriter, tmp, bodyLen); err != nil {
		fatalIf(err)
	}

	if armorWriter != nil {
		fatalIf(armorWriter.Close())
	}
	if outFile != nil {
		fatalIf(outFile.Close())
	}
}

func decrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	var pkb64 string
	var keyFile string
	var outPath string
	var pkalg stringFlag
	pkalg.value = "x448"
	fs.StringVar(new(string), "format", "rfc9580", "container format")
	fs.Var(&pkalg, "pkalg", "recipient alg: x25519|x448 (used with -pk or to override autodetect)")
	fs.StringVar(&pkb64, "pk", "", "recipient private key (raw) base64")
	fs.StringVar(&keyFile, "keyfile", "", "recipient private key file (.key|.key.asc)")
	fs.StringVar(&outPath, "out", "", "output file (default: stdout)")
	fatalIf(fs.Parse(args))

	if pkb64 != "" && keyFile != "" {
		fatalf("use either -pk or -keyfile")
	}
	if pkb64 == "" && keyFile == "" {
		fatalf("missing -pk (private key base64) or -keyfile")
	}

	var input io.Reader
	var inputCloser io.Closer
	if rest := fs.Args(); len(rest) > 0 && rest[0] != "-" {
		f, err := os.Open(rest[0])
		fatalIf(err)
		input = f
		inputCloser = f
	} else {
		input = os.Stdin
	}
	if inputCloser != nil {
		defer inputCloser.Close()
	}

	reader := bufio.NewReader(input)
	var armorTmp *os.File
	if looksLikeArmor(reader) {
		tmp, err := decodeArmorToTemp(reader)
		fatalIf(err)
		armorTmp = tmp
		reader = bufio.NewReader(tmp)
	}
	if armorTmp != nil {
		defer func() {
			armorTmp.Close()
			os.Remove(armorTmp.Name())
		}()
	}

	var priv []byte
	var pkAlgID int
	var err error
	if pkb64 != "" {
		priv, err = base64.StdEncoding.DecodeString(pkb64)
		fatalIf(err)
		pkAlgID, err = parsePKAlg(pkalg.value)
		fatalIf(err)
	} else {
		priv, pkAlgID, err = loadPrivateKeyFromFile(keyFile)
		fatalIf(err)
		if pkalg.set {
			want, err := parsePKAlg(pkalg.value)
			fatalIf(err)
			if want != pkAlgID {
				fatalf("private key algorithm mismatch: file is %s but -pkalg=%s", pkAlgName(pkAlgID), pkalg.value)
			}
			pkAlgID = want
		}
	}

	tag, bodyLen, err := pgp.ReadPacketHeader(reader)
	fatalIf(err)
	if tag != 1 {
		fatalf("first packet is not PKESK")
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(reader, body); err != nil {
		fatalIf(err)
	}
	switch pkAlgID {
	case pgp.PKALG_X25519:
		if len(priv) != 32 {
			fatalf("x25519 private key must be 32 bytes (raw base64)")
		}
	case pgp.PKALG_X448:
		if len(priv) != 56 {
			fatalf("x448 private key must be 56 bytes (raw base64)")
		}
	default:
		fatalf("unsupported private key algorithm: %d", pkAlgID)
	}

	cek, err := pgp.DecodePKESK_X(body, pkAlgName(pkAlgID), priv)
	fatalIf(err)

	tag2, bodyLen2, err := pgp.ReadPacketHeader(reader)
	fatalIf(err)
	limit := io.LimitReader(reader, int64(bodyLen2))

	var outFile *os.File
	var outWriter io.Writer
	if outPath == "" {
		outWriter = os.Stdout
	} else {
		outFile, err = os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		fatalIf(err)
		outWriter = outFile
	}

	switch tag2 {
	case 18:
		fatalIf(pgp.DecryptSEIPDv2OCBStream(outWriter, limit, int64(bodyLen2), cek))
	case 20:
		fatalIf(pgp.DecryptOCBEDStream(outWriter, limit, int64(bodyLen2), cek))
	default:
		fatalf("unsupported data tag: %d", tag2)
	}

	if outFile != nil {
		fatalIf(outFile.Close())
	}
}

func kemgen(args []string) {
	fs := flag.NewFlagSet("kemgen", flag.ExitOnError)
	var scheme string
	var out string
	fs.StringVar(&scheme, "scheme", "mlkem768", "KEM scheme: mlkem768|mlkem1024")
	fs.StringVar(&out, "out", "", "file prefix to write keys (*.pub / *.key)")
	fatalIf(fs.Parse(args))

	scheme = strings.ToLower(scheme)
	pub, priv, err := mlkem.Generate(scheme)
	fatalIf(err)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	privB64 := base64.StdEncoding.EncodeToString(priv)
	if out == "" {
		fmt.Printf("SCHEME=%s\nPUBLIC=%s\nPRIVATE=%s\n", scheme, pubB64, privB64)
		return
	}
	writeKeyFiles(out, pubB64, privB64)
}

func kemwrap(args []string) {
	fs := flag.NewFlagSet("kemwrap", flag.ExitOnError)
	var scheme string
	var pubB64 string
	var pubFile string
	var cekB64 string
	var cekSize int
	fs.StringVar(&scheme, "scheme", "mlkem768", "KEM scheme: mlkem768|mlkem1024")
	fs.StringVar(&pubB64, "pub", "", "recipient ML-KEM public key (base64)")
	fs.StringVar(&pubFile, "pubfile", "", "recipient ML-KEM public key file (base64)")
	fs.StringVar(&cekB64, "cek", "", "content-encryption key (base64); if omitted, random bytes are generated")
	fs.IntVar(&cekSize, "ceksize", 32, "random CEK length in bytes when -cek is omitted")
	fatalIf(fs.Parse(args))

	scheme = strings.ToLower(scheme)
	pub, err := decodeBase64Input(pubB64, "-pub", pubFile, "-pubfile")
	fatalIf(err)

	var cek []byte
	if cekB64 != "" {
		cek, err = base64.StdEncoding.DecodeString(cekB64)
		if err != nil {
			fatalf("invalid -cek base64: %v", err)
		}
	} else {
		if cekSize <= 0 {
			fatalf("-ceksize must be positive")
		}
		cek = make([]byte, cekSize)
		_, err = rand.Read(cek)
		fatalIf(err)
	}

	recip, wrapped, kemCT, err := mlkem.Wrap(scheme, pub, cek)
	fatalIf(err)
	fmt.Printf("SCHEME=%s\nWRAPPED=%s\nKEMCT=%s\n", recip, base64.StdEncoding.EncodeToString(wrapped), base64.StdEncoding.EncodeToString(kemCT))
	if cekB64 == "" {
		fmt.Printf("CEK=%s\n", base64.StdEncoding.EncodeToString(cek))
	}
}

func kemunwrap(args []string) {
	fs := flag.NewFlagSet("kemunwrap", flag.ExitOnError)
	var scheme string
	var privB64 string
	var privFile string
	var wrappedB64 string
	var wrappedFile string
	var kemCTB64 string
	var kemCTFile string
	fs.StringVar(&scheme, "scheme", "mlkem768", "KEM scheme: mlkem768|mlkem1024")
	fs.StringVar(&privB64, "priv", "", "recipient ML-KEM private key (base64)")
	fs.StringVar(&privFile, "privfile", "", "recipient ML-KEM private key file (base64)")
	fs.StringVar(&wrappedB64, "wrapped", "", "wrapped CEK bytes (base64)")
	fs.StringVar(&wrappedFile, "wrappedfile", "", "wrapped CEK file (base64)")
	fs.StringVar(&kemCTB64, "kemct", "", "ML-KEM ciphertext (base64)")
	fs.StringVar(&kemCTFile, "kemctfile", "", "ML-KEM ciphertext file (base64)")
	fatalIf(fs.Parse(args))

	scheme = strings.ToLower(scheme)
	priv, err := decodeBase64Input(privB64, "-priv", privFile, "-privfile")
	fatalIf(err)
	wrapped, err := decodeBase64Input(wrappedB64, "-wrapped", wrappedFile, "-wrappedfile")
	fatalIf(err)
	kemCT, err := decodeBase64Input(kemCTB64, "-kemct", kemCTFile, "-kemctfile")
	fatalIf(err)

	cek, err := mlkem.Unwrap(scheme, priv, wrapped, kemCT)
	fatalIf(err)
	fmt.Printf("CEK=%s\n", base64.StdEncoding.EncodeToString(cek))
}

func decodeBase64Input(inline string, inlineFlag string, file string, fileFlag string) ([]byte, error) {
	if inline != "" && file != "" {
		return nil, fmt.Errorf("use either %s or %s", inlineFlag, fileFlag)
	}
	if inline == "" && file == "" {
		return nil, fmt.Errorf("missing %s or %s", inlineFlag, fileFlag)
	}
	if inline != "" {
		b, err := base64.StdEncoding.DecodeString(inline)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 for %s: %w", inlineFlag, err)
		}
		return b, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", file)
	}
	b, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in %s: %w", file, err)
	}
	return b, nil
}

func looksLikeArmor(r *bufio.Reader) bool {
	peek, err := r.Peek(64)
	if err != nil && err != io.EOF {
		return false
	}
	trimmed := strings.TrimSpace(string(peek))
	return strings.HasPrefix(trimmed, "-----BEGIN ")
}

func decodeArmorToTemp(r *bufio.Reader) (*os.File, error) {
	tmp, err := os.CreateTemp("", "gocrypt-armor-*.bin")
	if err != nil {
		return nil, err
	}
	cleanup := func(e error) (*os.File, error) {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, e
	}

	// locate begin line
	var blockType string
	for {
		line, err := readLine(r)
		if err != nil {
			return cleanup(err)
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "-----BEGIN ") && strings.HasSuffix(trimmed, "-----") {
			blockType = strings.TrimSuffix(strings.TrimPrefix(trimmed, "-----BEGIN "), "-----")
			if blockType != "PGP MESSAGE" {
				return cleanup(fmt.Errorf("unexpected armor block: %s", blockType))
			}
			break
		}
	}

	// skip headers
	for {
		line, err := readLine(r)
		if err != nil {
			return cleanup(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	crc := uint32(0xB704CE)
	var crcExpected []byte
	hasCRC := false

	for {
		line, err := readLine(r)
		if err != nil {
			return cleanup(err)
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "-----END ") {
			endType := strings.TrimSuffix(strings.TrimPrefix(trimmed, "-----END "), "-----")
			if endType != blockType {
				return cleanup(fmt.Errorf("mismatched armor end: %s", endType))
			}
			break
		}
		if trimmed[0] == '=' {
			if hasCRC {
				return cleanup(fmt.Errorf("multiple armor CRC lines"))
			}
			buf := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)-1))
			n, err := base64.StdEncoding.Decode(buf, []byte(trimmed[1:]))
			if err != nil {
				return cleanup(fmt.Errorf("invalid armor crc: %w", err))
			}
			if n != 3 {
				return cleanup(fmt.Errorf("invalid armor crc length"))
			}
			crcExpected = buf[:n]
			hasCRC = true
			continue
		}
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
		n, err := base64.StdEncoding.Decode(decoded, []byte(trimmed))
		if err != nil {
			return cleanup(fmt.Errorf("invalid armor data: %w", err))
		}
		decoded = decoded[:n]
		for _, b := range decoded {
			crc = crc24Update(crc, b)
		}
		if _, err := tmp.Write(decoded); err != nil {
			return cleanup(err)
		}
	}

	if hasCRC {
		actual := []byte{byte((crc >> 16) & 0xFF), byte((crc >> 8) & 0xFF), byte(crc & 0xFF)}
		if !bytes.Equal(actual, crcExpected) {
			return cleanup(fmt.Errorf("armor crc mismatch"))
		}
	}

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return cleanup(err)
	}
	return tmp, nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		if err == io.EOF && len(line) > 0 {
			return line, nil
		}
		return "", err
	}
	return line, nil
}

func crc24Update(crc uint32, b byte) uint32 {
	crc ^= uint32(b) << 16
	for i := 0; i < 8; i++ {
		crc <<= 1
		if (crc & 0x1000000) != 0 {
			crc ^= 0x1864CF
		}
	}
	return crc & 0xFFFFFF
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
