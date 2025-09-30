package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildCLIBinary(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "gocrypt")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	cmd.Dir = wd
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

func runCLI(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func generateHybridMaterial(t *testing.T, bin string, alg string, dir string) (pubB64, privB64 string) {
	t.Helper()
	var eccAlgo string
	var kemScheme string
	switch alg {
	case "mlkem768+x25519":
		eccAlgo = "x25519"
		kemScheme = "mlkem768"
	case "mlkem1024+x448":
		eccAlgo = "x448"
		kemScheme = "mlkem1024"
	default:
		t.Fatalf("unsupported alg %s", alg)
	}
	subdir := filepath.Join(dir, strings.ReplaceAll(alg, "+", "_"))
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	eccPrefix := filepath.Join(subdir, "ecc")
	mlkemPrefix := filepath.Join(subdir, "mlkem")
	runCLI(t, bin, "keygen", "-pkalg="+eccAlgo, "-out", eccPrefix)
	runCLI(t, bin, "kemgen", "-scheme="+kemScheme, "-out", mlkemPrefix)
	pubOut := runCLI(t, bin, "hybrid", "-mode=pub", "-eccfile", eccPrefix+".pub", "-mlkemfile", mlkemPrefix+".pub")
	privOut := runCLI(t, bin, "hybrid", "-mode=priv", "-eccfile", eccPrefix+".key", "-mlkemfile", mlkemPrefix+".key")
	return strings.TrimSpace(pubOut), strings.TrimSpace(privOut)
}

func TestCLIEncryptDecryptHybridBase64(t *testing.T) {
	bin := buildCLIBinary(t)
	dir := t.TempDir()

	cases := []struct {
		name string
	}{
		{name: "mlkem768+x25519"},
		{name: "mlkem1024+x448"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pubB64, privB64 := generateHybridMaterial(t, bin, tc.name, dir)
			plain := []byte("hybrid base64 test " + tc.name)
			plainPath := filepath.Join(dir, tc.name+".txt")
			if err := os.WriteFile(plainPath, plain, 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			cipherPath := filepath.Join(dir, tc.name+".pgp")
			if len(pubB64) == 0 {
				t.Fatalf("empty pubB64")
			}
			cmd := exec.Command(bin, "-pk", pubB64, "-pkalg="+tc.name, "-out", cipherPath, plainPath)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("encrypt failed: %v\n%s", err, out)
			}

			decPath := filepath.Join(dir, tc.name+".out")
			cmd = exec.Command(bin, "decrypt", "-pk", privB64, "-pkalg="+tc.name, "-out", decPath, cipherPath)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("decrypt failed: %v\n%s", err, out)
			}

			got, err := os.ReadFile(decPath)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if string(got) != string(plain) {
				t.Fatalf("decrypted output mismatch: got %q want %q", got, plain)
			}
		})
	}
}
