package perm

import (
	"fmt"
	"os"
)

// Check0600 verifies file permissions are -rw-------
func Check0600(path string) error {
	st, err := os.Stat(path)
	if err != nil { return err }
	mode := st.Mode().Perm()
	if mode != 0o600 {
		return fmt.Errorf("file %s permissions %o (want 0600)", path, mode)
	}
	return nil
}
