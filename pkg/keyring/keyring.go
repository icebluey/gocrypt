package keyring

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"example.com/gocrypt/pkg/util/perm"
)

type Entry struct {
	KeyID     string `json:"key_id"`
	Path      string `json:"path"`
	Created   time.Time `json:"created"`
	Revoked   bool   `json:"revoked"`
}

type Store struct {
	Entries []Entry `json:"entries"`
}

func load(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Store{}, nil
	}
	if err != nil { return nil, err }
	var s Store
	if err := json.Unmarshal(b, &s); err != nil { return nil, err }
	return &s, nil
}

func save(path string, s *Store) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(path, b, 0600)
}

func Rotate(path string, keyID, newPriv string) error {
	if err := perm.Check0600(newPriv); err != nil { return err }
	s, err := load(path)
	if err != nil { return err }
	found := false
	for i := range s.Entries {
		if s.Entries[i].KeyID == keyID {
			s.Entries[i].Path = newPriv
			s.Entries[i].Created = time.Now().UTC()
			found = true
		}
	}
	if !found {
		s.Entries = append(s.Entries, Entry{KeyID: keyID, Path: newPriv, Created: time.Now().UTC()})
	}
	return save(path, s)
}

func Revoke(path string, keyID string) error {
	s, err := load(path)
	if err != nil { return err }
	found := false
	for i := range s.entriesPtr() {
		if s.Entries[i].KeyID == keyID {
			s.Entries[i].Revoked = true
			found = true
		}
	}
	if !found {
		return errors.New("key not found")
	}
	return save(path, s)
}

func (s *Store) entriesPtr() []Entry { return s.Entries }
