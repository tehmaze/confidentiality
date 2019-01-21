package confidentiality

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestMessage(t *testing.T) {
	defer func() {
		randomReader = rand.Reader
	}()

	for _, fields := range loadTestVectors(t, "message_test.txt", 5) {
		t.Run(fields[0], func(t *testing.T) {
			var (
				key       = mustUnhex(fields[1])
				iv        = mustUnhex(fields[2])
				decrypted = mustUnhex(fields[3])
				encrypted = mustUnhex(fields[4])
			)
			t.Run("encrypt", func(t *testing.T) {
				randomReader = bytes.NewBuffer(iv)
				test, err := Encrypt(decrypted, key)
				if err != nil {
					t.Errorf("encrypt failed: %v", err)
				} else if !bytes.Equal(test, encrypted) {
					t.Errorf("encrypted failed:\ngot:\n%sexpected:\n%s", hex.Dump(test), hex.Dump(encrypted))
				}
			})
			t.Run("decrypt", func(t *testing.T) {
				test, err := Decrypt(append(iv, encrypted...), key)
				if err != nil {
					t.Errorf("decrypt failed: %v", err)
				} else if !bytes.Equal(test, decrypted) {
					t.Errorf("decrypted failed:\ngot:\n%sexpected:\n%s", hex.Dump(test), hex.Dump(decrypted))
				}
			})
		})
	}
}
