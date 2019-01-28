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

	for _, vector := range loadTestVectors(t, "message-vectors.txt", 5) {
		t.Run(string(vector["name"]), func(t *testing.T) {
			var (
				key       = vector["key"]
				iv        = vector["nonce"]
				decrypted = vector["plaintext"]
				encrypted = append(iv, vector["ciphertext"]...)
			)
			t.Run("encrypt", func(t *testing.T) {
				randomReader = bytes.NewBuffer(iv)
				test, err := Encrypt(decrypted, key)
				if err != nil {
					t.Errorf("encrypt failed: %v", err)
				} else if remaining := randomReader.(*bytes.Buffer).Len(); remaining != 0 {
					t.Errorf("%d bytes of random remaining", remaining)
				} else if !bytes.Equal(test, encrypted) {
					t.Errorf("encrypted failed:\ngot:\n%sexpected:\n%s", hex.Dump(test), hex.Dump(encrypted))
				}

			})
			t.Run("decrypt", func(t *testing.T) {
				test, err := Decrypt(encrypted, key)
				if err != nil {
					t.Errorf("decrypt failed: %v", err)
				} else if !bytes.Equal(test, decrypted) {
					t.Errorf("decrypted failed:\ngot:\n%sexpected:\n%s", hex.Dump(test), hex.Dump(decrypted))
				}
			})
		})
	}
}
