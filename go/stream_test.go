package confidentiality

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

func TestStream(t *testing.T) {
	defer func() {
		// Cleanup our monkey patch
		randomReader = rand.Reader
	}()

	for _, fields := range loadTestVectors(t, "stream_test.txt", 5) {
		t.Run(fields[0], func(t *testing.T) {
			var (
				key       = mustUnhex(fields[1])
				iv        = mustUnhex(fields[2])
				decrypted = mustUnhex(fields[3])
				encrypted = mustUnhex(fields[4])
			)

			t.Run("encrypter", func(t *testing.T) {
				randomReader = bytes.NewBuffer(iv)

				buffer := new(bytes.Buffer)
				writer := Encrypter(buffer, key)
				if _, err := writer.Write(decrypted); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buffer.Bytes(), encrypted) {
					//t.Fatalf("unexpected output\ngot:\n%s\nwant:\n%s", hex.Dump(buffer.Bytes()), hex.Dump(encrypted))
					t.Fatalf("unexpected output\ngot:\n%x\nwant:\n%x", buffer.Bytes(), encrypted)
				}
			})

			t.Run("decrypter", func(t *testing.T) {
				buffer := make([]byte, len(decrypted))
				reader := Decrypter(bytes.NewBuffer(encrypted), key)
				if _, err := io.ReadFull(reader, buffer); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buffer, decrypted) {
					t.Fatalf("unexpected output\ngot:\n%s\nwant:\n%s", hex.Dump(buffer), hex.Dump(decrypted))
				}
			})
		})
	}
}
