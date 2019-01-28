package confidentiality

import (
	"bytes"
	"testing"
)

func TestAuthentication(t *testing.T) {
	for _, vector := range loadTestVectors(t, "authentication-vectors.txt", 3) {
		t.Run(string(vector["name"]), func(t *testing.T) {
			var (
				key       = vector["key"]
				message   = vector["message"]
				signature = vector["signature"]
				signed    = append(message, signature...)
			)
			must(len(key) > 0, "key is nil")
			must(len(message) > 0, "message is nil")
			must(len(signature) > 0, "signature is nil")

			t.Run("sign", func(t *testing.T) {
				if test := Signed(nil, message, key); !bytes.Equal(signed, test) {
					t.Fatalf("expected %q, got %q", signed, test)
				}
			})

			t.Run("verify", func(t *testing.T) {
				if !Verify(signed, key) {
					t.Fatal("failed to verify")
				}
			})

			t.Run("stream", func(t *testing.T) {
				buffer := new(bytes.Buffer)
				writer := Signer(buffer, key)
				if _, err := writer.Write(message); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}

				reader := Verifier(buffer, key)
				output := make([]byte, len(message))
				if _, err := reader.Read(output); err != nil {
					t.Fatal(err)
				}
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(output, message) {
					t.Fatalf("output mangled, expected %q, got %q", message, output)
				}
			})
		})
	}
}
