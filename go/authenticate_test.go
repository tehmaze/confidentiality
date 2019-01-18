package confidentiality

import (
	"bytes"
	"testing"
)

func TestAuthentication(t *testing.T) {
	for _, vector := range loadTestVectors(t, "authenticate_test.txt", 3) {
		var (
			key     = mustUnhex(vector[0])
			message = mustUnhex(vector[1])
			digest  = mustUnhex(vector[2])
		)

		t.Run("sign", func(t *testing.T) {
			var (
				want = append(message, digest...)
				test = Sign(nil, message, key)
			)
			if !bytes.Equal(want, test) {
				t.Fatalf("expected %q, got %q", want, test)
			}
		})

		t.Run("verify", func(t *testing.T) {
			if !Verify(append(message, digest...), key) {
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
	}
}
