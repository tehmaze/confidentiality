package confidentiality

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadTestVectors(t *testing.T, name string, items int) (vectors [][]string) {
	t.Helper()

	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	f, err := ioutil.ReadFile(filepath.Join(d, "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}

	for line, vector := range strings.Split(string(f), "\n") {
		if strings.HasPrefix(vector, "#") || strings.TrimSpace(vector) == "" {
			continue
		}

		fields := strings.Split(vector, ":")
		if len(fields) != items {
			t.Errorf("vector on line %d has %d fields, expected %d", line+1, len(fields), items)
		}
		vectors = append(vectors, fields)
	}

	return
}

func mustUnhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
