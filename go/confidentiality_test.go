package confidentiality

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadTestVectors(t *testing.T, name string, items int) (vectors []map[string][]byte) {
	t.Helper()

	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	f, err := ioutil.ReadFile(filepath.Join(d, "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}

	var header []string
	for line, vector := range strings.Split(string(f), "\n") {
		vector = strings.TrimSpace(vector)
		if vector == "" {
			continue
		} else if strings.HasPrefix(vector, "# cols=") {
			header = strings.Split(vector[len("# cols="):], ":")
			continue
		} else if vector[0] == '#' {
			continue
		}

		fields := strings.Split(vector, ":")
		if len(fields) != len(header) {
			t.Errorf("vector on line %d has %d fields, expected %d", line+1, len(fields), len(header))
		}

		mapped := make(map[string][]byte)
		for i, key := range header {
			if key == "name" {
				mapped[key] = []byte(fields[i])
			} else {
				if mapped[key], err = hex.DecodeString(fields[i]); err != nil {
					panic(err)
				}
			}
		}

		vectors = append(vectors, mapped)
	}

	return
}

func must(c bool, s string) {
	if !c {
		panic(s)
	}
}

func mustUnhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
