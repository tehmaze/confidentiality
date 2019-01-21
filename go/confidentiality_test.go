package confidentiality

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
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

func ExampleExchange() {
	server, _ := net.Listen("tcp", "localhost:0")
	defer server.Close()

	go func(listener net.Listener) {
		connection, _ := listener.Accept()
		defer connection.Close()

		var (
			sharedKey, _ = Exchange(connection)
			decrypter    = Decrypter(connection, sharedKey)
			encrypter    = Encrypter(connection, sharedKey)
			message      = make([]byte, 14)
		)
		io.ReadFull(decrypter, message)
		fmt.Fprint(encrypter, "hello, client!") // 14 bytes
	}(server)

	client, _ := net.Dial("tcp", server.Addr().String())
	defer client.Close()
	var (
		sharedKey, _ = Exchange(client)
		encrypter    = Encrypter(client, sharedKey)
		decrypter    = Decrypter(client, sharedKey)
		message      = make([]byte, 14)
	)
	fmt.Fprint(encrypter, "hello, server!") // 14 bytes
	io.ReadFull(decrypter, message)
	fmt.Println(string(message)) // Shall print "hello, client!"
}
