package confidentiality

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
)

func TestExchange(t *testing.T) {
	server, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var (
		wait sync.WaitGroup
		out  = make(chan []byte, 2)
	)

	wait.Add(1)
	go func(l net.Listener, wait *sync.WaitGroup) {
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}

		defer c.Close()
		testExchange(out, c, wait)
	}(server, &wait)

	wait.Add(1)
	go testExchange(out, client, &wait)

	wait.Wait()

	var aKey, bKey []byte
	select {
	case aKey = <-out:
	default:
		t.Fatal("no key from a")
	}
	select {
	case bKey = <-out:
	default:
		t.Fatal("no key from b")
	}

	if !bytes.Equal(aKey, bKey) {
		t.Fatalf("exchange failed, %x != %x", aKey, bKey)
	}
	t.Logf("shared key: %x", aKey)
}

func testExchange(out chan<- []byte, rw io.ReadWriter, wait *sync.WaitGroup) {
	defer wait.Done()

	k, err := Exchange(rw)
	if err != nil {
		panic(err)
	}

	out <- k
}

func TestExchangeVectors(t *testing.T) {
	t.Helper()
	for _, vector := range loadTestVectors(t, "exchange-vectors.txt", 7) {
		t.Run(string(vector["name"]), func(t *testing.T) {
			testExchangeVectors(t, vector)
		})
	}
}

func testExchangeVectors(t *testing.T, vector map[string][]byte) {
	t.Helper()

	defer func() {
		randomReader = rand.Reader
	}()

	randomReader = bytes.NewBuffer(vector["random"])

	var (
		publicKey *[32]byte
		buffer    = new(bytes.Buffer)
		key       []byte
		err       error
	)
	if _, publicKey, err = generateKey(randomReader); err != nil {
		t.Fatal(err)
	}
	if err = writePublicKey(buffer, publicKey); err != nil {
		return
	}
	if key, err = Exchange(buffer); err != nil {
		return
	} else if len(key) < 32 {
		t.Fatalf("expected 256-bit key, got %d-bit", len(key)<<3)
	}

	if !bytes.Equal(key, vector["sharedSecret"]) {
		t.Fatalf("expected key %x, got %x", vector["sharedSecret"], key)
	}
}
