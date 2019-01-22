package confidentiality

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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
	for _, vector := range loadTestVectors(t, "exchange_test.txt", 7) {
		t.Run("", func(t *testing.T) {
			testExchangeVectors(t, vector)
		})
	}
}

func testExchangeVectors(t *testing.T, vectors []string) {
	t.Helper()

	defer func() {
		randomReader = rand.Reader
	}()

	randomVector, _ := hex.DecodeString(vectors[0])
	randomReader = bytes.NewBuffer(randomVector)

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

	wantedKey, _ := hex.DecodeString(vectors[8])
	if !bytes.Equal(key, wantedKey) {
		t.Fatalf("expected key %x, got %x", wantedKey, key)
	}

}
