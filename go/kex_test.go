package confidentiality

import (
	"bytes"
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
