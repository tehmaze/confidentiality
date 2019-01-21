package confidentiality

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

var (
	testNetworkSizes   = []int{1, 2, 4, 8, 16, 32, 64, 128, 150, 256, 512, 1024, 4096, 65536}
	testNetworkPayload = "They're taking the Gophers to Dósóþeus! "
)

func TestNetwork(t *testing.T) {
	l, err := Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("listening on %s", l.Addr())
	defer l.Close()

	var wait sync.WaitGroup
	go func(l net.Listener, wait *sync.WaitGroup) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go testListenerClient(t, c, wait)
		}
	}(l, &wait)

	for i := 0; i < 5; i++ {
		wait.Add(1)

		c, err := Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()

		testNetworkReads(t, c)
		testNetworkWrites(t, c)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}

	wait.Wait()
}

func testListenerClient(t *testing.T, c net.Conn, wait *sync.WaitGroup) {
	defer wait.Done()

	t.Helper()
	t.Logf("new client from %s", c.RemoteAddr())
	testNetworkWrites(t, c)
	testNetworkReads(t, c)
}

func testNetworkWrites(t *testing.T, c net.Conn) {
	t.Helper()

	// Test encrypter
	var total int
	for _, size := range testNetworkSizes {
		b := make([]byte, size)
		for i := 0; i < size; i += len(testNetworkPayload) {
			copy(b[i:], testNetworkPayload)
		}

		var (
			n, m int
			err  error
		)
		for n < size {
			if m, err = c.Write(b); err != nil {
				t.Fatal(err)
			}
			n += m
		}
		total += n
	}
	t.Logf("wrote %d bytes", total)
}

func testNetworkReads(t *testing.T, c net.Conn) {
	t.Helper()

	// Test decrypter
	var total int
	for _, size := range testNetworkSizes {
		b := make([]byte, size)
		if _, err := io.ReadFull(c, b); err != nil {
			t.Fatal(err)
		}

		var (
			repeat = (len(b) + len(testNetworkPayload) - 1) / len(testNetworkPayload)
			wanted = strings.Repeat(testNetworkPayload, repeat)
		)
		if string(b) != wanted[:size] {
			t.Fatal("unexpected data read")
		}

		total += size
	}
	t.Logf("read %d bytes", total)
}
