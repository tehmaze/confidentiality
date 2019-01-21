package confidentiality

import (
	"crypto/elliptic"
	"io"
	"math/big"
	"net"
	"time"
)

type netStream struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func newNetStream(c net.Conn) (net.Conn, error) {
	k, err := Exchange(c)
	if err != nil {
		return nil, err
	}

	// First start an encrypter, because Decrypter will block on reading from c.
	w := Encrypter(c, k)
	r := Decrypter(c, k)
	return &netStream{Conn: c, r: r, w: w}, nil
}

func (s *netStream) Read(p []byte) (int, error) {
	return s.r.Read(p)
}

func (s *netStream) Write(p []byte) (int, error) {
	return s.w.Write(p)
}

// Dial connects to the address on the named network, does a key exchange and
// switches to an encrypted link. See net.Dial for all options.
func Dial(network, address string) (net.Conn, error) {
	c, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	return newNetStream(c)
}

// DialTimeout acts like Dial but takes a timeout.
func DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return nil, err
	}

	return newNetStream(c)
}

type netListener struct {
	net.Listener

	d    []byte
	x, y *big.Int
}

// Accept waits for and returns the next connection to the listener, negotiating
// encryption with the client.
func (l *netListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	k, err := exchangeSessionKey(c, l.d, l.x, l.y)
	if err != nil {
		return nil, err
	}

	return &netStream{
		Conn: c,
		r:    Decrypter(c, k),
		w:    Encrypter(c, k),
	}, nil
}

// Listen announces on the local network address.
func Listen(network, address string) (net.Listener, error) {
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	s := &netListener{Listener: l}
	if s.d, s.x, s.y, err = elliptic.GenerateKey(exchangeCurve, randomReader); err != nil {
		return nil, err
	}

	return s, nil
}
