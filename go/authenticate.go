package confidentiality

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"errors"
	"hash"
	"io"

	_ "crypto/sha256" // Load SHA-256
)

// Authentication errors.
var (
	ErrNotSigned = errors.New("not signed")
	ErrVerify    = errors.New("signature verification failed")
)

var (
	authenticationHash = crypto.SHA256
	authenticationSize = authenticationHash.Size()
)

// Sign a message.
func Sign(dst, message, key []byte) []byte {
	ret, out := sliceForAppend(dst, len(message)+authenticationSize)

	mac := hmac.New(authenticationHash.New, key)
	mac.Write(message)
	copy(out, message)
	copy(out[len(message):], mac.Sum(nil))

	return ret
}

// Verify a signed message.
func Verify(signed, key []byte) bool {
	if len(signed) < authenticationSize {
		// Not signed.
		return false
	}

	var (
		size               = len(signed) - authenticationSize
		message, signature = signed[:size], signed[size:]
		mac                = hmac.New(authenticationHash.New, key)
	)
	mac.Write(message)
	return hmac.Equal(signature, mac.Sum(nil))
}

type signer struct {
	w    io.Writer
	hmac hash.Hash
}

func (s *signer) Close() error {
	buffer := make([]byte, s.hmac.Size())
	copy(buffer, s.hmac.Sum(nil))
	copied := 0
	for copied < len(buffer) {
		n, err := s.w.Write(buffer[copied:])
		if err != nil {
			return err
		}
		copied += n
	}
	return nil
}

func (s *signer) Write(p []byte) (n int, err error) {
	if n, err = s.w.Write(p); n > 0 {
		s.hmac.Write(p[:n])
	}
	return
}

// Signer writes a signature to w upon closing the returned WriteCloser.
func Signer(w io.Writer, key []byte) io.WriteCloser {
	return &signer{
		w:    w,
		hmac: hmac.New(authenticationHash.New, key),
	}
}

type verifier struct {
	r    io.Reader
	hmac hash.Hash
	buf  *bytes.Buffer
	err  error
}

func (v *verifier) Close() error {
	if v.buf.Len() < v.hmac.Size() {
		// Our buffer doesn't contain sufficient bytes, there is no MAC to verify.
		return ErrNotSigned
	}

	if !hmac.Equal(v.buf.Bytes(), v.hmac.Sum(nil)) {
		return ErrVerify
	}

	return nil
}

func (v *verifier) Read(p []byte) (int, error) {
	for v.err == nil && (v.buf.Len()-v.hmac.Size()) < len(p) {
		m, err := v.r.Read(p)
		if m > 0 {
			v.buf.Write(p[:m])
		}
		if err == io.EOF {
			v.err = err
		} else if err != nil {
			return 0, err
		}
	}

	read := len(v.buf.Bytes()) - v.hmac.Size()
	if l := len(p); read > l {
		read = l
	}
	if read > 0 {
		q := v.buf.Next(read)
		copy(p, q)
		v.hmac.Write(q)
	}
	return read, v.err
}

// Verifier reads the signature from r upon closing the returned ReadCloser.
func Verifier(r io.Reader, key []byte) io.ReadCloser {
	return &verifier{
		r:    r,
		hmac: hmac.New(authenticationHash.New, key),
		buf:  new(bytes.Buffer),
	}
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
