package confidentiality

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
)

// Decrypter reads the encrypted iv from r and returns a Reader that will
// decrypt the stream from r.
func Decrypter(r io.Reader, key []byte) io.Reader {
	block, err := aes.NewCipher(key)
	if err != nil {
		return streamError{err}
	}

	var aead cipher.AEAD
	if aead, err = cipher.NewGCMWithTagSize(block, 16); err != nil {
		return streamError{err}
	}

	// Read nonce and encrypted IV
	nonceAndEncryptedIV := make([]byte, gcmNonceSize+block.BlockSize()+aead.Overhead())
	if _, err = io.ReadFull(r, nonceAndEncryptedIV); err != nil {
		return streamError{err}
	}

	// Decrypt IV using the nonce
	var (
		nonce       = nonceAndEncryptedIV[:gcmNonceSize]
		encryptedIV = nonceAndEncryptedIV[gcmNonceSize:]
		iv          []byte
	)
	if iv, err = aead.Open(nil, nonce, encryptedIV, nil); err != nil {
		return streamError{err}
	}

	return cipher.StreamReader{S: cipher.NewCTR(block, iv), R: r}
}

// Encrypter generates a new iv, encrypts it with key and writes it to w and
// returns a Writer that will encrypt the stream to w.
func Encrypter(w io.Writer, key []byte) io.Writer {
	block, err := aes.NewCipher(key)
	if err != nil {
		return streamError{err}
	}

	// Generate IV
	iv := make([]byte, block.BlockSize())
	if _, err = io.ReadFull(randomReader, iv); err != nil {
		return streamError{err}
	}

	// Generate nonce
	nonce := make([]byte, gcmNonceSize)
	if _, err = io.ReadFull(randomReader, nonce); err != nil {
		return streamError{err}
	}

	// Encrypt IV using the nonce and write it to the stream
	aead, err := cipher.NewGCMWithTagSize(block, gcmTagSize)
	if err != nil {
		return streamError{err}
	}
	if _, err = w.Write(append(nonce, aead.Seal(nil, nonce, iv, nil)...)); err != nil {
		return streamError{err}
	}

	return cipher.StreamWriter{S: cipher.NewCTR(block, iv), W: w}
}

type streamError struct{ err error }

func (s streamError) Read(_ []byte) (int, error) {
	return 0, s.err
}

func (s streamError) Write(_ []byte) (int, error) {
	return 0, s.err
}

// Secure exchanges a key over the passed ReadWriter and returns a ReadWriter that
// transparently encrypts and decrypts writes and reads.
func Secure(rw io.ReadWriter) io.ReadWriter {
	shared, err := Exchange(rw)
	if err != nil {
		return &secured{err: err}
	}

	return &secured{
		r: Decrypter(rw, shared),
		w: Encrypter(rw, shared),
	}
}

type secured struct {
	r   io.Reader
	w   io.Writer
	err error
}

func (s *secured) Read(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	return s.r.Read(p)
}

func (s *secured) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	return s.w.Write(p)
}
