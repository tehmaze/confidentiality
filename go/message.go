package confidentiality

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
)

const (
	gcmNonceSize = 12
	gcmTagSize   = 16
)

// Decrypt a message.
func Decrypt(message, key []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	if len(message) < gcmNonceSize {
		return nil, io.ErrUnexpectedEOF
	}

	var nonce []byte
	nonce, message = message[:gcmNonceSize], message[gcmNonceSize:]
	return aead.Open(nil, nonce, message, nil)
}

// Encrypt a message.
func Encrypt(message, key []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err = io.ReadFull(randomReader, nonce); err != nil {
		return nil, err
	}

	return append(nonce, aead.Seal(nil, nonce, message, nil)...), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}
