package confidentiality

import (
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"golang.org/x/crypto/curve25519"
)

const (
	publicKeyTypeECDSA = 0x04
	publicKeyType25519 = 0x19
	kexRounds          = 4096
	kexKeyLen          = 32
)

// Exchange a session key.
func Exchange(rw io.ReadWriter) (key []byte, err error) {
	var privateKey, publicKey *[32]byte
	if privateKey, publicKey, err = generateKey(randomReader); err != nil {
		return
	}
	defer zero(privateKey[:])
	return exchangeSessionKey(rw, privateKey, publicKey)
}

func generateKey(r io.Reader) (privateKey, publicKey *[32]byte, err error) {
	privateKey, publicKey = new([32]byte), new([32]byte)
	if _, err = io.ReadFull(r, privateKey[:]); err != nil {
		return
	}

	// Masking X25519 key.
	privateKey[0x00] &= 0xf8
	privateKey[0x1f] &= 0x7f
	privateKey[0x1f] |= 0x40

	curve25519.ScalarBaseMult(publicKey, privateKey)
	return
}

func exchangeSessionKey(rw io.ReadWriter, localPrivateKey, localPublicKey *[32]byte) (key []byte, err error) {
	if err = writePublicKey(rw, localPublicKey); err != nil {
		return
	}

	var peersPublicKey *[32]byte
	if peersPublicKey, err = readPublicKey(rw); err != nil {
		return
	}

	// Compute the shared session key
	var sharedKey [32]byte
	curve25519.ScalarMult(&sharedKey, localPrivateKey, peersPublicKey)

	if testing.Verbose() {
		fmt.Printf("local secret key %x\n", localPrivateKey[:])
		fmt.Printf("local public key %x\n", localPublicKey[:])
		fmt.Printf("peers public key %x\n", peersPublicKey[:])
		fmt.Printf("shared_point %x\n", sharedKey[:])
	}

	// 256-bit key from the scalar multiplication product as PBKDF2 input
	key = pbkdf2.Key(sharedKey[:], nil, kexRounds, kexKeyLen, sha256.New)
	zero(sharedKey[:]) // No longer needed

	return
}

func readPublicKey(r io.Reader) (publicKey *[32]byte, err error) {
	var wireBytes = make([]byte, 33)
	if _, err = io.ReadFull(r, wireBytes); err != nil {
		return
	}

	if wireBytes[0] != publicKeyType25519 {
		return nil, fmt.Errorf("confidentiality: peer sent unsupported public key")
	}

	publicKey = new([32]byte)
	copy(publicKey[:], wireBytes[1:])
	return
}

func writePublicKey(w io.Writer, publicKey *[32]byte) (err error) {
	var wireBytes = make([]byte, 33)
	wireBytes[0] = publicKeyType25519
	copy(wireBytes[1:], (*publicKey)[:])

	var offset, n int
	for offset < 33 {
		if n, err = w.Write(wireBytes[offset:]); err != nil {
			return
		}
		offset += n
	}

	return
}
