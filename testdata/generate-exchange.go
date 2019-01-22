package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

var curve = elliptic.P256()

func main() {
	fmt.Println("# r1:k1:p1:r2:k2:p2:shared")

	for i := 0; i < 6; i++ {
		generate(i)
	}
}

func generate(i int) {
	// Each X25519 curve needs 32 bytes of random
	var random = make([]byte, 64)

	switch i {
	case 0:
	case 1:
		for i := range random {
			random[i] = 0xff
		}
	default:
		if _, err := io.ReadFull(rand.Reader, random); err != nil {
			panic(err)
		}
	}

	var (
		reader = bytes.NewBuffer(random)
		k1, p1 *[32]byte
		k2, p2 *[32]byte
		sk     = new([32]byte)
		err    error
	)
	if k1, p1, err = generateKey(reader); err != nil {
		panic(err)
	}
	if k2, p2, err = generateKey(reader); err != nil {
		panic(err)
	}
	curve25519.ScalarMult(sk, k1, p2)

	fmt.Printf("%064x:%064x:%064x:%064x:%064x:%064x:%064x\n",
		random[:32], k1[:], p1[:],
		random[32:], k2[:], p2[:], sk[:])
}

func generateKey(r io.Reader) (privateKey, publicKey *[32]byte, err error) {
	privateKey, publicKey = new([32]byte), new([32]byte)
	if _, err = io.ReadFull(r, privateKey[:]); err != nil {
		return
	}
	privateKey[0] &= 0xf8
	privateKey[31] &= 0x7f
	privateKey[31] |= 0x40

	curve25519.ScalarBaseMult(publicKey, privateKey)
	return
}
