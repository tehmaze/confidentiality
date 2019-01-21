package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
)

var curve = elliptic.P256()

func main() {
	fmt.Println("# r1:x1:y1:d1:r2:x2:y2:d2:shared")

	for i := 0; i < 6; i++ {
		generate(i)
	}
}

func generate(i int) {
	// Each P-256 needs 32 bytes of random
	var random = make([]byte, 64)

	if i > 0 {
		if _, err := io.ReadFull(rand.Reader, random); err != nil {
			panic(err)
		}
	}

	var reader = bytes.NewBuffer(random)

	d1, x1, y1, err := elliptic.GenerateKey(curve, reader)
	if err != nil {
		panic(err)
	}

	d2, x2, y2, err := elliptic.GenerateKey(curve, reader)
	if err != nil {
		panic(err)
	}

	sk, _ := curve.ScalarMult(x2, y2, d1)
	fmt.Printf("%064x:%064x:%064x:%064x:%064x:%064x:%064x:%064x:%064x\n",
		random[:32], d1, x1, y1,
		random[32:], d2, x2, y2, sk)
}
