package confidentiality

import (
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var exchangeCurve = elliptic.P256()

type ellipticPublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type ellipticPrivateKey struct {
	D []byte
}

// Exchange a 256-bit session key.
func Exchange(rw io.ReadWriter) (key []byte, err error) {
	var (
		d    []byte
		x, y *big.Int
	)
	if d, x, y, err = elliptic.GenerateKey(exchangeCurve, randomReader); err != nil {
		return
	}
	return exchangeSessionKey(rw, d, x, y)
}

func exchangeSessionKey(rw io.ReadWriter, d []byte, x, y *big.Int) (key []byte, err error) {
	if err = writeEllipticPublicKey(rw, exchangeCurve, x, y); err != nil {
		return
	}

	var peersX, peersY, sharedX *big.Int
	if peersX, peersY, err = readEllipticPublicKey(rw, exchangeCurve); err != nil {
		return
	}

	// Compute the shared session key
	sharedX, _ = exchangeCurve.ScalarMult(peersX, peersY, d)

	// 256-bit key from the scalar multiplication product
	key = make([]byte, 32)
	copy(key, sharedX.Bytes())

	return
}

func readEllipticPublicKey(r io.Reader, curve elliptic.Curve) (x, y *big.Int, err error) {
	var (
		ecdhKeyBytesLengthBytes [2]byte
		ecdhKeyBytesLength      uint16
		ecdhKeyBytes            []byte
	)
	if _, err = io.ReadFull(r, ecdhKeyBytesLengthBytes[:]); err != nil {
		err = fmt.Errorf("error reading public key size: %v", err)
		return
	} else if ecdhKeyBytesLength = binary.BigEndian.Uint16(ecdhKeyBytesLengthBytes[:]); ecdhKeyBytesLength == 0 {
		err = errors.New("confidentiality: peer sent empty public key")
		return
	}

	ecdhKeyBytes = make([]byte, ecdhKeyBytesLength)
	if _, err = io.ReadFull(r, ecdhKeyBytes); err != nil {
		err = fmt.Errorf("error reading %d-bytes public key size: %v", ecdhKeyBytesLength, err)
		return
	}

	x, y = elliptic.Unmarshal(curve, ecdhKeyBytes)
	return
}

func writeEllipticPublicKey(w io.Writer, curve elliptic.Curve, x, y *big.Int) (err error) {
	var (
		ecdhKeyBytes       = elliptic.Marshal(curve, x, y)
		ecdhKeyBytesLength = uint16(len(ecdhKeyBytes))
		wireKeyBytes       []byte
	)
	wireKeyBytes = make([]byte, 2+len(ecdhKeyBytes))
	binary.BigEndian.PutUint16(wireKeyBytes, ecdhKeyBytesLength)
	copy(wireKeyBytes[2:], ecdhKeyBytes)
	if _, err = w.Write(wireKeyBytes); err != nil {
		return
	}
	return
}
