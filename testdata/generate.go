package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"
)

var (
	zeros [64]byte
	fulls [64]byte
)

func init() {
	for i := range fulls[:] {
		fulls[i] = 0xff
	}
}

func main() {
	generateAuthenticationVectors("authentication-vectors.txt", 16)
	generateMessageVectors("message-vectors.txt", 16)
	generateExchangeVectors("exchange-vectors.txt", 16)
	generateStreamVectors("stream-vectors.txt", 16)
}

func tohex(b []byte) string {
	f := fmt.Sprintf("%%0%dx", len(b)<<1)
	return fmt.Sprintf(f, b)
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func generateAuthenticationVectors(name string, n int) {
	f, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	/*
		Authentication vectors require:
		- arbitrary-sized key
		- arbitrary-sized plaintext
		- 32 bytes message authenticator
	*/
	fmt.Fprintln(f, "# name=authentication vectors")
	fmt.Fprintln(f, "# cols=name:key:message:signature")

	// Start with HMAC-256 test vectors.
	// Note that test case 5 is skipped: we don't do truncation.
	fmt.Fprint(f, `# From the RFC4321:
RFC4312 Test Case 1:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b:4869205468657265:b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
RFC4312 Test Case 2:4a656665:7768617420646f2079612077616e7420666f72206e6f7468696e673f:5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
RFC4312 Test Case 3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd:773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe
RFC4312 Test Case 4:0102030405060708090a0b0c0d0e0f10111213141516171819:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd:82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b
RFC4312 Test Case 6:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374:60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54
RFC4312 Test Case 7:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e:9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2
# Generated random vectors:
`)

	// Generate random vectors
	for i := 6; i < n; i++ {
		var (
			size      = 1 << uint(i-5)
			key       = make([]byte, size>>1)
			message   = make([]byte, size)
			signature []byte
			mac       hash.Hash
		)
		io.ReadFull(rand.Reader, key)
		mac = hmac.New(sha256.New, key)

		io.ReadFull(rand.Reader, message)
		mac.Write(message)

		signature = mac.Sum(nil)

		fmt.Fprintf(f, "Generated vector %d:%s:%s:%s\n",
			i-6,
			tohex(key),
			tohex(message),
			tohex(signature))
	}
}

func generateMessageVectors(name string, n int) {
	f, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	/*
		Message vectors require:
		- 32 or 64 bytes AES key (128 or 256-bit AES key)
		- 12 byte GCM nonce
		- arbitrary-sized decrypted message
		- arbitrary-sized encrypted message and 16-bytes GCM tag
	*/
	fmt.Fprintln(f, "# name=message vectors")
	fmt.Fprintln(f, "# cols=name:key:nonce:plaintext:ciphertext")

	// From the NIST GCM specification http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
	fmt.Fprint(f, `# From the NIST GCM specification:
NIST AES-128 empty:00000000000000000000000000000000:000000000000000000000000::58e2fccefa7e3061367f1d57a4e7455a
NIST AES-128 zeros:00000000000000000000000000000000:000000000000000000000000:00000000000000000000000000000000:0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf
NIST AES-128:feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255:42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4
NIST AES-256 empty:0000000000000000000000000000000000000000000000000000000000000000:000000000000000000000000::530f8afbc74536b9a963b4f1c4cb738b
NIST AES-256 zeros:0000000000000000000000000000000000000000000000000000000000000000:000000000000000000000000:00000000000000000000000000000000:cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919
NIST AES-256:feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf888:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255:522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c
# Generated random vectors:
`)

	var (
		sizes = []int{16, 24, 32}
		sizep int
	)
	for i := 6; i < n; i++ {
		var (
			// Alternate between generated key sizes
			size  = sizes[sizep%3]
			key   = make([]byte, size)
			block cipher.Block
			nonce = make([]byte, 12)
			aead  cipher.AEAD
		)
		sizep++

		io.ReadFull(rand.Reader, key)
		if block, err = aes.NewCipher(key); err != nil {
			panic(err)
		}

		io.ReadFull(rand.Reader, nonce)
		if aead, err = cipher.NewGCM(block); err != nil {
			panic(err)
		}

		var (
			decrypted = make([]byte, (size<<1)+0)
			encrypted []byte
		)

		io.ReadFull(rand.Reader, decrypted)
		encrypted = aead.Seal(nil, nonce, decrypted, nil)

		fmt.Fprintf(f, "Generated vector %d:%s:%s:%s:%s\n",
			i-6,
			tohex(key),
			tohex(nonce),
			tohex(decrypted),
			tohex(encrypted))
	}
}

func generateExchangeVectors(name string, n int) {
	f, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	/*
		Exchange vectors require:
		- 64 bytes of random (to generate 2 256-bit X25519 keys)
		- 64 bytes of local public and secret X25519 keys
		- 64 bytes of peers public and secret X25519 keys
		- 32 bytes of shared secret
	*/
	fmt.Fprintln(f, "# name=exchange vectors")
	fmt.Fprintln(f, "# cols=name:random:localPublic:localSecret:peersPublic:peersSecret:sharedSecret")

	// Start with zero vector
	generateExchangeVector(f, bytes.NewBuffer(zeros[:]), "All zeros")
	generateExchangeVector(f, bytes.NewBuffer(fulls[:]), "All 0xff")
	for i := 2; i < n; i++ {
		generateExchangeVector(f, rand.Reader, fmt.Sprintf("Generated vector %d", i-2))
	}
}

func maskX25519(secret [32]byte) {
	// https://tools.ietf.org/html/rfc7748#section-5
	secret[0x00] &= 0xf8
	secret[0x1f] &= 0x7f
	secret[0x1f] |= 0x40
}

func generateExchangeVector(w io.Writer, r io.Reader, name string) {
	var (
		random                   = make([]byte, 64)
		localPublic, localSecret [32]byte
		peersPublic, peersSecret [32]byte
		sharedSecret             [32]byte
		sharedKey                []byte
	)
	if _, err := io.ReadFull(r, random); err != nil {
		panic(err)
	}

	// Generate local key
	copy(localSecret[:], random[:32])
	maskX25519(localSecret)
	curve25519.ScalarBaseMult(&localPublic, &localSecret)

	// Generate peers key
	copy(peersSecret[:], random[32:])
	maskX25519(peersSecret)
	curve25519.ScalarBaseMult(&peersPublic, &peersSecret)

	// Generate shared key
	curve25519.ScalarMult(&sharedSecret, &localSecret, &peersPublic)
	sharedKey = pbkdf2.Key(sharedSecret[:], nil, 4096, 32, sha256.New)

	fmt.Fprintf(w, "%s:%s:%s:%s:%s:%s:%s\n",
		name,
		tohex(random),
		tohex(localPublic[:]), tohex(localSecret[:]),
		tohex(peersPublic[:]), tohex(peersPublic[:]),
		tohex(sharedKey))
}

func generateStreamVectors(name string, n int) {
	f, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	/*
		Stream vectors require:
		- 16, 24 or 32 bytes AES key
		- 28 bytes or random (12 bytes AES-GCM nonce, 16 bytes AES-CTR counter)
		- arbitrary-sized decrypted message
		- arbitrary-sized encrypted message + 12 bytes AES-GCM nonce + 16 bytes encrypted AES-CTR counter + 16 bytes AES-GCM tag
	*/
	fmt.Fprintln(f, "# name=stream vectors")
	fmt.Fprintln(f, "# cols=name:key:random:decrypted:encrypted")

	// Fixed test suites:
	fmt.Fprint(f, `# Fixed tests:
NIST AES-128 empty:00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000::0000000000000000000000000388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf
NIST AES-128 zeros:00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000:00000000000000000000000000000000:0000000000000000000000000388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf66e94bd4ef8a2c3b884cfa59ca342b2e
NIST AES-128:feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf88800000000000000000000000000000000:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255:000000000000000000000000804e0e5cdebeaa72a002652c1518f3adc5d01e1553cc7566b5213c03f25da3fac6737b188d8d24f905eb254aeb38aa9fb4e0b118297b9e7e63f0e2150d8a3e6a878e20724c9b7b92c1e4265662834723d4676589933bb56da1ee3527b932f909
NIST AES-256 empty:0000000000000000000000000000000000000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000::000000000000000000000000cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919
NIST AES-256 zeros:0000000000000000000000000000000000000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000:00000000000000000000000000000000:000000000000000000000000cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919dc95c078a2408989ad48a21492842087
NIST AES-256:feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308:cafebabefacedbaddecaf88800000000000000000000000000000000:d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255:00000000000000000000000005ee47610126e39acfe381b8395c4b8692d6d2b154d5294200950d8f1aa037d8b51e3fac2e14c20e8ae908a5e3addb077b8b0345b0b7d9ac845f1c29d9df500c9720ff40f4ba72b17ee93042ccd7d1c253f7c87a00dcd144e1b7e9b9b5cb898d
`)
}
