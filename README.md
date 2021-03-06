# Confidentiality [![License: MIT][license_img]][license_url] [![Build Status][build_img]][build_url] [![Go Documentation][godoc_img]][godoc_url]

[license_img]: https://img.shields.io/badge/License-MIT-yellow.svg
[license_url]: https://opensource.org/licenses/MIT
[build_img]: https://travis-ci.org/tehmaze/confidentiality.svg?branch=master
[build_url]: https://travis-ci.org/tehmaze/confidentiality
[godoc_img]: https://godoc.org/github.com/tehmaze/confidentiality/go?status.svg
[godoc_url]: https://godoc.org/github.com/tehmaze/confidentiality/go

Portable, secure by default cryptography.

**Important**: This library is *not a substitution for well seasoned TLS 
implementations* and only exists as a supplementary means of offering 
cryptographic primitives. Make sure you understand the limitations of each
function before you use them.

**Project state**: Unstable, we're still working on the API and used algorithms.

## Supported languages

| Language     | Version         | Remarks                           |
| ------------ | --------------- | --------------------------------- |
| [C]          | `c99`           | Requires [mbedTLS] `>= 2.1.0` or [OpenSSL] `>= 1.0.0` |
| [Go]         | `>= 1.10`       |                                   |
| [Javascript] | `node.js >= 11` | Browsers with [WebCrypto] support |
| [Python]     | `>= 3.4`        |                                   |
| [Ruby]       | `>= 2.5`        |                                   |

[C]:          c/
[mbedTLS]:    https://tls.mbed.org
[OpenSSL]:    https://www.openssl.org
[Go]:         go/
[Javascript]: javascript/
[Python]:     python/
[Ruby]:       ruby/
[WebCrypto]:  https://caniuse.com/#feat=cryptography

## Used algorithms

| Algorithm           | Usage                                     |
| ------------------- | ----------------------------------------- |
| [HMAC-SHA256]       | Message authentication                    |
| [AES]               | Block encryption                          |
| [AES-GCM]           | Message and iv encryption (authenticated) |
| [AES-GCM]+[AES-CTR] | Stream encryption                         |
| [X25519]+[PBKDF2]   | Key exchange (KEX)                        |

[HMAC-SHA256]: https://en.wikipedia.org/wiki/HMAC
[AES]:         https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Security
[AES-GCM]:     https://en.wikipedia.org/wiki/Galois/Counter_Mode
[AES-CTR]:     https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
[X25519]:      https://en.wikipedia.org/wiki/Curve25519
[PBKDF2]:      https://en.wikipedia.org/wiki/PBKDF2

## Backward compatibility

Confidentiality will be released using [semantic versioning]. Releases on the
a new major release may introduce algorithm changes that are not compatible
with releases on previous major releases. New major versions *may* be compatible
with older releases, unless there are security concerns for supporting older
algorithms.

The `0` major release has no promise of backward compatibility and are used to
field test algorithm changes.

[semantic versioning]: https://semver.org/

## Message authentication

Using HMAC-SHA256.

### Signing

```
sign(message, key) -> signed message
```

### Verifying

```
verify(signed message, key) -> [error]
```

## Key exchange

Using Elliptive Curve Diffie-Helman (ECDH) key exchange.

### Shared key

```
exchange(readable & writable stream) -> key
```

## Message encryption

Using AES-128-GCM.

### Encrypting

```
encrypt(message, key) -> encrypted message
```

### Decrypting

```
decrypt(encypted message, key) -> message
```

## Stream encryption

Using AES-128-GCM for IV hand over and AES-128-CTR for stream encryption.

### Encrypting

```
encrypter(writable stream, key) -> writable stream
```

### Decrypting

```
decrypter(readable stream, key) -> readable stream
```

### Secure a stream

Performs a key exchange and switches to encrypted/decrypted streams for
writing/reading to/from the stream.

```
secure(readable & writable stream) -> readable & writable stream
```