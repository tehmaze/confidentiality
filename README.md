# Confidentiality [![License: MIT][license_img]][license_url] [![Build Status][build_img]][build_url] [![Go Documentation][godoc_img]][godoc_url]

[license_img]: https://img.shields.io/badge/License-MIT-yellow.svg
[license_url]: https://opensource.org/licenses/MIT
[build_img]: https://travis-ci.org/tehmaze/confidentiality.svg?branch=master
[build_url]: https://travis-ci.org/tehmaze/confidentiality
[godoc_img]: https://godoc.org/github.com/tehmaze/confidentiality/go?status.svg
[godoc_url]: https://godoc.org/github.com/tehmaze/confidentiality/go

Portable, secure by default cryptography.

## Supported languages

| Language       | Version         | Remarks                             |
| -------------- | --------------- | ----------------------------------- |
| [Go]()         | `>= 1.10`       |                                     |
[ [Javascript]() | `node.js >= 11` | Browsers with [WebCrypto]() support |
| [Python]()     | `>= 3.4`        |                                     |
| [Ruby]()       | `>= 2.5`        |                                     |

[Go]:         go/
[Javascript]: javascript/
[Python]:     python/
[Ruby]:       ruby/
[WebCrypto]:  https://caniuse.com/#feat=cryptography

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

Using Elliptive Curve Diffie-Helman (ECDH) key exchanged, based on the NIST P-256
curve.

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