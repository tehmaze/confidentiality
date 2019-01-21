# confidentiality

Portable, secure by default cryptography.

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