# confidentiality

Portable, secure by default cryptography.

## Message authentication

Using HMAC-SHA1.

### Signing

```
sign(message, key) -> signed message
```

### Verifying

```
verify(signed message, key) -> [error]
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

Using AES-128-GCM for IV negotiation and AES-128-CTR for stream encryption.

### Encrypting

```
encrypt(stream, key) -> stream
```

### Decrypting

```
decrypt(stream, key) -> stream
```