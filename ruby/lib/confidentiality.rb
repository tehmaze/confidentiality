require 'openssl'
require 'x25519'

module Confidentiality
  def self.random_bytes(length)
    OpenSSL::Random.pseudo_bytes(length)
  end

  def self.encrypt(message, key)
    raise "Cipher requires a 128 or 256-bit key, got #{key.length<<3}" unless key.length == 16 or key.length == 32
    nonce = self.random_bytes(GCM_NONCE_SIZE)
    cipher = OpenSSL::Cipher.new(self.message_cipher_for(key))
    cipher.encrypt
    cipher.key = key
    cipher.iv = nonce
    ciphertext = nonce
    ciphertext << cipher.update(message) unless message.empty?
    ciphertext << cipher.final
    ciphertext << cipher.auth_tag(GCM_TAG_SIZE)
    return ciphertext
  end

  def self.decrypt(message, key)
    raise "Cipher requires a 128 or 256-bit key, got #{key.length<<3}" unless key.length == 16 or key.length == 32
    nonce = message[0..GCM_NONCE_SIZE - 1]
    ciphertext = message[GCM_NONCE_SIZE..message.bytesize - GCM_TAG_SIZE - 1]
    tag = message[message.bytesize - GCM_TAG_SIZE..message.bytesize - 1]
    cipher = OpenSSL::Cipher.new(self.message_cipher_for(key))
    cipher.decrypt
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_tag = tag
    plaintext = ''
    plaintext << cipher.update(ciphertext) unless ciphertext.empty?
    plaintext << cipher.final
    return plaintext
  end

  def self.sign(message, key)
    hmac = OpenSSL::HMAC.new(key, OpenSSL::Digest::SHA256.new)
    hmac << message
    return message + hmac.digest
  end

  def self.verify(message, key)
    raise 'Message contains no signature' unless message.length >= 32
    
    signature = message[message.length - 32..message.length - 1]
    hmac = OpenSSL::HMAC.new(key, OpenSSL::Digest::SHA256.new)
    hmac << message[0..message.length - 33]
    
    raise 'Signature verification failed' unless self.constant_time_compare(hmac.digest, signature)
    true
  end

  def self.exchange(stream)
    # Generate an emphemeral ECDSA NIST P-256 private key
    #group = OpenSSL::PKey::EC::Group.new('prime256v1')
    #key = OpenSSL::PKey::EC.generate('prime256v1')
    key = X25519::Scalar.generate
  
    # Write the public part on the wire
    self.write_public_key(stream, key.public_key)

    # Read peer's public key from the wire
    peers_public_key = self.read_public_key(stream)
    
    # Compute the scalar product of our private key with peer's
    shared_point = key.multiply(peers_public_key)
    
    # Returns as bytes
    return shared_point.to_bytes
  end

  private 
  
  AES_BLOCK_SIZE = 16
  GCM_NONCE_SIZE = 12
  GCM_TAG_SIZE = 16

  def self.constant_time_compare(a, b)
    return false unless a.bytesize == b.bytesize

    l = a.unpack "C#{a.bytesize}"
    res = 0
    b.each_byte { |byte| res |= byte ^ l.shift }
    res == 0
  end

  def self.message_cipher_for(key)
    return 'aes-128-gcm' if key.length == 16
    return 'aes-256-gcm' if key.length == 32
    raise "Invalid key length #{key.length}"
  end

  def self.read_public_key(stream)
    chunk = stream.recv(33)
    ctype = chunk[0].unpack('c').first
    raise "Peer sent unknown curve type #{ctype.to_s(16)}" unless ctype == 0x19
    X25519::MontgomeryU.new(chunk[1..32])
  end

  def self.write_public_key(stream, public_key)
    stream.send("\x19" + public_key.to_bytes)
  end
end
