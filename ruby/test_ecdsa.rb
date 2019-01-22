require 'openssl'

def bin_to_hex(s)
	s.unpack('H*').first
end

def hex_to_bin(s)
	s.scan(/../).map { |x| x.hex }.pack('c*')
end

d = 'ffbdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
x = hex_to_bin('3b889194d386236551b34dc648f891426cc0ab2b499612266637d29c772b9f06')
y = hex_to_bin('85246e98e36d081c006ff1b1b2a28ed31c8f999f2d2d56b37faa20b7887dd7e3')

group = OpenSSL::PKey::EC::Group.new('prime256v1')
key = OpenSSL::PKey::EC.new(group)
key.private_key = OpenSSL::BN.new(d, 16)
key.public_key = group.generator.mul(key.private_key)
puts key
puts key.private_key
puts key.private_key.to_s(16)
puts key.public_key
puts key.public_key.to_bn.to_s(16)

peers_key_bn = "\x04" + x + y
puts bin_to_hex(peers_key_bn.to_s)
peers_key = OpenSSL::PKey::EC::Point.new(group, peers_key_bn)
puts peers_key.methods
puts peers_key.to_bn.to_s(16)

puts peers_key.mul(key.private_key).to_bn.to_s(16)[2..65]