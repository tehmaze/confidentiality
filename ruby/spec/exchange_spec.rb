require 'confidentiality'
require 'socket'

RSpec.describe Confidentiality, "message" do
  File.readlines('../testdata/exchange_test.txt').each do |line|
    line.chomp!
    next if line.empty?
    next if line.start_with? '#'
    
    part = line.split(':')
    r1, d1, x1, y1, r2, d2, x2, y2, shared = part.map do |hex|
      hex_to_bin(hex)
    end

    k1 = OpenSSL::PKey::EC.new('prime256v1')
    k1.private_key = OpenSSL::BN.new(bin_to_hex(d1), 16)
    k1.public_key = OpenSSL::PKey::EC::Group.new('prime256v1').generator.mul(k1.private_key)
    
    describe ".exchange" do
      # Mock OpenSSL::PKey::EC.generate to return our loaded private key
      before { 
        allow(OpenSSL::PKey::EC).to receive(:generate).and_return(k1)
      }
        
      it "returns shared key #{bin_to_hex(shared)}" do
        class Stream
          def initialize(data)
            @r = data
            @w = ''
          end

          def recv(size)
            br = @r[0..size - 1]
            @r = @r[size..@r.length - 1]
            br
          end

          def send(data)
            @w = @w + data
          end

          def written
            @w
          end
        end

        # Mock that peer sent the public key on (x2, y2)
        socket = Stream.new("\x04" + x2 + y2)

        # Make the exchange
        result = Confidentiality.exchange(socket)

        # Match written data in the exchange with what we expected
        expect(socket.written()).to eq("\x04" + x1 + y1)

        # Match generated shared key with what we expected
        expect(result).to be_an_instance_of(String).and eq(shared)
      end
    end
  end
end