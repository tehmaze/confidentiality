require 'confidentiality'
require 'socket'

RSpec.describe Confidentiality, "message" do
  File.readlines('../testdata/exchange_test.txt').each do |line|
    line.chomp!
    next if line.empty?
    next if line.start_with? '#'
    
    part = line.split(':')
    r1, k1, p1, r2, k2, p2, shared = part.map do |hex|
      hex_to_bin(hex)
    end

    describe ".exchange" do
      # Mock OpenSSL::PKey::EC.generate to return our loaded private key
      before { 
        allow(X25519::Scalar).to receive(:generate).and_return(X25519::Scalar.new(k1))
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

        # Mock that peer sent the public key
        socket = Stream.new("\x19" + p2)

        # Make the exchange
        result = Confidentiality.exchange(socket)

        # Match written data in the exchange with what we expected
        expect(socket.written()).to eq("\x19" + p1)

        # Match generated shared key with what we expected
        expect(result).to be_an_instance_of(String).and eq(shared)
      end
    end
  end
end