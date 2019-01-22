require 'confidentiality'

def bin_to_hex(s)
  s.unpack('H*').first
end

def hex_to_bin(s)
  s.scan(/../).map { |x| x.hex }.pack('c*')
end

RSpec.describe Confidentiality, "authenticate" do
  File.readlines('../testdata/authenticate_test.txt').each do |line|
    line.chomp!
    next if line.empty?
    next if line.start_with? '#'
    
    part = line.split(':')
    key, message, signature = part.map { |hex| hex_to_bin(hex) }

    context name do
      describe ".sign" do
        it "signs a message with key" do
          allow(Confidentiality).to receive(:sign).with(message: message, key: key).and_call_original
        end

        it "matches signature #{bin_to_hex(signature)}" do
          expect(Confidentiality.sign(message, key)).to eq message + signature
        end
      end

      describe ".verify" do
        it "verifies a message with key" do
          allow(Confidentiality).to receive(:verify).with(message: message + signature, key: key).and_call_original
        end

        it "matches signature #{bin_to_hex(signature)}" do
          expect(Confidentiality.verify(message + signature, key)).to eq true
        end
      end
    end
  end
end