require 'confidentiality'

RSpec.describe Confidentiality, "message" do
  File.readlines('../testdata/message_test.txt').each do |line|
    line.chomp!
    next if line.empty?
    next if line.start_with? '#'
    
    part = line.split(':')
    name = part[0]
    key, iv, decrypted, encrypted = part[1..part.length - 1].map { |hex| hex_to_bin(hex) }

    context name do
      skip unless decrypted

      describe ".encrypt" do
        it "encrypts a message with key" do
          allow(Confidentiality).to receive(:encrypt).with(message: decrypted, key: key).and_call_original
        end

        # TODO: how to mock random???
        #it "encrypts to #{bin_to_hex(iv) + bin_to_hex(encrypted)}" do
        #  expect(Confidentiality.encrypt(decrypted, key)).to eq iv + encrypted
        #end
      end

      describe ".decrypt" do
        it "decrypts a message with key" do
          allow(Confidentiality).to receive(:decrypt).with(message: encrypted, key: key).and_call_original
        end

        it "decrypts to #{bin_to_hex(decrypted)}" do
          skip unless encrypted
          expect(Confidentiality.decrypt(iv + encrypted, key)).to be_an_instance_of(String).and eq decrypted
        end
      end
    end
  end

  describe ".encrypt" do
    it "requires a 16 or 32 byte key" do
      expect { Confidentiality.encrypt('test', 'test') }.to raise_error(RuntimeError)
    end
  end
end