require 'base64'
require 'test/unit'

class CryptString
	attr_accessor :raw

	def initialize(raw)
		@raw = raw
	end

	def hex
		[@raw].pack('H*')
	end

	def char_array
		hex.unpack('C*')
	end

	def b64
		Base64.strict_encode64(hex)
	end

	def self.from_char_array(char_array)
		self.new(char_array.pack('C*').unpack('H*')[0])
	end

	def xor(rhs)
		CryptString.from_char_array(char_array.zip(rhs.char_array).map { |c1,c2| c1 ^ c2 })
	end
end

class Cracker
	LETTER_FREQ = "etaoinshrdlcumwfgypbvkjxqz"

	def letter_freq(s)
		counts = {}
		s.each { |letter|
			if counts[letter] then counts[letter] += 1
			else counts[letter] = 1 end
		}
		
	def crack_xor(crypt)
		len = crypt.char_array.length
		255.times { |key|
			keystring = ([key].pack('C*').unpack('H*')*len).join
			guess = crypt.xor(CryptString.new(keystring))

		}
	end
end


class Challenge1Test < Test::Unit::TestCase
	def test_conversions
		s1 = CryptString.new("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
		assert_equal("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", s1.b64)
	end

	def test_xor
		s1 = CryptString.new("1c0111001f010100061a024b53535009181c")
		s2 = CryptString.new("686974207468652062756c6c277320657965")
		assert_equal("746865206b696420646f6e277420706c6179", s1.xor(s2).raw)
	end

	def test_cracker
		s1 = CryptString.new("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
		cracker = Cracker.new()
		assert_equal("expected", cracker.xor(s1))
	end

end