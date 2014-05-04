import unittest
import basic

class Challenge1Tests(unittest.TestCase):
    def test_helpers(self):
        self.assertEqual('010203',basic.hex_encode('\x01\x02\x03'))
        self.assertEqual('abc', basic.hex_decode('616263'))

    def test_base_64(self):
        start = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        self.assertEqual(expected, basic.hex_to_b64(start))
        self.assertEqual(start, basic.b64_to_hex(expected))

    def test_xorsum(self):
        start = '1c0111001f010100061a024b53535009181c'
        key = '686974207468652062756c6c277320657965'
        expected = '746865206b696420646f6e277420706c6179'

        self.assertEqual(expected, basic.xorstr(start, key))
        self.assertEqual(start, basic.xorstr(expected, key))

    def test_find_simple_xor(self):
        encoded = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        result = basic.find_simple_xor(encoded)
        print "Found result: ",result
        self.assertEqual('Cooking MC\'s like a pound of bacon', result[0])

    def test_find_simple_xor_from_file(self):
        f = file('test-file1.txt')
        answer = None
        for l in f:
            result = basic.find_simple_xor(l.strip())
            if result:
                print l,"->",result
                answer = result
        self.assertEqual('Now that the party is jumping\n', answer[0])

    def test_repeating_encryption(self):
        plaintext = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
        expected = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
        key = 'ICE'
        self.assertEqual(expected, basic.hex_encode(basic.xor_binary(plaintext, key)))

    def test_hamming_distance(self):
        s1 = 'this is a test'
        s2 = 'wokka wokka!!!'
        actual = basic.hamming_distance(s1, s2)
        self.assertEqual(37, actual)

    def find_key_size(self):
        key = 'dayz'
        crypt = basic.xor_binary('this is a test', key)
        expected = len(key)
        self.assertEqual(expected+1, basic.find_key_length(crypt))
