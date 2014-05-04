import base64
import encodings.hex_codec
import re
import collections
import difflib
from itertools import imap
import operator

def bin(s):
	return str(s) if s<=1 else bin(s>>1) + str(s&1)

def bin8(s):
	return ("%8s" % (bin(s))).replace(' ','0')

def hamming_distance(a, b):
	s1 = ''.join([bin8(ord(c)) for c in a])
	s2 = ''.join([bin8(ord(c)) for c in b])
	return sum(imap(operator.ne, s1, s2))

def hex_decode(hexstr):
	return encodings.hex_codec.hex_decode(hexstr)[0]

def hex_encode(binarystr):
	return encodings.hex_codec.hex_encode(binarystr)[0]

def b64_to_hex(s):
	return hex_encode(base64.b64decode(s))

def hex_to_b64(s):
	return base64.b64encode(hex_decode(s))

def xorstr(crypt, key):
	return hex_encode(xor_binary(hex_decode(crypt), hex_decode(key)))

def xor_binary(binary_crypt, binary_key):
	if len(binary_key) < binary_crypt:
		binary_key = binary_key * ((len(binary_crypt)/len(binary_key))+1)
	return ''.join([chr(ord(x) ^ ord(y)) for (x,y) in zip(binary_crypt, binary_key)])

def find_simple_xor(crypt):
	# How do we know if we found a plaintext?
	# Lets start by eliminating anything non-printable
	binary_crypt = hex_decode(crypt)
	key_len = len(binary_crypt)
	possibilities = []
	for key in range(255):
		keystr = chr(key)*key_len
		plaintext = xor_binary(binary_crypt, keystr)
		if score(plaintext) > 2:
			possibilities.append(plaintext)
	return possibilities

def find_key_length(crypt):
	best_guess = 0
	best_distance = 99999
	for length in range(2,4):
		blocklist = []
		for block in range(0,2):
			blocklist.append(crypt[block*length:block*length+length])
		l = [basic.hamming_distance(b1,b2) for (b1, b2) in blocklist.zip(blocklist)]
		avg_distance = sum(l)/len(l)
		if avg_distance < best_distance:
			best_distance = avg_distance
			best_guess = length

	return best_guess



class FailScoringException(Exception):
	pass


def freq(s):
	count = collections.Counter(s.lower())
	return ''.join([a for (a,b) in count.most_common(26)])

def space_count(plaintext):
	count = plaintext.count(' ')
	if count > 4:
		return 2
	if count > 2:
		return 1
	return 0

def badwords(plaintext):
	# Finding any of these unprintable characters means its definately not plaintext
	matcher = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7B-\xFF]')
	if not matcher.search(plaintext):
		return 0
	raise FailScoringException

def frequency(plaintext):
	best = difflib.get_close_matches('a egihjmoNpsrutwyn', [freq(plaintext)], 3, 0.2)
	if best:
		return 1
	return 0


def common_words(plaintext):
	wordlist = ['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have']
	word_score = 0.5
	present = [plaintext.count(' '+word+' ')>0 for word in wordlist]
	total = word_score * len(filter(lambda x: x, present))
	return int(min(round(total), 2))

def score(plaintext):
	try:
		rules = [badwords, space_count, frequency, common_words]
		scores = [rule(plaintext) for rule in rules]
		print plaintext," -> ",scores
		return sum(scores)
	except FailScoringException:
		return 0