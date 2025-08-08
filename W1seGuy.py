# solution for W1seGuy challenge from tryhackme.compile
# link: https://tryhackme.com/room/w1seguy

import string
import sys
from itertools import product

def xor_key_cipher(key, cipher_bytes):
    return ''.join([chr(ord(key[i % len(key)])^c) for i,c in enumerate(cipher_bytes)])

def find_key_prefix(cipher_bytes, known_prefix):
    return xor_key_cipher(known_prefix, cipher_bytes[:len(known_prefix)])

def brute_force(cipher, known_prefix="THM{", known_postfix="}"):
    cipher_bytes = bytes.fromhex(cipher)
    key_start = find_key_prefix(cipher_bytes, known_prefix)
    print(f"Recover the prefix of the key: {key_start}")

    postfix_key_length = 5 - len(key_start) # as mentioned that the key size is 5

    charset = string.ascii_letters + string.digits

    # print(charset)
    for i in product(charset, repeat=postfix_key_length):
    #    print(i)
        for x in i:
            key = key_start
            key = key + x

            decrypted_text = xor_key_cipher(key, cipher_bytes)

            if(decrypted_text.endswith(known_postfix)):
                # decrypted[key].add(decrypted_text)
                print(f"The lost key is: {key} and the flag is: {decrypted_text}")

brute_force(sys.argv[1])