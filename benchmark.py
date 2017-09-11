#!/usr/bin/env python
import time
import argparse
import hashlib,binascii
import krbKeyCrack
import krbKeyGenerate

if __name__ == '__main__':

    # Command line arguments
    parser = argparse.ArgumentParser(description="Kerberos POC Benchmark")
    parser.add_argument('wordlist', nargs='?', default = "/usr/share/wordlists/rockyou.txt", help='Input wordlist')
    args = parser.parse_args()
    if not args.wordlist:
        parser.print_help()
        sys.exit(2)

    # Setup Static Info
    username = "normal"
    password = "password1"
    domain = "internal.corp".upper() # case sensitive
    wordlist = args.wordlist

    # Generate Kerberos Keys
    keys = krbKeyGenerate.main(username, password, domain)

    # Loop through Keys and Record Time
    for key in reversed(keys):
        ts = time.time()
        krbKeyCrack.main(wordlist, key)
        te = time.time()
        elapsed_time = te - ts
        print "[+] Elapsed Time: %s\n" % str(elapsed_time)
