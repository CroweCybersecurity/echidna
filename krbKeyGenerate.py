#!/usr/bin/env python
import argparse
from krb5 import crypto

def main(username, password, domain, john):

    # Setup Constants
    salt = domain.upper() + username
    out_salt = domain.upper() + "\\" + username
    iterations = '\x00\x00\x10\x00'
    keys = []

    # AES-256
    key = crypto.string_to_key(crypto.Enctype.AES256, password, salt, iterations)
    if john:
        cid = 18
        out = "$krb%s$%s%s$%s" % (cid, domain.upper(), username, (key.contents).encode("hex"))
    else:
        out = "%s:aes256-cts-hmac-sha1-96:%s" % (out_salt, (key.contents).encode("hex"))
    keys.append(out)

    # AES-128
    key = crypto.string_to_key(crypto.Enctype.AES128, password, salt, iterations)
    if john:
        cid = 17
        out = "$krb%s$%s%s$%s" % (cid, domain.upper(), username, (key.contents).encode("hex"))
    else:
        out = "%s:aes128-cts-hmac-sha1-96:%s" % (out_salt, (key.contents).encode("hex"))
    keys.append(out)

    # DES
    key = crypto.string_to_key(crypto.Enctype.DES_MD5, password, salt)
    if john:
        cid = 3
        out = "$krb%s$%s%s$%s" % (cid, domain.upper(), username, (key.contents).encode("hex"))
    else:
        out = "%s:des-cbc-md5:%s" % (out_salt, (key.contents).encode("hex"))
    keys.append(out)

    # RC4
    key = crypto.string_to_key(crypto.Enctype.RC4, password, None)
    if not john:
        out = "%s:rc4_hmac:%s" % (out_salt, (key.contents).encode("hex"))
        keys.append(out)

    return keys

if __name__ == '__main__':

    # Command line arguments
    parser = argparse.ArgumentParser(description="Kerberos Key Generator")
    parser.add_argument('-u', '--user', required=True, dest='username', help='Case sensitive Username')
    parser.add_argument('-p', '--password', required=True, dest='password', help='Password for user')
    parser.add_argument('-d', '--domain', required=True, dest='domain', help='Domain')
    parser.add_argument('-j', '--john', dest='john', action='store_true', help='Output jtr format')
    args = parser.parse_args()

    keys = main(args.username, args.password, args.domain, args.john)
    for key in (keys):
        print key
