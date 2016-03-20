#!/usr/bin/env python2
import subprocess
import sys
import itertools
import string

def run_openstego(word):
    cmd = ["openstego", "extract", "-sf", sys.argv[1], "-p", word]
    outp = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    if "Extracted" in outp:
        print("[+] found bro!")
        print(outp)
        return True

    return False

def main():
    files = open(sys.argv[2],'r').read()
    lines = []
    words = []

    lines = files.split("\n")
    words = files.split()

    # brute each word
    print("[i] bruting all words in text file")
    for word in words:
        if run_openstego(word):
            print("Password: %s" % word)
            sys.exit(0)

    # brute each movie verbatim
    print("[i] bruting all lines in the text file")
    for line in lines:
        if run_openstego(line):
            print("Password: %s" % line)
            sys.exit(0)

    # brute a four letter word
    print("[i] about to brute all four letter comboz...")
    for b in itertools.product(string.ascii_lowercase + string.ascii_uppercase + string.digits, repeat=4):
        if run_openstego(''.join(b)):
            print("Password: %s" % ''.join(b))
            sys.exit(0)


main()
