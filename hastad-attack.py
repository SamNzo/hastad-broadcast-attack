from Cryptodome.Util.number import long_to_bytes, inverse
from Cryptodome.PublicKey import RSA
from binascii import hexlify
from math import gcd
import argparse
import base64
import gmpy2

def chinese_remainder_theorem(congruences):
    # Extract the moduli and residues from the congruences
    moduli = [modulus for _, modulus in congruences]
    residues = [residue for residue, _ in congruences]

    # Compute the product of all moduli
    N = 1
    for modulus in moduli:
        N *= modulus

    # Compute the solution using the CRT
    result = 0
    for residue, modulus in congruences:
        Ni = N // modulus
        Mi = inverse(Ni, modulus)
        result += residue * Ni * Mi

    # Reduce the solution modulo N
    result %= N

    return result

def get_public_keys():
    with open(args.publickeys[0], "rb") as f:
        k1 = RSA.import_key(f.read())
        n1 = k1.n
        e1 = k1.e
        f.close()

    with open(args.publickeys[1], "rb") as f:
        k2 = RSA.import_key(f.read())
        n2 = k2.n
        e2 = k2.e
        f.close()    

    with open(args.publickeys[2], "rb") as f:
        k3 = RSA.import_key(f.read())
        n3 = k3.n
        e3 = k3.e
        f.close()

    if gcd(n1, n2) != gcd(n1, n3) != gcd(n2, n3) != 1:
        raise Exception("All 3 moduli must be coprimes!")
    
    if e1 != e2 != e3:
        raise Exception("All 3 public exponent must be equal!")
    
    return n1, n2, n3, e1

def get_ciphertexts():
    with open(args.ciphertexts[0], "r") as f:
        c1 = f.read()
        if args.base64:
            c1 = base64.b64decode(c1)
            c1 = int(hexlify(c1), 16)
        else:
            c1 = int(c1)

    with open(args.ciphertexts[1], "r") as f:
        c2 = f.read()
        if args.base64:
            c2 = base64.b64decode(c2)
            c2 = int(hexlify(c2), 16)
        else:
            c2 = int(c2)

    with open(args.ciphertexts[2], "r") as f:
        c3 = f.read()
        if args.base64:
            c3 = base64.b64decode(c3)
            c3 = int(hexlify(c3), 16)
        else:
            c3 = int(c3)

    return c1, c2, c3

def nth_root(x, n):
    precision = gmpy2.get_context().precision
    gmpy2.get_context().precision = precision + 1000  # Set precision higher for accuracy

    root = gmpy2.cbrt(x) if n == 3 else gmpy2.root(x, n)
    rounded_root = gmpy2.mpfr(root)  # Round the result to the nearest integer

    gmpy2.get_context().precision = precision  # Restore original precision

    return int(rounded_root)

def main():
    n1, n2, n3, e = get_public_keys()
    c1, c2, c3 = get_ciphertexts()

    # Chinese Remainder Theorem
    m = chinese_remainder_theorem([(c1,n1), (c2,n2), (c3,n3)])
    # 3rd root
    m = nth_root(m, e)

    print(long_to_bytes(m)) 

if __name__ == "__main__":
    # python3 ./hastad-attack.py -k <pubkey1> <pubkey2> <pubkey3> -c <cipher1> <cipher2> <cipher3> -b64
    parser = argparse.ArgumentParser(
        description="Python implementation of Hastad's broadcast attack for public exponent 3"
    )

    parser.add_argument("-k", "--publickeys", required=True, nargs=3, help="public key pem files")
    parser.add_argument("-c", "--ciphertexts", required=True, nargs=3, help="ciphertext files")
    parser.add_argument("-b64", "--base64", required=False, action="store_true", help="use this option if ciphertexts are encoded with base64")

    args = parser.parse_args()

    main()
