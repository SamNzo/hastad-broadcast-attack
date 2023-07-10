# hastad-broadcast-attack
Hastad's broadcast attack on RSA for public exponent 3.

---
# Hastad's Broadcast Attack
Hastad's Broadcast Attack targets a scenario where the same message is encrypted using multiple RSA public keys with the different modulus but same small public exponents. By exploiting the Chinese Remainder Theorem, an attacker can recover the original plaintext message without knowledge of the private keys.

The attack steps are as follows:

1. The attacker collects the ciphertexts encrypted using the same modulus but different public exponents.
2. Using the Chinese Remainder Theorem, the attacker combines the ciphertexts to solve a system of congruences.
3. The attacker obtains the original plaintext message by taking the N-th root of the combined solution, where N is the number of ciphertexts.
# Install
```
git clone https://github.com/SamNzo/hastad-broadcast-attack.git
cd hastad-broadcast-attack
pip install -r requirements.txt
```

# Usage
```
python3 ./hastad-attack.py -k <pubkey1> <pubkey2> <pubkey3> -c <cipher1> <cipher2> <cipher3> -b64
```
Arguments for `-k` and `-c` are respectively path to pem files and path to ciphertext files

Use `-b64` if the ciphertexts are base64 encoded.
