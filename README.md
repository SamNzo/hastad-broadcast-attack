# hastad-broadcast-attack
Hastad's broadcast attack on RSA for public exponent 3.
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
