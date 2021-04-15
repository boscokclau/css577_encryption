# css577_encryption 
# Encryption Assignment


## Running the programs

###Runtime: python 3.7

###Dependencies: [PyCryptodome 3.10.1](https://pycryptodome.readthedocs.io/en/latest/)

To install, run: 
> `pip3 install pycryptodome`

###Configurations
**Configuration File:** `filecrypto.ini`

`kdf` : KDF function to use. Set to `pbkdf2`, which is the only KDF supported.

`cipher`: Cipher schemes. Values can be: `aes128`, `aes256`, `3des`.

`hash`: HMAC-Hash to use. Values can be: `sha256`, `sha512`.

`iterations`: Number of rounds to derive key in the KDF function. Value can be any non-zero positive integer.

###Encrypt File:
>`python3 fileencrypt.py filename password`

###Decrypt File:
>`python3 filedecrypt.py filename password`

