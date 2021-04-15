# css577_encryption 
# Encryption Assignment


## Running the applications

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

## Performance Discussions on PBKDF2
Key derivations are done using PBKDF2 provided in the [PyCryptodome 3.10.1](https://pycryptodome.readthedocs.io/en/latest/)
 library. A simple performance test against the master key derivation was developed to obtain execution time using 
six combinations of SHA algorithm and key-lengths.

The six combinations of six cases are:
1. 128-bit keys generated separately using SHA256 and SHA512, as in the case of doing encryption using AES128
1. 192-bit keys generated separately  using SHA256 and SHA512, as in the case of doing encryption using 3DES
1. 256-bit keys generated separately  using SHA256 and SHA512, as in the case of doing encryption using AES256

Graphs for each combination can be found in `perf/Perf_Analysis.xlsx`. Tests were run with different number of iterations 
from 1000 to 100,000, steps 500. The execution time is growing linearly with respect to the number of iterations. The 
worst case was about 0.075 secs.

Further into finding an optimal number of iterations between performance and security, three encryption tests were run on
files of three different sizes, encrypt using AES256 and SHA256 with 100,000 iterations in the KDF function, summarizing in the following table:

| File               | Size            | Time Encryption | Time Decryption
| :-----------------:| :-------------: | --------------: | ----------------
| Excel Workbook     |      11 kB      | 0.729825 secs   | 0.777776 secs
| PNG Image          |     463 kB      | 0.757357 secs   | 0.777106 secs
| PDF                |     9.5 MB      | 0.856867 secs   | 0.851239 secs

The numbers show that the KDF generation is not the bottleneck of the encryption. This program can make configure doing 
key derivation using 100,000 iterations, potentially higher if necessary.