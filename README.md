# SCryptoPy

[![CI Status](https://github.com/kdrobnyh/scryptopy/actions/workflows/ci.yml/badge.svg)](https://github.com/kdrobnyh/scryptopy/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/kdrobnyh/scryptopy/branch/main/graph/badge.svg?token=GTEAV3X2Z0)](https://codecov.io/gh/kdrobnyh/scryptopy)
[![PyPI](https://img.shields.io/pypi/v/scryptopy.svg)](https://pypi.org/project/scryptopy/)
[![license](http://img.shields.io/badge/license-GNU-blue.svg)](https://raw.githubusercontent.com/kdrobnyh/scryptopy/main/LICENSE)

Salted Crypto Python library.
Allows to encrypt and decrypt files and directories using popular cryptographic algorithms with salty passphrases.

## Purpose

This library allows to securely encrypt and decrypt files and directories, using different passphrase for each encrypted item. The idea is to use just one file (keyfile) for encryption and decryption, but different passphrases are used for each encrypted item internally. One of the possible applications is an encryption of the backup that is uploaded to publically available cloud services (like Dropbox, Google Drive, OneDrive). This library also provides CLI (command-line interface).

## Keyfiles

### Structure (technical details)

Keyfile should describe an object with the following parameters:

- **keys** is an array of keys. Should contain at least one element. Each element has the following format:
    - **key** is an array of encryption stages:
        - **stage** is an object with the following parameters:
            - **algorithm** is a name of encoding algorithm (see [supported encryption algorithms](#supported-encryption-algorithms));
            - **passphrase_template** is a passphrase template (see [salts and passphrases](#salts-and-passphrases));
            - **num_salts** is a number of the used salts. Although all the salts are generated and stored for each file, passphrase template might use any subset of them (see [salts and passphrases](#salts-and-passphrases)). Should be less than 256;
- **data_key_index** is an index of **key** in **keys** that is going to be used for data encryption;
- **filename_key_index** is an index of element in **keys** that is going to be used for filename encryption;
- **dirname_key_index** is an index of element in **keys** that is going to be used for directory name encryption.

Array indices always start with 0. Note that indices for data, filename and dirname are not required to be different from each other.

### Example

Keyfiles are represented as [json](https://www.json.org/json-en.html) files.
Note: passphrase templates used here are just examples. Do not use them in your own keyfiles!

```
{
    'keys':
    [
        [
            {
                'algorithm': 'TWOFISH',
                'passphrase_template': 'WYGkxg4s4rzxj{salt1}qwsYrP8G{salt0}BaxNxGnUh',
                'num_salts': 2
            },
            {
                'algorithm': 'AES256',
                'passphrase_template': 'pvOKLChPDN{salt4}iD6sPqGo7dUdbshYgh7',
                'num_salts': 5
            },
            {
                'algorithm': 'AES256',
                'passphrase_template': 'yaWgfEnF17vmkzr0s6d{salt4}W0uKami485Z',
                'num_salts': 7
            }
        ],
        [
            {
                'algorithm': 'AES256',
                'passphrase_template': 'voS8tfqiSvsulLSh5xfaBssx1p80GF',
                'num_salts': 0
            }
        ],
        [
            {
                'algorithm': 'AES256',
                'passphrase_template': 'Wth4Oco2518uiEp{salt3}Ykn2Cfts80mj5Qo',
                'num_salts': 5
            }
        ]
    ],
    'data_key_index': 0,
    'filename_key_index': 2,
    'dirname_key_index': 1
}
```

## Encryption details

### Supported encryption algorithms

This tool uses [gpg](https://gnupg.org/) internally. Check *Cipher* section of `gpg --version` to see which symmetric cipher algorithms are supported. E.g., in version 2.2.32, the following algorithms are listed: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH, CAMELLIA128, CAMELLIA192, CAMELLIA256.

### Encryption

Data is encrypted in several stages. If encryption key specified in keyfile has more than one stage, data is encrypted using keys consecutively: first, data is encrypted using the first stage key. Then, new encrypted data is encrypted using the second stage key. The process goes on until there are no more stages left. Decryption works in the same way, but in reversed order.

### Salts and passphrases

Ideally, passphrases should be unique for each file. This library achieves this by using salts. Salts are generated randomly for each file (number of salts should be specified) and are used to replace `{salt[X]}` structures in passphrase templates, where `[X]` is a salt index (array indices start from 0). Note that passphrase template might use any subset of salts, even though all of them are generated and stored in each encrypted file (see [encrypted file structure](#encrypted-file-structure)).

Let's consider an example. Imagine the following stage: `{'algorithm': 'TWOFISH', 'passphrase_template': 'something{salt1}else{salt3}here', 'num_salts': 5}`. If randomly generated salts for some file are `['banana', 'pineapple', 'grape', 'orange', 'grape']`, then the passphrase is `somethingpineappleelseorangehere`.

### Hashes

Comparison of an encrypted file to an unencrypted one might take long time, because it requires decryption. To speed it up, the tool uses hashes. Encrypted file contains hash of its encrypted content, which can be accessed without decryption directly. Then, only hash of unencrypted file should be calculated to compare. In the current version, only SHA-256 is supported.

### Filename encryption

The tool uses random [urlsafe](https://en.wikipedia.org/wiki/Percent-encoding) strings of length 32 as file names of encrypted files. Encrypted files contain their corresponding original names internally, also encrypted. Since original filenames should be decrypted for file comparison, one might want to use a faster encryption for that purpose (faster algorithms or less number of used algorithms).

### Encrypted file structure

The following tables constitute a formal description of the encrypted file format.

| ENCRYPTED_FILE |  |
| - | - |
| PREFIX | "SCryptoPy", ASCII marker |
| CONTENT_BLOCK* | Zero or more content blocks |

| CONTENT_BLOCK |  |
| - | - |
| BLOCK_TYPE | One byte block type marker |
| BLOCK_LENGTH | One or more bytes that encode length of CONTENT_DATA block. Each byte encodes 7 bit of information. The last byte should start with bit 0, all the others should start with bit 1. E.g., length `15` is `00001111` and represented as one byte `0F` (`00001111`), length `255` is `11111111` and represented as two bytes `81 7F` (`10000001 01111111`). |
| CONTENT_DATA | Contains data that corresponds to BLOCK_TYPE. Should have BLOCK_LENGTH length. |

One byte block type marker can have one of the following values:

* `00`: filename;
* `01`: directory name;
* `03-FD`: reserved;
* `FE`: SHA-256 hash;
* `FF`: data.

| CONTENT_DATA (for filename BLOCK_TYPE) |  |
| - | - |
| ENCRYPTED_CONTENT | Encrypted original filename |

| CONTENT_DATA (for directory name BLOCK_TYPE) |  |
| - | - |
| ENCRYPTED_CONTENT | Encrypted directory name |

| CONTENT_DATA (for hash BLOCK_TYPE) |  |
| - | - |
| DATA | Unencrypted hash of the encrypted data |

| CONTENT_DATA (for data BLOCK_TYPE) |  |
| - | - |
| ENCRYPTED_CONTENT | Encrypted data |

| ENCRYPTED_CONTENT |  |
| - | - |
| SALT* | Zero or more salts |
| ENCRYPTED_DATA | Encrypted data |

| SALT |  |
| - | - |
| RANDOM_SALT | Random salt in binary format |
| ZERO_BYTE | Zero byte `00` |

### Encrypted directory structure

If directories are encrypted, then random [urlsafe](https://en.wikipedia.org/wiki/Percent-encoding) strings of length 32 are used as names of encrypted directories. Each encrypted directory contains `__index__` file with encrypted original directory name. If directories are not encrypted, names of encrypted directories are the same as unencrypted and no index file needed.

## CLI usage

SCryptoPy is composed of multiple commands, similar to `git`.

### Common arguments

* `-v, --verbose` - Enable verbose debug output
* `-p, --print_arguments` - Print arguments and exit the script
* `-ded, --no_encrypt_dirnames` - Do not encrypt directory names

### `encrypt` arguments

`scryptopy [-v] [-p] [-ded] encrypt INPUT OUTPUT KEYFILE [-s] [-dc]`

* `INPUT` - Input file or directory to encrypt
* `OUTPUT` - Output file or directory to place the encrypted files
* `KEYFILE` - Path to the keyfile
* `-s, --sync` - Synchronize input and output. Any files in output that do not have corresponding inputs are removed
* `-dc, --double_check` - Double check the encryption. Takes a little bit more time, but ensures that encrypted files can be decrypted and are identical to the corresponding input files

### `decrypt` arguments

`scryptopy [-v] [-p] [-ded] decrypt INPUT OUTPUT KEYFILE [-s]`

* `INPUT` - Input file or directory to decrypt
* `OUTPUT` - Output file or directory to place the decrypted files
* `KEYFILE` - Path to the keyfile
* `-s, --sync` - Synchronize input and output. Any files in output that do not have corresponding inputs are removed

### `check` arguments

`scryptopy [-v] [-p] [-ded] check UNENCRYPTED ENCRYPTED KEYFILE`

* `UNENCRYPTED` - Unencrypted file or directory
* `ENCRYPTED` - Encrypted file or directory
* `KEYFILE` - Path to the keyfile

## Contribution

Ways to contribute:

* Suggest a feature
* Report a bug
* Fix something and open a pull request
* Spread the word

## Authors

Developed with passion by [Klim Drobnyh](mailto:klim.drobnyh@gmail.com).

## License

Copyright &copy; 2021 Klim Drobnyh.

All code is licensed under the GPL, v3 or later. See LICENSE file for details.
