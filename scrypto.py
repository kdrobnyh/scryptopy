# Copyright 2021 Klim Drobnyh <klim.drobnyh@gmail.com>

# This file is part of SCryptoPy [Salty Crypto Python library].

# SCryptoPy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# SCryptoPy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


from typing import List, Tuple, Union
import os
import sys
import json
import argparse
import itertools
import logging
import gnupg
from pathlib import Path
from matplotlib import pyplot as plt
from math import sin
import shutil


gpg = gnupg.GPG()
logger = logging.getLogger(__file__)
gnupg_logger = logging.getLogger('gnupg')
gnupg_logger.setLevel(logging.CRITICAL)
findfont_logger = logging.getLogger('matplotlib.font_manager')
findfont_logger.setLevel(logging.CRITICAL)


def read_content(file: Path) -> bytes:
    with open(file, 'rb') as f:
        return f.read()


def write_content(file: Path, content: bytes):
    with open(file, 'wb') as f:
        f.write(content)


def get_encrypted_name(filename: str) -> str:
    return filename + '.scp'


def get_decrypted_name(filename: str) -> str:
    return filename[:filename.rfind('.')]


def load_keys(keyfile: Union[str, Path]):
    keyfile_path = Path(keyfile)
    if not keyfile_path.exists():
        logger.error(f'Key file does not exist, exiting...')
        sys.exit(1)
    with open(keyfile_path) as json_file:
        try:
            keys_loaded = json.load(json_file)
            return keys_loaded
        except Exception as e:
            logger.error('An error occurred while loading the keys...')
            print(e)
            sys.exit(1)


def encrypt(data: bytes, fname: str, keys: List[Tuple[str, str]]) -> Tuple[str, bytes]:
    fnames = [fname] + [get_encrypted_name(fname)] * (len(keys) - 1)
    for i, (fname, (enc_alg, key)) in enumerate(zip(fnames, keys)):
        key = key.format(filename=fname)
        temp = gpg.encrypt(data,
            None,
            passphrase=key,
            armor=False,
            symmetric=enc_alg)
        if not temp.ok:
            logger.error(f'Cannot encrypt input file "{fname}" with "{enc_alg}": "{temp.status}" (stage {i}/{len(keys)})...')
            sys.exit(1)
        data = temp.data
    return fnames[-1], data


def decrypt(data: bytes, fname: str, keys: List[Tuple[str, str]]) -> Tuple[str, bytes]:
    fnames = [fname] * (len(keys) - 1) + [get_decrypted_name(fname)]
    for i, (fname, (enc_alg, key)) in enumerate(zip(fnames, keys[::-1])):
        key = key.format(filename=fname)
        temp = gpg.decrypt(data, passphrase=key)
        if not temp.ok:
            logger.error(f'Cannot decrypt input file "{fname}" with "{enc_alg}": "{temp.status}" (stage {i}/{len(keys)})...')
            sys.exit(1)
        data = temp.data
    return fnames[-1], data


def __get_files(path: Path, root: Path) -> List[Path]:
    if path.is_file():
        return [path.relative_to(root)]
    if path.is_dir():
        return list(itertools.chain(*[__get_files(x, root) for x in path.iterdir()]))
    logger.error()
    sys.exit(1)


def get_files(root: Path) -> List[Path]:
    return __get_files(root, root)


def do_encrypt(input: Union[str, Path], output: Union[str, Path], keyfile: Union[str, Path], double_check: bool):
    logger.info('Starting to encrypt...')
    logger.debug(f'input        = "{input}"')
    logger.debug(f'output       = "{output}"')
    logger.debug(f'keyfile      = "{keyfile}"')
    logger.debug(f'double_check = "{double_check}"')
    input_path = Path(input)
    if not input_path.exists():
        logger.error('Input does not exist, exiting...')
        sys.exit(1)
    output_path = Path(output)
    if output_path.is_file():
        logger.error('Output folder is a file, exiting...')
        sys.exit(1)
    if not output_path.exists():
        output_path.mkdir()
    if input_path.is_file():
        root = input_path.parent
        files = [input_path.relative_to(root)]
        input_path = root
    else:
        files = get_files(input_path)
    logger.debug('Trying to encrypt the following files:')
    logger.debug(files)
    keys = load_keys(keyfile)
    total = len(files)
    logger.info(f'Encrypting {total} file(s)...')
    for i, file in enumerate(files):
        output_file = output_path / get_encrypted_name(file.name)
        if not output_file.parent.exists():
            output_file.parent.mkdir()
        content = read_content(input_path / file)
        encrypted_content = encrypt(content, file.name, keys)[1]
        output_file = output_path / get_encrypted_name(file.name)
        write_content(output_file, encrypted_content)
        if double_check:
            encrypted_content = read_content(output_file)
            if content != decrypt(encrypted_content, output_file.name, keys)[1]:
                logger.error(f'Double-check for "{file.name}" was unsuccessful...')
                sys.exit(1)
            else:
                logger.info(f'"{file.name}" is double-checked...')
        logger.info(f'Encrypted {100 * (i + 1) / total :.2f}% [{total-i-1}/{total} left]...')
        logger.debug(f'File {file.name} has been encrypted, {total-i-1} out of {total} left...')

def do_encrypt_wrapper(args):
    do_encrypt(
        input=args.input,
        output=args.output,
        keyfile=args.keyfile,
        double_check=args.double_check)

def do_decrypt(input: Union[str, Path], output: Union[str, Path], keyfile: Union[str, Path]):
    logger.info('Starting to decrypt...')
    logger.debug(f'input        = "{input}"')
    logger.debug(f'output       = "{output}"')
    logger.debug(f'keyfile      = "{keyfile}"')
    input_path = Path(input)
    if not input_path.exists():
        logger.error(f'Input does not exist, exiting...')
        sys.exit(1)
    output_path = Path(output)
    if output_path.is_file():
        logger.error('Output folder is a file, exiting...')
        sys.exit(1)
    if not output_path.exists():
        output_path.mkdir()
    if input_path.is_file():
        root = input_path.parent
        files = [input_path.relative_to(root)]
        input_path = root
    else:
        files = get_files(input_path)
    logger.debug('Trying to decrypt the following files:')
    logger.debug(files)
    keys = load_keys(keyfile)
    total = len(files)
    logger.info(f'Decrypting {total} file(s)...')
    for i, file in enumerate(files):
        output_file = output_path / get_decrypted_name(file.name)
        if not output_file.parent.exists():
            output_file.parent.mkdir()
        content = read_content(input_path / file)
        content = decrypt(content, file.name, keys)[1]
        write_content(output_file, content)
        logger.info(f'Decrypted {100 * (i+1) / total :.2f}% [{total-i-1}/{total} left]...\r')
        logger.debug(f'File {file.name} has been decrypted, {total-i-1} out of {total} left...')


def do_decrypt_wrapper(args):
    do_decrypt(
        input=args.input,
        output=args.output,
        keyfile=args.keyfile)


def do_check(unencrypted: Union[str, Path], encrypted: Union[str, Path], keyfile: Union[str, Path]):
    logger.info('Starting to check...')
    logger.debug(f'unencrypted    = "{unencrypted}"')
    logger.debug(f'encrypted      = "{encrypted}"')
    logger.debug(f'keyfile              = "{keyfile}"')
    unencrypted_path = Path(unencrypted)
    if not unencrypted_path.exists():
        logger.error(f'Unencrypted input folder/file does not exist, exiting...')
        sys.exit(1)
    encrypted_path = Path(encrypted)
    if not encrypted_path.exists():
        logger.error(f'Encrypted input folder/file does not exist, exiting...')
        sys.exit(1)
    keys = load_keys(keyfile)
    if unencrypted_path.is_file():
        if not encrypted_path.is_file():
            logger.error('Encrypted input is a folder, while unencrypted input is a file, exiting...')
            sys.exit(1)
        root = unencrypted_path.parent
        unencrypted_files = [unencrypted_path.relative_to(root)]
        unencrypted_path = root
        root = encrypted_path.parent
        encrypted_files = [encrypted_path.relative_to(root)]
        encrypted_path = root
    else:
        if not encrypted_path.is_dir():
            logger.error('Encrypted input is a file, while unencrypted input is a folder, exiting...')
            sys.exit(1)
        unencrypted_files = get_files(unencrypted_path)
        encrypted_files = get_files(encrypted_path)
    logger.debug('Unencrypted files:')
    logger.debug(unencrypted_files)
    logger.debug('Encrypted files:')
    logger.debug(encrypted_files)
    for file in unencrypted_files:
        encrypted_file = file.parent / get_encrypted_name(file.name)
        if encrypted_file not in encrypted_files:
            logger.error(f'There is a file that exists in unencrypted files, but encrypted version is missing: {file}')
            sys.exit(1)
    for file in encrypted_files:
        unencrypted_file = file.parent / get_decrypted_name(file.name)
        if unencrypted_file not in unencrypted_files:
            logger.error(f'There is a file that exists in encrypted files, but unencrypted version is missing: {file}')
            sys.exit(1)
    total = len(unencrypted_files)
    logger.info(f'Checking {total} file(s)...')
    for i, file in enumerate(unencrypted_files):
        unencrypted_file = unencrypted_path / file
        encrypted_file = encrypted_path / file.parent / get_encrypted_name(file.name)
        content_unencrypted = read_content(unencrypted_file)
        content_encrypted = read_content(encrypted_file)
        content_decrypted = decrypt(content_encrypted, encrypted_file.name, keys)[1]
        if content_unencrypted != content_decrypted:
            logger.error(f'Unencrypted content is different from encrypted: {file}')
        logger.info(f'Checked {100 * (i+1) / total :.2f}% [{total-i-1}/{total} left]...\r')
        logger.debug(f'File {file.name} has been checked, {total-i-1} out of {total} left...')


def do_check_wrapper(args):
    do_check(
        unencrypted=args.unencrypted,
        encrypted=args.encrypted,
        keyfile=args.keyfile)


def do_test(args):
    i = 0
    while Path(f'./test_{i}').exists():
        i += 1
    folder = Path(f'./test_{i}')
    logger.info('Starting to test...')
    logger.debug(f'keep = "{args.keep}"')
    logger.debug(f'double_check = "{args.double_check}"')
    logger.info(f'Path for testing is {folder}')
    folder.mkdir()
    (folder / 'unencrypted').mkdir()
    (folder / 'keys').mkdir()
    x = [v / 100.0 for v in range(1000)]
    plt.plot(x, [sin(v) for v in x])
    plt.savefig(folder / 'unencrypted' / 'sin.png')
    plt.close()
    with open(folder / 'unencrypted' / 'text.txt', 'w') as f:
        f.write('''
            Lorem ipsum dolor sit amet,
            consectetur adipiscing elit,
            sed do eiusmod tempor incididunt
            ut labore et dolore magna aliqua.
            ''')
    gold_image = read_content(folder / 'unencrypted' / 'sin.png')
    gold_text = read_content(folder / 'unencrypted' / 'text.txt')
    (folder / 'temp').mkdir()
    (folder / 'encrypted_folder').mkdir()
    # Test 1
    keys = [('3DES', 'some_enc_key{filename}'),
            ('AES256', 'prefix{filename}suffix'),
            ('CAMELLIA256', 'some_key'),
            ('TWOFISH', '???{filename}!!!'),
            ('BLOWFISH', '{filename}')]
    with open(folder / 'keys' / '1.key', 'w') as f:
        f.write(json.dumps(keys))
    do_encrypt(
        input=folder / 'unencrypted',
        output=folder / 'encrypted_folder',
        keyfile=folder / 'keys' / '1.key',
        double_check=args.double_check)
    do_check(
        unencrypted=folder / 'unencrypted',
        encrypted=folder / 'encrypted_folder',
        keyfile=folder / 'keys' / '1.key')
    do_decrypt(
        input=folder / 'encrypted_folder',
        output=folder / 'decrypted_folder',
        keyfile=folder / 'keys' / '1.key')
    if gold_text != read_content(folder / 'decrypted_folder' / 'text.txt'):
        logger.error(f'There is a problem of encrypting the folder: text...')
        if not args.keep: shutil.rmtree(folder)
        sys.exit(1)
    if gold_image != read_content(folder / 'decrypted_folder' / 'sin.png'):
        logger.error(f'There is a problem of encrypting the folder: image...')
        if not args.keep: shutil.rmtree(folder)
        sys.exit(1)
    # Test 2
    keys = [('AES256', 'prefix{filename}suffix')]
    with open(folder / 'keys' / '2.key', 'w') as f:
        f.write(json.dumps(keys))
    keys = [('TWOFISH', '???{filename}!!!'),
             ('AES256', 'prefix{filename}suffix')]
    with open(folder / 'keys' / '3.key', 'w') as f:
        f.write(json.dumps(keys))
    do_encrypt(folder / 'unencrypted' / 'text.txt',       folder / 'encrypted_files',
        folder / 'keys' / '2.key', args.double_check)
    do_check(folder / 'unencrypted' / 'text.txt',       folder / 'encrypted_files' / 'text.txt.scp',
        folder / 'keys' / '2.key')
    do_decrypt(folder / 'encrypted_files' / 'text.txt.scp', folder / 'decrypted_files',
        folder / 'keys' / '2.key')
    do_encrypt(folder / 'unencrypted' / 'sin.png',        folder / 'encrypted_files',
        folder / 'keys' / '3.key', args.double_check)
    do_check(folder / 'unencrypted' / 'sin.png',       folder / 'encrypted_files' / 'sin.png.scp',
        folder / 'keys' / '3.key')
    do_decrypt(folder / 'encrypted_files' / 'sin.png.scp',  folder / 'decrypted_files',
        folder / 'keys' / '3.key')
    if gold_text != read_content(folder / 'decrypted_files' / 'text.txt'):
        logger.error(f'There is a problem of encrypting the file: text...')
        if not args.keep: shutil.rmtree(folder)
        sys.exit(1)
    if gold_image != read_content(folder / 'decrypted_files' / 'sin.png'):
        logger.error(f'There is a problem of encrypting the file: image...')
        if not args.keep: shutil.rmtree(folder)
        sys.exit(1)
    if not args.keep: shutil.rmtree(folder)
    logger.info('All the tests are successfully passed.')


if __name__ == '__main__':
    FORMAT = '[{filename}:{lineno} - {funcName}(): {levelname}] {message}'
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true',
                            help='enable verbose debug output')
    parser.add_argument('-p', '--print_arguments', action='store_true',
                            help='print argument and exit the script')
    subparsers = parser.add_subparsers(dest='command', description='command to perform')
    subparsers.required = True

    parser_encrypt = subparsers.add_parser('encrypt', help='encrypt file or folder')
    parser_encrypt.add_argument('input', type=str,
                            help='input folder or file to encrypt')
    parser_encrypt.add_argument('output', type=str,
                            help='output folder to place the encrypted files')
    parser_encrypt.add_argument('keyfile', type=str,
                            help='path to the key file\nshould contain something like that:\n' +
                           '[("aes256", "some_enc_key"), ("blowfish", "another_key_{filename}")]')
    parser_encrypt.add_argument('-dc', '--double_check', action='store_true',
                            help='double-check the encryption')
    parser_encrypt.set_defaults(func=do_encrypt_wrapper)

    parser_decrypt = subparsers.add_parser('decrypt', help='decrypt file or folder')
    parser_decrypt.add_argument('input', type=str,
                            help='input folder or file to decrypt')
    parser_decrypt.add_argument('output', type=str,
                            help='output folder to place the decrypted files')
    parser_decrypt.add_argument('keyfile', type=str,
                            help='path to the key file\nshould contain something like that:\n' +
                           '[("aes256", "some_enc_key"), ("blowfish", "another_key_{filename}")]')
    parser_decrypt.set_defaults(func=do_decrypt_wrapper)

    parser_test = subparsers.add_parser('test', help='test this script')
    parser_test.add_argument('-k', '--keep', action='store_true',
                            help='keep the test folder and files afterwards')
    parser_test.add_argument('-dc', '--double_check', action='store_true',
                            help='double-check the encryption')
    parser_test.set_defaults(func=do_test)

    parser_check = subparsers.add_parser('check', help='check the encryption')
    parser_check.add_argument('unencrypted', type=str,
                            help='unencrypted folder or file')
    parser_check.add_argument('encrypted', type=str,
                            help='encrypted folder or file')
    parser_check.add_argument('keyfile', type=str,
                            help='path to the key file\nshould contain something like that:\n' +
                           '[("aes256", "some_enc_key"), ("blowfish", "another_key_{filename}")]')
    parser_check.set_defaults(func=do_check_wrapper)
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format=FORMAT, style='{')
    if args.print_arguments:
        logger.info('The arguments are:')
        logger.info(args)
        sys.exit(0)
    logging.debug(args)
    args.func(args)
