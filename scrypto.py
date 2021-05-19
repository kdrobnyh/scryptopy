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


from typing import List, Tuple, Union, Dict
import os
import sys
import json
import argparse
import itertools
import logging
import random
import secrets
import gnupg
from pathlib import Path
from matplotlib import pyplot as plt
from math import sin, cos
import shutil
import base64
import jsonschema
import click


gpg = gnupg.GPG()
logger = logging.getLogger(__file__)
gnupg_logger = logging.getLogger('gnupg')
gnupg_logger.setLevel(logging.CRITICAL)
findfont_logger = logging.getLogger('matplotlib.font_manager')
findfont_logger.setLevel(logging.CRITICAL)


prefix = b'SCryptoPy'
salt_len_min = 10
salt_len_max = 30

keyJsonSchema = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "alg": {"type": "string"},
            "pass": {"type": "string"},
            "salts": {"type": "number"},
        },
    }
}


def read_content(file: Path) -> bytes:
    with open(file, 'rb') as f:
        return f.read()


def write_content(file: Path, content: bytes):
    with open(file, 'wb') as f:
        f.write(content)


def get_encrypted_name(file: Path) -> Path:
    return file.parent / (file.name + '.scp')


def get_decrypted_name(file: Path) -> Path:
    return file.parent / file.name[:file.name.rfind('.')]


def load_keys(keyfile: Union[str, Path]):
    keyfile_path = Path(keyfile)
    if not keyfile_path.exists():
        logger.error(f'Key file does not exist, exiting...')
        sys.exit(1)
    with open(keyfile_path) as json_file:
        try:
            keys_loaded = json.load(json_file)
            jsonschema.validate(instance=keys_loaded, schema=keyJsonSchema)
            return keys_loaded
        except Exception as e:
            logger.error('An error occurred while loading the keys...')
            print(e)
            sys.exit(1)


def generate_salt() -> str:
    length = random.randrange(salt_len_min, salt_len_max)
    return secrets.token_urlsafe(length)[:length]


def encrypt(data: bytes, keys: List[Dict]) -> bytes:
    for i, key in enumerate(keys):
        alg = key['alg']
        nsalts = key['salts']
        if (nsalts > 255):
            logger.error(f'Number of salts should be less than 256, but it\'s {nsalts} (stage {i}/{len(keys)})...')
            sys.exit(1)
        salts = {f'salt{x}': generate_salt() for x in range(nsalts)}
        passphrase = key['pass'].format(**salts)
        if passphrase.find('{') != -1:
            logger.error(f'Passphrase = "{passphrase}"')
            logger.error('Passphrase should not contain "\{" characters, exiting...')
            sys.exit(1)
        temp = gpg.encrypt(data,
            None,
            passphrase=passphrase,
            armor=False,
            symmetric=alg)
        data = prefix
        for j in range(nsalts):
            data += salts[f'salt{j}'].encode('utf8') + b'\0'
        if not temp.ok:
            logger.error(f'Cannot encrypt input file with "{alg}": "{temp.status}" (stage {i}/{len(keys)})...')
            sys.exit(1)
        data += temp.data
    return data


def decrypt(data: bytes, keys: List[Dict]) -> bytes:
    for i, key in enumerate(keys[::-1]):
        alg = key['alg']
        if not data.startswith(prefix):
            logger.error(f'Cannot decrypt the data: wrong file content (stage {i}/{len(keys)})...')
            sys.exit(1)
        data = data[len(prefix):]
        salts = {}
        for j in range(key['salts']):
            pos = data.find(b'\0', salt_len_min, salt_len_max)
            if pos == -1:
                logger.error(f'Cannot decrypt the data: cannot find the salt (stage {i}/{len(keys)})...')
                sys.exit(1)
            salts[f'salt{j}'] = data[:pos].decode('utf8')
            data = data[pos+1:]
        passphrase = key['pass'].format(**salts)
        temp = gpg.decrypt(data, passphrase=passphrase)
        if not temp.ok:
            logger.error(f'Cannot decrypt input file with "{alg}": "{temp.status}" (stage {i}/{len(keys)})...')
            sys.exit(1)
        data = temp.data
    return data


def __get_files(path: Path, root: Path) -> List[Path]:
    if path.is_file():
        return [path.relative_to(root)]
    if path.is_dir():
        return list(itertools.chain(*[__get_files(x, root) for x in path.iterdir()]))
    logger.error()
    sys.exit(1)


def get_files(root: Path) -> List[Path]:
    return __get_files(root, root)


def do_encrypt(input: Union[str, Path], output: Union[str, Path],
    keyfile: Union[str, Path], double_check: bool,
    skip_existing: bool, confirm: bool = True):
    if confirm:
        if not click.confirm('Ready to proceed?', default=True):
            logger.info('That\'s all right. Bye!')
            sys.exit(0)
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
    output_path.mkdir(exist_ok=True)
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
        output_file = output_path / get_encrypted_name(file)
        output_file.parent.mkdir(exist_ok=True, parents=True)
        if skip_existing and output_file.exists():
            logger.info(f'Skipped {100 * (i+1) / total :.2f}% [{total-i-1}/{total} left]...\r')
            logger.debug(f'File {file.name} has been skipped, {total-i-1} out of {total} left...')
            continue
        content = read_content(input_path / file)
        encrypted_content = encrypt(content, keys)
        output_file = output_path / get_encrypted_name(file)
        write_content(output_file, encrypted_content)
        if double_check:
            encrypted_content = read_content(output_file)
            if content != decrypt(encrypted_content, keys):
                logger.error(f'Double-check for "{file.name}" was unsuccessful...')
                sys.exit(1)
            else:
                logger.info(f'"{file.name}" is double-checked...')
        logger.info(f'Encrypted {100 * (i + 1) / total :.2f}% [{total-i-1}/{total} left]...')
        logger.debug(f'File {file.name} has been encrypted, {total-i-1} out of {total} left...')
    logger.info('All done!')


def do_encrypt_wrapper(args):
    do_encrypt(
        input=args.input,
        output=args.output,
        keyfile=args.keyfile,
        double_check=args.double_check,
        skip_existing=args.skip_existing)


def do_decrypt(input: Union[str, Path], output: Union[str, Path],
    keyfile: Union[str, Path], skip_existing: bool,
    confirm: bool = True):
    if confirm:
        if not click.confirm('Ready to proceed?', default=True):
            logger.info('That\'s all right. Bye!')
            sys.exit(0)
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
    output_path.mkdir(exist_ok=True)
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
        output_file = output_path / get_decrypted_name(file)
        output_file.parent.mkdir(exist_ok=True, parents=True)
        if skip_existing and output_file.exists():
            logger.info(f'Skipped {100 * (i+1) / total :.2f}% [{total-i-1}/{total} left]...\r')
            logger.debug(f'File {file.name} has been skipped, {total-i-1} out of {total} left...')
            continue
        content = read_content(input_path / file)
        content = decrypt(content, keys)
        write_content(output_file, content)
        logger.info(f'Decrypted {100 * (i+1) / total :.2f}% [{total-i-1}/{total} left]...\r')
        logger.debug(f'File {file.name} has been decrypted, {total-i-1} out of {total} left...')


def do_decrypt_wrapper(args):
    do_decrypt(
        input=args.input,
        output=args.output,
        keyfile=args.keyfile,
        skip_existing=args.skip_existing)


def do_check(unencrypted: Union[str, Path], encrypted: Union[str, Path],
    keyfile: Union[str, Path], confirm: bool = True):
    if confirm:
        if not click.confirm('Ready to proceed?', default=True):
            logger.info('That\'s all right. Bye!')
            sys.exit(0)
    logger.info('Starting to check...')
    logger.debug(f'unencrypted    = "{unencrypted}"')
    logger.debug(f'encrypted      = "{encrypted}"')
    logger.debug(f'keyfile        = "{keyfile}"')
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
        encrypted_file = get_encrypted_name(file)
        if encrypted_file not in encrypted_files:
            logger.error(f'There is a file that exists in unencrypted files, but encrypted version is missing: {file}')
            sys.exit(1)
    for file in encrypted_files:
        unencrypted_file = get_decrypted_name(file)
        if unencrypted_file not in unencrypted_files:
            logger.error(f'There is a file that exists in encrypted files, but unencrypted version is missing: {file}')
            sys.exit(1)
    total = len(unencrypted_files)
    logger.info(f'Checking {total} file(s)...')
    for i, file in enumerate(unencrypted_files):
        unencrypted_file = unencrypted_path / file
        encrypted_file = encrypted_path / get_encrypted_name(file)
        content_unencrypted = read_content(unencrypted_file)
        content_encrypted = read_content(encrypted_file)
        content_decrypted = decrypt(content_encrypted, keys)
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

    logger.info(f'Path for testing is {folder}')

    if not click.confirm('Ready to proceed?', default=True):
        logger.info('That\'s all right. Bye!')
        sys.exit(0)

    logger.info('Starting to test...')
    logger.debug(f'keep = "{args.keep}"')
    logger.debug(f'double_check = "{args.double_check}"')
    (folder / 'unencrypted' / 'plots').mkdir(parents=True)
    (folder / 'unencrypted' / 'texts').mkdir(parents=True)
    (folder / 'keys').mkdir(parents=True)
    x = [v / 100.0 for v in range(1000)]
    plt.plot(x, [sin(v) for v in x])
    plt.savefig(folder / 'unencrypted' / 'plots' / 'sin.png')
    plt.close()
    plt.plot(x, [cos(v) for v in x])
    plt.savefig(folder / 'unencrypted' / 'plots' / 'cos.png')
    plt.close()
    with open(folder / 'unencrypted' / 'texts' / 'text.txt', 'w') as f:
        f.write('''
            Lorem ipsum dolor sit amet,
            consectetur adipiscing elit,
            sed do eiusmod tempor incididunt
            ut labore et dolore magna aliqua.
            ''')
    gold_plot_sin = read_content(folder / 'unencrypted' / 'plots' / 'sin.png')
    gold_plot_cos = read_content(folder / 'unencrypted' / 'plots' / 'cos.png')
    gold_text = read_content(folder / 'unencrypted' / 'texts' / 'text.txt')
    # Test 1
    keys = [{'alg': '3DES', 'pass': 'some{salt0}_e{salt4}{salt1}nc_{salt2}key{salt3}', 'salts': 5},
            {'alg': 'AES256', 'pass': 'prefix{salt0}suffix', 'salts': 1},
            {'alg': 'CAMELLIA256', 'pass': 'some_key', 'salts': 0},
            {'alg': 'TWOFISH', 'pass': '???{salt1}!!!', 'salts': 2},
            {'alg': 'BLOWFISH', 'pass': '{salt0}', 'salts': 1}]
    with open(folder / 'keys' / '1.key', 'w') as f:
        f.write(json.dumps(keys))
    do_encrypt(
        input=folder / 'unencrypted',
        output=folder / 'encrypted_folder',
        keyfile=folder / 'keys' / '1.key',
        double_check=args.double_check,
        skip_existing=False,
        confirm=False)
    do_check(
        unencrypted=folder / 'unencrypted',
        encrypted=folder / 'encrypted_folder',
        keyfile=folder / 'keys' / '1.key',
        confirm=False)
    do_decrypt(
        input=folder / 'encrypted_folder',
        output=folder / 'decrypted_folder',
        keyfile=folder / 'keys' / '1.key',
        skip_existing=False,
        confirm=False)
    if gold_text != read_content(folder / 'decrypted_folder' / 'texts' / 'text.txt'):
        logger.error(f'There is a problem of encrypting the folder: text...')
        if not args.keep: shutil.rmtree(folder)
        sys.exit(1)
    if gold_plot_sin != read_content(folder / 'decrypted_folder' / 'plots' / 'sin.png'):
        logger.error(f'There is a problem of encrypting the folder: sin plot...')
        if not args.keep: shutil.rmtree(folder)
        sys.exit(1)
    if gold_plot_cos != read_content(folder / 'decrypted_folder' / 'plots' / 'cos.png'):
        logger.error(f'There is a problem of encrypting the folder: cos plot...')
        if not args.keep: shutil.rmtree(folder)
        sys.exit(1)
    # Test 2
    keys = [{'alg': 'AES256', 'pass': 'prefix{salt0}suffix', 'salts': 5}]
    with open(folder / 'keys' / '2.key', 'w') as f:
        f.write(json.dumps(keys))
    keys = [{'alg': 'TWOFISH', 'pass': '???{salt1}{salt3}!!!', 'salts': 5},
            {'alg': 'AES256', 'pass': 'prefix{salt4}suffix', 'salts': 5}]
    with open(folder / 'keys' / '3.key', 'w') as f:
        f.write(json.dumps(keys))
    keys = [{'alg': 'TWOFISH', 'pass': '{salt0}{salt3}', 'salts': 4},
            {'alg': 'AES256', 'pass': 'prefixsuffix', 'salts': 0}]
    with open(folder / 'keys' / '4.key', 'w') as f:
        f.write(json.dumps(keys))
    do_encrypt(
        input=folder / 'unencrypted' / 'texts' / 'text.txt',
        output=folder / 'encrypted_files',
        keyfile=folder / 'keys' / '2.key',
        double_check=args.double_check,
        skip_existing=False,
        confirm=False)
    do_check(
        unencrypted=folder / 'unencrypted' / 'texts' / 'text.txt',
        encrypted=folder / 'encrypted_files' / 'text.txt.scp',
        keyfile=folder / 'keys' / '2.key',
        confirm=False)
    do_decrypt(
        input=folder / 'encrypted_files' / 'text.txt.scp',
        output=folder / 'decrypted_files',
        keyfile=folder / 'keys' / '2.key',
        skip_existing=False,
        confirm=False)
    do_encrypt(
        input=folder / 'unencrypted' / 'plots' / 'sin.png',
        output=folder / 'encrypted_files',
        keyfile=folder / 'keys' / '3.key',
        double_check=args.double_check,
        skip_existing=False,
        confirm=False)
    do_check(
        unencrypted=folder / 'unencrypted' / 'plots' / 'sin.png',
        encrypted=folder / 'encrypted_files' / 'sin.png.scp',
        keyfile=folder / 'keys' / '3.key',
        confirm=False)
    do_decrypt(
        input=folder / 'encrypted_files' / 'sin.png.scp',
        output=folder / 'decrypted_files',
        keyfile=folder / 'keys' / '3.key',
        skip_existing=False,
        confirm=False)
    do_encrypt(
        input=folder / 'unencrypted' / 'plots' / 'cos.png',
        output=folder / 'encrypted_files',
        keyfile=folder / 'keys' / '4.key',
        double_check=args.double_check,
        skip_existing=False,
        confirm=False)
    do_check(
        unencrypted=folder / 'unencrypted' / 'plots' / 'cos.png',
        encrypted=folder / 'encrypted_files' / 'cos.png.scp',
        keyfile=folder / 'keys' / '4.key',
        confirm=False)
    do_decrypt(
        input=folder / 'encrypted_files' / 'cos.png.scp',
        output=folder / 'decrypted_files',
        keyfile=folder / 'keys' / '4.key',
        skip_existing=False,
        confirm=False)
    if gold_text != read_content(folder / 'decrypted_files' / 'text.txt'):
        logger.error(f'There is a problem of encrypting the file: text...')
        if not args.keep: shutil.rmtree(folder)
        sys.exit(1)
    if gold_plot_sin != read_content(folder / 'decrypted_files' / 'sin.png'):
        logger.error(f'There is a problem of encrypting the file: sin plot...')
        if not args.keep: shutil.rmtree(folder)
        sys.exit(1)
    if gold_plot_cos != read_content(folder / 'decrypted_files' / 'cos.png'):
        logger.error(f'There is a problem of encrypting the file: cos plot...')
        if not args.keep: shutil.rmtree(folder)
        sys.exit(1)
    if not args.keep: shutil.rmtree(folder)
    logger.info('All the tests have successfully passed.')


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
                            help='path to the key file. Example of key file content: ' +
                           '[{"alg": "aes256", "pass": "some{salt0}_enc{salt3}_key", "salts": 5}, ' +
                           '{"alg": "blowfish", "pass": "prefix{salt0}suffix", "salts": 1}]')
    parser_encrypt.add_argument('-dc', '--double_check', action='store_true',
                            help='double-check the encryption')
    parser_encrypt.add_argument('-s', '--skip_existing', action='store_true',
                            help='skip files if their encrypted version already exist')
    parser_encrypt.set_defaults(func=do_encrypt_wrapper)

    parser_decrypt = subparsers.add_parser('decrypt', help='decrypt file or folder')
    parser_decrypt.add_argument('input', type=str,
                            help='input folder or file to decrypt')
    parser_decrypt.add_argument('output', type=str,
                            help='output folder to place the decrypted files')
    parser_decrypt.add_argument('keyfile', type=str,
                            help='path to the key file. Example of key file content: ' +
                           '[{"alg": "aes256", "pass": "some{salt0}_enc{salt3}_key", "salts": 5}, ' +
                           '{"alg": "blowfish", "pass": "prefix{salt0}suffix", "salts": 1}]')
    parser_decrypt.add_argument('-s', '--skip_existing', action='store_true',
                            help='skip files if their decrypted version already exist')
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
                            help='path to the key file. Example of key file content: ' +
                           '[{"alg": "aes256", "pass": "some{salt0}_enc{salt3}_key", "salts": 5}, ' +
                           '{"alg": "blowfish", "pass": "prefix{salt0}suffix", "salts": 1}]')
    parser_check.set_defaults(func=do_check_wrapper)
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format=FORMAT, style='{')
    if args.print_arguments:
        logger.info('The arguments are:')
        logger.info(args)
        sys.exit(0)
    logging.debug(args)
    args.func(args)
