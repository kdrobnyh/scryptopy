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
import sys
import hashlib
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
import tempfile
import subprocess
import collections


gpg = gnupg.GPG()
logger = logging.getLogger(__file__)
gnupg_logger = logging.getLogger('gnupg')
gnupg_logger.setLevel(logging.CRITICAL)
findfont_logger = logging.getLogger('matplotlib.font_manager')
findfont_logger.setLevel(logging.CRITICAL)


prefix = b'SCryptoPy'
salt_len_min = 10
salt_len_max = 30
md5sum_length = 32
key_json_schema = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "alg": {"type": "string"},
            "pass": {"type": "string"},
            "salts": {"type": "number"},
        }
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
    if not file.name.endswith('.scp'):
        logger.error(f'Filename of encrypted file "{file}" should have extension ".scp"...')
        sys.exit(1)
    return file.parent / file.name[:file.name.rfind('.')]


def load_keys(keyfile: Union[str, Path]):
    keyfile_path = Path(keyfile)
    if not keyfile_path.exists():
        logger.error(f'Key file "{keyfile_path}" does not exist, exiting...')
        sys.exit(1)
    with open(keyfile_path) as json_file:
        try:
            keys_loaded = json.load(json_file)
            jsonschema.validate(instance=keys_loaded, schema=key_json_schema)
            return keys_loaded
        except Exception as e:
            logger.error(f'An error occurred while loading the keys from "{keyfile_path}"...')
            print(e)
            sys.exit(1)


def generate_salt() -> str:
    length = random.randrange(salt_len_min, salt_len_max)
    return secrets.token_urlsafe(length)[:length]


def calc_md5sum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def encrypt_file(file: Path, keys: List[Dict]) -> bytes:
    data = read_content(file)
    md5sum = calc_md5sum(data)
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
        data = b''
        for j in range(nsalts):
            data += salts[f'salt{j}'].encode('utf8') + b'\0'
        if not temp.ok:
            logger.error(f'Cannot encrypt "{file}" with "{alg}": "{temp.status}" (stage {i}/{len(keys)})...')
            sys.exit(1)
        data += temp.data
    return prefix + md5sum.encode('utf8') + b'\0' + data


def parse_encrypted_file(file: Path) -> Tuple[str, bytes]:
    data = read_content(file)
    if not data.startswith(prefix):
        logger.error(f'Cannot decrypt "{file}": wrong file content...')
        sys.exit(1)
    data = data[len(prefix):]
    if len(data) <= md5sum_length:
        logger.error(f'Cannot decrypt "{file}": wrong file content, empty...')
        sys.exit(1)
    md5sum = data[:md5sum_length].decode('utf8')
    data = data[md5sum_length+1:]
    return md5sum, data


def decrypt_file(file: Path, keys: List[Dict]) -> bytes:
    md5sum, data = parse_encrypted_file(file)
    for i, key in enumerate(keys[::-1]):
        alg = key['alg']
        salts = {}
        for j in range(key['salts']):
            pos = data.find(b'\0', salt_len_min, salt_len_max)
            if pos == -1:
                logger.error(f'Cannot decrypt "{file}": cannot find the salt (stage {i}/{len(keys)})...')
                sys.exit(1)
            salts[f'salt{j}'] = data[:pos].decode('utf8')
            data = data[pos+1:]
        passphrase = key['pass'].format(**salts)
        temp = gpg.decrypt(data, passphrase=passphrase)
        if not temp.ok:
            logger.error(f'Cannot decrypt "{file}" with "{alg}": "{temp.status}" (stage {i}/{len(keys)})...')
            sys.exit(1)
        data = temp.data
    if md5sum != calc_md5sum(data):
        logger.error(f'Cannot decrypt "{file}": failed integrity check...')
        sys.exit(1)
    return data


def __get_files_relative_to(path: Path, root: Path) -> List[Path]:
    if path.is_file():
        return [path.relative_to(root)]
    if path.is_dir():
        return list(itertools.chain(*[__get_files_relative_to(x, root) for x in sorted(path.iterdir())]))
    logger.error()
    sys.exit(1)


def get_files_relative_to(root: Path) -> List[Path]:
    if root.is_file():
        return (root.parent, [root.relative_to(root.parent)])
    else:
        return (root, __get_files_relative_to(root, root))


def confirm_action(action_name, files_new, files_check, files_remove):
    action_name_capitalized = action_name.capitalize()
    res = click.prompt(f'There are {len(files_new)} files to {action_name},\n' +
            f'  {len(files_check)} files to check, and\n' +
            f'  {len(files_remove)} files to remove.\nReady to proceed?\n' +
            f'  [Y]es [n]o [r]eview',
            show_choices=False,
            show_default=False,
            default='y',
            type=click.Choice(['y', 'n', 'r'],
                case_sensitive=False))
    if res == 'r':
        f = tempfile.NamedTemporaryFile(mode='w')
        for file in files_remove:
            f.write(f'Remove: {file}\n')
        for file in files_check:
            f.write(f'Check: {file.unencrypted} vs {file.encrypted}\n')
        for file in files_new:
            f.write(f'{action_name_capitalized}: {file}\n')
        f.seek(0)
        subprocess.run(['less', f.name])
        f.close()
        res = click.prompt(f'There are {len(files_new)} files to {action_name},\n' +
                f'  {len(files_check)} files to check, and\n' +
                f'  {len(files_remove)} files to remove.\nReady to proceed?' +
                f'  [Y]es [n]o',
                show_choices=False,
                show_default=False,
                default='y',
                type=click.Choice(['y', 'n'],
                    case_sensitive=False))
    if res == 'n':
        logger.info('That\'s all right. Bye!')
        sys.exit(0)


analyze_files_result = collections.namedtuple('analyze_files_result',
    ['unencrypted_only', 'both', 'encrypted_only'])

analyze_files_both = collections.namedtuple('analyze_files_both',
    ['unencrypted', 'encrypted'])


def analyze_files(files_encrypted, files_unencrypted):
    files_encrypted_expected = [get_encrypted_name(file) for file in files_unencrypted]
    files_unencrypted_only     = [file for file, expected_output in
        zip(files_unencrypted, files_encrypted_expected) if expected_output not in files_encrypted]
    files_both     = [analyze_files_both(unencrypted=file, encrypted=expected_output)
        for file, expected_output in
        zip(files_unencrypted, files_encrypted_expected)
        if expected_output in files_encrypted]
    files_encrypted_only = [file for file in files_encrypted if file not in files_encrypted_expected]
    return analyze_files_result(
        unencrypted_only=files_unencrypted_only,
        both=files_both,
        encrypted_only=files_encrypted_only)


def do_encrypt(input: Union[str, Path], output: Union[str, Path],
        keyfile: Union[str, Path], double_check: bool, sync: bool,
        confirm: bool = True):
    logger.info('Starting to encrypt...')
    logger.debug(f'input        = "{input}"')
    logger.debug(f'output       = "{output}"')
    logger.debug(f'keyfile      = "{keyfile}"')
    logger.debug(f'double_check = "{double_check}"')
    logger.debug(f'sync         = "{sync}"')

    input_path = Path(input)
    if not input_path.exists():
        logger.error('Input does not exist, exiting...')
        sys.exit(1)

    output_path = Path(output)
    if output_path.is_file():
        logger.error('Output folder is a file, exiting...')
        sys.exit(1)
    output_path.mkdir(exist_ok=True)

    input_path, input_files = get_files_relative_to(input_path)
    output_path, output_files = get_files_relative_to(output_path)

    analyzed_files = analyze_files(
        files_unencrypted=input_files,
        files_encrypted=output_files)

    files_new = analyzed_files.unencrypted_only
    files_check = analyzed_files.both
    files_remove = analyzed_files.encrypted_only

    if not sync: files_remove = []

    if confirm:
        confirm_action(action_name='encrypt',
            files_new=files_new,
            files_check=files_check,
            files_remove=files_remove)

    keys = load_keys(keyfile)
    total = len(files_new) + len(files_check) + len(files_remove)
    logger.info(f'Processing {total} file(s)...')

    with click.progressbar(
        length=total,
        label='Encrypting',
        item_show_func=lambda x: x) as bar:
        for file in files_check:
            input_file = input_path / file.unencrypted
            output_file = output_path / file.encrypted
            output_md5sum, _ = parse_encrypted_file(output_file)
            input_md5sum = calc_md5sum(read_content(input_file))
            if input_md5sum == output_md5sum:
                bar.update(1, f'{input_file.name} skipped')
            else:
                if sync:
                    output_file.unlink()
                    bar.update(0, f'{output_file.name} removed')
                    files_new.append(file.unencrypted)
                else:
                    logger.error(f'{file.unencrypted} is different from {file.encrypted}, exiting...')
                    sys.exit(1)
        for file in files_new:
            input_file = input_path / file
            output_file = output_path / get_encrypted_name(file)
            output_file.parent.mkdir(exist_ok=True, parents=True)
            encrypted_content = encrypt_file(input_file, keys)
            write_content(output_file, encrypted_content)
            if double_check:
                content = read_content(input_file)
                if content != decrypt_file(output_file, keys):
                    logger.error(f'Double-check for "{file.name}" was unsuccessful...')
                    sys.exit(1)
                bar.update(1, f'{input_file.name} encrypted & checked')
            else:
                bar.update(1, f'{input_file.name} encrypted')
        for file in files_remove:
            output_file = output_path / file
            output_file.unlink()
            bar.update(1, f'{output_file.name} removed')
    logger.info('Encryption completed!')


def do_encrypt_wrapper(args):
    do_encrypt(
        input=args.input,
        output=args.output,
        keyfile=args.keyfile,
        double_check=args.double_check,
        sync=args.sync)


def do_decrypt(input: Union[str, Path], output: Union[str, Path],
        keyfile: Union[str, Path], sync: bool, confirm: bool = True):
    logger.info('Starting to decrypt...')
    logger.debug(f'input        = "{input}"')
    logger.debug(f'output       = "{output}"')
    logger.debug(f'keyfile      = "{keyfile}"')
    logger.debug(f'sync         = "{sync}"')

    input_path = Path(input)
    if not input_path.exists():
        logger.error(f'Input does not exist, exiting...')
        sys.exit(1)

    output_path = Path(output)
    if output_path.is_file():
        logger.error('Output folder is a file, exiting...')
        sys.exit(1)
    output_path.mkdir(exist_ok=True)

    input_path, input_files = get_files_relative_to(input_path)
    output_path, output_files = get_files_relative_to(output_path)

    analyzed_files = analyze_files(
        files_unencrypted=output_files,
        files_encrypted=input_files)

    files_remove = analyzed_files.unencrypted_only
    files_check = analyzed_files.both
    files_new = analyzed_files.encrypted_only

    if not sync: files_remove = []

    if confirm:
        confirm_action(action_name='decrypt',
            files_new=files_new,
            files_check=files_check,
            files_remove=files_remove)

    keys = load_keys(keyfile)
    total = len(files_new) + len(files_check) + len(files_remove)
    logger.info(f'Processing {total} file(s)...')

    with click.progressbar(
        length=total,
        label='Decrypting',
        item_show_func=lambda x: x) as bar:
        for file in files_check:
            input_file = input_path / file.encrypted
            output_file = output_path / file.unencrypted
            input_md5sum, _ = parse_encrypted_file(input_file)
            output_md5sum = calc_md5sum(read_content(output_file))
            if input_md5sum == output_md5sum:
                bar.update(1, f'{input_file.name} skipped')
            else:
                if sync:
                    output_file.unlink()
                    bar.update(0, f'{output_file.name} removed')
                    files_new.append(file.encrypted)
                else:
                    logger.error(f'{file.encrypted} is different from {file.unencrypted}, exiting...')
                    sys.exit(1)
        for file in files_new:
            input_file = input_path / file
            output_file = output_path / get_decrypted_name(file)
            output_file.parent.mkdir(exist_ok=True, parents=True)
            content = decrypt_file(input_file, keys)
            write_content(output_file, content)
            bar.update(1, f'{input_file.name} decrypted')
        for file in files_remove:
            output_file = output_path / file
            output_file.unlink()
            bar.update(1, f'{output_file.name} removed')
    logger.info('Decryption completed!')


def do_decrypt_wrapper(args):
    do_decrypt(
        input=args.input,
        output=args.output,
        keyfile=args.keyfile,
        sync=args.sync)


def do_check(unencrypted: Union[str, Path], encrypted: Union[str, Path],
        keyfile: Union[str, Path], confirm: bool = True):
    if confirm:
        if not click.prompt('Ready to proceed?\n[Y]es [n]o',
                type=bool, default=True, show_choices=False,
                show_default=False):
            logger.info('That\'s all right. Bye!')
            sys.exit(0)
    logger.info('Starting to check...')
    logger.debug(f'unencrypted    = "{unencrypted}"')
    logger.debug(f'encrypted      = "{encrypted}"')
    logger.debug(f'keyfile        = "{keyfile}"')

    unencrypted_path = Path(unencrypted)
    encrypted_path = Path(encrypted)

    if unencrypted_path.is_file():
        if not encrypted_path.is_file():
            logger.error('Encrypted input is a folder, while unencrypted input is a file, exiting...')
            sys.exit(1)
    else:
        if not encrypted_path.is_dir():
            logger.error('Encrypted input is a file, while unencrypted input is a folder, exiting...')
            sys.exit(1)

    unencrypted_path, unencrypted_files = get_files_relative_to(unencrypted_path)
    encrypted_path, encrypted_files     = get_files_relative_to(encrypted_path)

    analyzed_files = analyze_files(
        files_unencrypted=unencrypted_files,
        files_encrypted=encrypted_files)

    files_unencrypted_only = analyzed_files.unencrypted_only
    files_both = analyzed_files.both
    files_encrypted_only = analyzed_files.encrypted_only

    is_ok = (len(files_unencrypted_only) == 0) and (len(files_encrypted_only) == 0)

    logger.debug('Unencrypted files:')
    logger.debug(unencrypted_files)
    logger.debug('Encrypted files:')
    logger.debug(encrypted_files)

    to_log = []
    for file in files_unencrypted_only:
        to_log.append(f'Unencrypted only: {file}')

    for file in files_encrypted_only:
        to_log.append(f'Encrypted only: {file}')

    keys = load_keys(keyfile)
    total = len(files_both)

    logger.info(f'Processing {total} file(s)...')

    with click.progressbar(
            length=total,
            label='Checking',
            item_show_func=lambda x: x) as bar:
        for file in files_both:
            unencrypted_file = unencrypted_path / file.unencrypted
            encrypted_file = encrypted_path / file.encrypted
            content_unencrypted = read_content(unencrypted_file)
            content_decrypted = decrypt_file(encrypted_file, keys)
            if content_unencrypted != content_decrypted:
                to_log.append(f'Different: {file.unencrypted} and {file.encrypted}')
                is_ok = False
            bar.update(1, f'{unencrypted_file.name} checked')

    if not is_ok:
        for s in to_log:
            logger.info(s)
        sys.exit(1)
    logger.info('Checking completed!')


def do_check_wrapper(args):
    do_check(
        unencrypted=args.unencrypted,
        encrypted=args.encrypted,
        keyfile=args.keyfile)


def do_test(keep: bool, double_check: bool):
    i = 0
    while Path(f'./test_{i}').exists():
        i += 1
    folder = Path(f'./test_{i}')

    logger.info(f'Path for testing is {folder}')

    if not click.prompt('Ready to proceed?\n[Y]es [n]o',
            type=bool, default=True, show_choices=False, show_default=False):
        logger.info('That\'s all right. Bye!')
        sys.exit(0)

    logger.info('Starting to test...')
    logger.debug(f'keep         = "{keep}"')
    logger.debug(f'double_check = "{double_check}"')
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
    gold_text     = read_content(folder / 'unencrypted' / 'texts' / 'text.txt')
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
        sync=True,
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
        sync=True,
        confirm=False)
    if gold_text != read_content(folder / 'decrypted_folder' / 'texts' / 'text.txt'):
        logger.error(f'There is a problem of encrypting the folder: text...')
        if not keep: shutil.rmtree(folder)
        sys.exit(1)
    if gold_plot_sin != read_content(folder / 'decrypted_folder' / 'plots' / 'sin.png'):
        logger.error(f'There is a problem of encrypting the folder: sin plot...')
        if not keep: shutil.rmtree(folder)
        sys.exit(1)
    if gold_plot_cos != read_content(folder / 'decrypted_folder' / 'plots' / 'cos.png'):
        logger.error(f'There is a problem of encrypting the folder: cos plot...')
        if not keep: shutil.rmtree(folder)
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
        double_check=double_check,
        sync=False,
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
        sync=False,
        confirm=False)
    do_encrypt(
        input=folder / 'unencrypted' / 'plots' / 'sin.png',
        output=folder / 'encrypted_files',
        keyfile=folder / 'keys' / '3.key',
        double_check=double_check,
        sync=False,
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
        sync=False,
        confirm=False)
    do_encrypt(
        input=folder / 'unencrypted' / 'plots' / 'cos.png',
        output=folder / 'encrypted_files',
        keyfile=folder / 'keys' / '4.key',
        double_check=double_check,
        sync=False,
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
        sync=False,
        confirm=False)
    if gold_text != read_content(folder / 'decrypted_files' / 'text.txt'):
        logger.error(f'There is a problem of encrypting the file: text...')
        if not keep: shutil.rmtree(folder)
        sys.exit(1)
    if gold_plot_sin != read_content(folder / 'decrypted_files' / 'sin.png'):
        logger.error(f'There is a problem of encrypting the file: sin plot...')
        if not keep: shutil.rmtree(folder)
        sys.exit(1)
    if gold_plot_cos != read_content(folder / 'decrypted_files' / 'cos.png'):
        logger.error(f'There is a problem of encrypting the file: cos plot...')
        if not keep: shutil.rmtree(folder)
        sys.exit(1)
    if not keep: shutil.rmtree(folder)
    logger.info('All the tests have successfully passed.')


def do_test_wrapper(args):
    do_test(keep=args.keep,
            double_check=args.double_check)


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
    parser_encrypt.add_argument('-s', '--sync', action='store_true',
                            help='synchronize output to input')
    parser_encrypt.add_argument('-dc', '--double_check', action='store_true',
                            help='double-check the encryption')
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
    parser_decrypt.add_argument('-s', '--sync', action='store_true',
                            help='synchronize output to input')
    parser_decrypt.set_defaults(func=do_decrypt_wrapper)

    parser_test = subparsers.add_parser('test', help='test this script')
    parser_test.add_argument('-k', '--keep', action='store_true',
                            help='keep the test folder and files afterwards')
    parser_test.add_argument('-dc', '--double_check', action='store_true',
                            help='double-check the encryption')
    parser_test.set_defaults(func=do_test_wrapper)

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
