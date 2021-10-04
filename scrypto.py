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
fname_len = 32
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

content_types = {'MD5': 0,
                 'fname': 1,
                 'dirname': 2,
                 'data': 255 }

content_types_back = {v: k for k, v in content_types.items()}
length_base = 128


def read_bytes(file: Path) -> bytes:
    if not file.exists():
        logger.error(f'File {file} does not exist, exiting...')
        sys.exit(1)
    with open(file, 'rb') as f:
        return f.read()


def write_bytes(fname: Path, data: bytes):
    if fname.exists():
        logger.error(f'File {fname} already exists, exiting...')
        sys.exit(1)
    with open(fname, 'wb') as f:
        f.write(data)


def load_keys(keyfile: Union[str, Path]) -> List[Dict]:
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
            sys.exit(1)


def generate_fname() -> str:
    return secrets.token_urlsafe(fname_len)[:fname_len]


def generate_salt() -> str:
    length = random.randrange(salt_len_min, salt_len_max)
    return secrets.token_urlsafe(length)[:length]


def calc_md5sum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def encrypt_bytes(data: bytes, keys: List[Dict]) -> bytes:
    for key in keys:
        alg = key['alg']
        nsalts = key['salts']
        if (nsalts > 255):
            logger.error(f'Number of salts should be less than 256, but it\'s {nsalts} (stage {i}/{len(keys)})...')
            sys.exit(1)
        salts = {f'salt{j}': generate_salt() for j in range(nsalts)}
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
    return data


def encrypt_content(content: Dict[str, bytes], keys: List[Dict]) -> bytes:
    if 'data' in content:
        content['MD5'] = calc_md5sum(content['data'])
    data = prefix
    wrong_types = [t for t in content.keys() if t not in content_types.keys()]
    for t in wrong_types:
        logger.error(f'Content type {t} is not recognized, should be one of these:')
        logger.error(f'\t"{content_types.keys()}", exiting...')
        sys.exit(1)

    for t in content_types.keys():
        if t not in content.keys():
            continue
        data += bytes((content_types[t],))
        data_temp = b''
        if t == 'MD5':
            data_temp = content[t].encode('utf-8')
        elif t == 'fname':
            data_temp = encrypt_bytes(content[t].encode('utf-8'), keys)
        elif t == 'dirname':
            data_temp = encrypt_bytes(content[t].encode('utf-8'), keys)
        elif t == 'data':
            data_temp = encrypt_bytes(content[t], keys)
        else:
            logger.error(f'Content type {t} is not recognized, should be one of these:')
            logger.error(f'\t"{content_types.keys()}", exiting...')
            sys.exit(1)
        length = len(data_temp)
        length_bytes = bytes((length % length_base, ))
        while length >= length_base:
            length = length // length_base
            length_bytes += bytes((length_base + length % length_base, ))
        data += length_bytes[::-1]
        data += data_temp
    return data


def decrypt_bytes(data: bytes, keys: List[Dict]) -> bytes:
    for key in keys[::-1]:
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
    return data


def decrypt_file(fname: Path, keys: List[Dict],
                 needed_content_types: List[str] = content_types.keys()) -> Dict[str, bytes]:
    data = read_bytes(fname)
    if not data.startswith(prefix):
        logger.error(f'Cannot decrypt "{file}": wrong file content...')
        sys.exit(1)
    data = data[len(prefix):]
    content = {}
    while len(data) > 0:
        t = data[0]
        data = data[1:]
        if t not in content_types_back.keys():
            logger.error(f'Content type {t} is not recognized, should be one of these:')
            logger.error(f'\t"{content_types_back.keys()}", exiting...')
            sys.exit(1)
        t = content_types_back[t]
        length_total = 0
        length_current = 128
        while length_current >= 128:
            if len(data) == 0:
                logger.error(f'Not enough data to decrypt, exiting...')
                sys.exit(1)
            length_total = length_total * 128 + (length_current - 128)
            length_current = data[0]
            data = data[1:]
        length_total = length_total * 128 + length_current
        if len(data) < length_total:
            logger.error(f'Not enough data to decrypt, exiting...')
            sys.exit(1)
        data_temp = data[:length_total]
        data = data[length_total:]
        if t not in needed_content_types:
            continue
        if t == 'MD5':
            content[t] = data_temp.decode('utf-8')
        elif t == 'fname':
            content[t] = decrypt_bytes(data_temp, keys).decode('utf-8')
        elif t == 'dirname':
            content[t] = decrypt_bytes(data_temp, keys).decode('utf-8')
        elif t == 'data':
            content[t] = decrypt_bytes(data_temp, keys)
        else:
            logger.error(f'Content type {t} is not recognized, should be one of these:')
            logger.error(f'\t"{content_types.keys()}", exiting...')
            sys.exit(1)
    return content


def get_unencrypted_relative_to(path: Path, root: Path) -> List[Path]:
    full_path = root / path
    if full_path.is_file():
        return [path]
    if full_path.is_dir():
        subpaths = list(itertools.chain(*[get_unencrypted_relative_to(x.relative_to(root), root) for x in sorted(full_path.iterdir())]))
        return ([path] if path != Path('.') else []) + subpaths
    logger.error(f'Path "{full_path}" is not file or directory, exiting...')
    sys.exit(1)


EncryptedFname = collections.namedtuple('EncryptedFname',
    ['unenc_path', 'enc_path'])


def get_encrypted_relative_to(enc_path: Path, unenc_path: Path,
                              root: Path, keys: List[Dict],
                              encrypted_dirnames: bool) -> Tuple[List[Tuple[Path, Path]], Dict[Path, Path]]:
    full_enc_path = root / enc_path
    if full_enc_path.is_file():
        if encrypted_dirnames and full_enc_path.name == '__index__':
            return ([], {})
        unenc_fname = decrypt_file(fname=full_enc_path,
                             keys=keys, needed_content_types=['fname'])['fname']
        unenc_path = unenc_path.parent / unenc_fname
        return ([EncryptedFname(enc_path=enc_path, unenc_path=unenc_path)],
                {unenc_path: enc_path})
    if full_enc_path.is_dir():
        if encrypted_dirnames and enc_path != Path('.'):
            fname = decrypt_file(fname=full_enc_path/'__index__',
                                 keys=keys, needed_content_types=['dirname'])['dirname']
            unenc_path = unenc_path.parent / fname
        result = [get_encrypted_relative_to(
                        enc_path=x.relative_to(root),
                        unenc_path=unenc_path/x.name,
                        root=root,
                        keys=keys,
                        encrypted_dirnames=encrypted_dirnames)
                     for x in sorted(full_enc_path.iterdir())]
        enc_map = {unenc_path: enc_path}
        files = []
        if enc_path != Path('.'):
            files = [EncryptedFname(enc_path=enc_path, unenc_path=unenc_path)]
        for x in result:
            enc_map.update(x[1])
            files.extend(x[0])
        return (files, enc_map)
    logger.error(f'Path "{enc_path}" is not file or directory, exiting...')
    sys.exit(1)


# Redo
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


AnalyzedFiles = collections.namedtuple('AnalyzedFiles',
    ['unencrypted_only', 'both', 'encrypted_only'])


def collect_files(enc_root: Path, unenc_root: Path, keys: List[Dict], encrypted_dirnames):
    encrypted_dirnames=True
    if enc_root.is_file():
        logger.error(f'"{enc_root}" should be a directory, not file, exiting...')
        sys.exit(1)
    if unenc_root.is_file():
        logger.error(f'"{unenc_root}" should be a directory, not file, exiting...')
        sys.exit(1)
    files_unencrypted = get_unencrypted_relative_to(path=Path('.'), root=unenc_root)
    files_encrypted, enc_map = get_encrypted_relative_to(enc_path=Path('.'),
                                                         unenc_path=Path('.'),
                                                         root=enc_root,
                                                         keys=keys,
                                                         encrypted_dirnames=encrypted_dirnames)
    files_encrypted_unenc_paths = [file.unenc_path for file in files_encrypted]
    files_unencrypted_only = []
    for file in (file for file in files_unencrypted if file not in files_encrypted_unenc_paths):
        enc_path = enc_map[file.parent] / generate_fname()
        if (unenc_root / file).is_dir():
            if not encrypted_dirnames:
                enc_path = file
            enc_map[file] = enc_path
        files_unencrypted_only.append(EncryptedFname(enc_path=enc_path, unenc_path=file))
    files_both = [enc_file for enc_file in files_encrypted
                  if enc_file.unenc_path in files_unencrypted]
    files_encrypted_only = [enc_file for enc_file in files_encrypted if enc_file.unenc_path not in files_unencrypted]
    return AnalyzedFiles(
        unencrypted_only=files_unencrypted_only,
        both=files_both,
        encrypted_only=files_encrypted_only)


def do_encrypt(input: Union[str, Path], output: Union[str, Path],
               keyfile: Union[str, Path], double_check: bool, sync: bool,
               encrypted_dirnames: bool, confirm: bool = True):
    logger.info('Starting to encrypt...')
    logger.debug(f'input            = "{input}"')
    logger.debug(f'output           = "{output}"')
    logger.debug(f'keyfile          = "{keyfile}"')
    logger.debug(f'double_check     = "{double_check}"')
    logger.debug(f'encrypt_dirnames = "{encrypted_dirnames}"')
    logger.debug(f'sync             = "{sync}"')

    input_path = Path(input)
    if not input_path.exists():
        logger.error('Input does not exist, exiting...')
        sys.exit(1)

    output_path = Path(output)
    keys = load_keys(keyfile)

    if input_path.is_file():
        files_new = []
        files_check = []
        files_remove = []
        file = EncryptedFname(unenc_path=input_path.name, enc_path=output_path.name)
        if output_path.exists():
            if not output_path.is_file():
                logger.error('Output is not a regular file, but is expected to be, exiting...')
                sys.exit(1)
            files_check.append(file)
        else:
            files_new.append(file)
        input_path = input_path.parent
        output_path = output_path.parent
        output_path.mkdir(exist_ok=True)
    else:
        if output_path.exists and output_path.is_file():
            logger.error('Output is a regular file, but is not expected to be, exiting...')
            sys.exit(1)
        output_path.mkdir(exist_ok=True)
        files = collect_files(unenc_root=input_path, enc_root=output_path,
                              keys=keys, encrypted_dirnames=encrypted_dirnames)
        files_new = files.unencrypted_only
        files_check = [file for file in files.both if (input_path/file.unenc_path).is_file()]
        files_remove = files.encrypted_only
        if not sync: files_remove = []

    if confirm:
        confirm_action(action_name='encrypt',
            files_new=files_new,
            files_check=files_check,
            files_remove=files_remove)

    total = len(files_new) + len(files_check) + len(files_remove)
    logger.info(f'Processing {total} file(s)...')

    with click.progressbar(
        length=total,
        label='Encrypting',
        item_show_func=lambda x: x) as bar:
        for file in files_check:
            input_file = input_path / file.unencrypted
            output_file = output_path / file.encrypted
            output_md5sum = decrypt_file(fname=output_file,
                                         keys=keys, needed_content_types=['MD5'])['MD5']
            input_md5sum = calc_md5sum(read_bytes(input_file))
            if input_md5sum == output_md5sum:
                bar.update(1, f'{input_file.name} skipped')
            else:
                if sync:
                    output_file.unlink()
                    bar.update(0, f'{output_file.name} removed')
                    files_new.append(EncryptedFname(unenc_path=file.unencrypted,
                                                    enc_path=None))
                else:
                    logger.error(f'{file.unencrypted} is different from {file.encrypted}, exiting...')
                    sys.exit(1)
        for file in files_new:
            input_file = input_path / file.unenc_path
            output_file = output_path / file.enc_path
            if input_file.is_file():
                # output_file.parent.mkdir(exist_ok=True, parents=True)
                data = read_bytes(input_file)
                encrypted_content = encrypt_content(
                    {'fname': input_file.name,
                     'data': data}, keys)
                write_bytes(fname=output_file,
                            data=encrypted_content)
                if double_check:
                    content = read_bytes(input_file)
                    encrypted_content = decrypt_file(output_file, keys)
                    if content != encrypted_content['data']:
                        logger.error(f'Double-check for "{file.name}" was unsuccessful...')
                        sys.exit(1)
                    bar.update(1, f'{input_file.name} encrypted & checked')
                else:
                    bar.update(1, f'{input_file.name} encrypted')
            else:
                output_file.mkdir()
                encrypted_content = encrypt_content({'dirname': input_file.name}, keys=keys)
                write_bytes(fname=output_file/'__index__',
                            data=encrypted_content)
                bar.update(1, f'{input_file.name} encrypted')
        for file in files_remove[::-1]:
            output_file = output_path / file.enc_path
            output_file.unlink()
            bar.update(1, f'{output_file.name} removed')
    logger.info('Encryption completed!')


def do_encrypt_wrapper(args):
    do_encrypt(
        input=args.input,
        output=args.output,
        keyfile=args.keyfile,
        double_check=args.double_check,
        encrypted_dirnames=~args.no_encrypt_dirnames,
        sync=args.sync)


def do_decrypt(input: Union[str, Path], output: Union[str, Path],
        keyfile: Union[str, Path], sync: bool,
        encrypted_dirnames: bool, confirm: bool = True):
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
    keys = load_keys(keyfile)

    if input_path.is_file():
        files_new = []
        files_check = []
        files_remove = []
        file = EncryptedFname(enc_path=input_path.name, unenc_path=output_path.name)
        if output_path.exists():
            if not output_path.is_file():
                logger.error('Output is a file, but expected to be a directory, exiting...')
                sys.exit(1)
            files_check.append(file)
        else:
            files_new.append(file)
        input_path = input_path.parent
        output_path = output_path.parent
        output_path.mkdir(exist_ok=True)
    else:
        if output_path.exists() and output_path.is_file():
            logger.error('Output is a directory, but expected to be a file, exiting...')
            sys.exit(1)
        output_path.mkdir(exist_ok=True)
        files = collect_files(enc_root=input_path, unenc_root=output_path,
                              keys=keys, encrypted_dirnames=encrypted_dirnames)
        files_remove = files.unencrypted_only
        files_check = [file for file in files.both if (input_path/file.unenc_path).is_file()]
        files_new = files.encrypted_only
        if not sync: files_remove = []

    if confirm:
        confirm_action(action_name='decrypt',
            files_new=files_new,
            files_check=files_check,
            files_remove=files_remove)

    total = len(files_new) + len(files_check) + len(files_remove)
    logger.info(f'Processing {total} file(s)...')

    with click.progressbar(
        length=total,
        label='Decrypting',
        item_show_func=lambda x: x) as bar:
        for file in files_check:
            input_file = input_path / file.enc_path
            output_file = output_path / file.unenc_path
            input_md5sum, _ = decrypt_file(fname=input_file,
                                           keys=keys,
                                           needed_content_types=['MD5'])['MD5']
            output_md5sum = calc_md5sum(read_bytes(output_file))
            if input_md5sum == output_md5sum:
                bar.update(1, f'{input_file.name} skipped')
            else:
                if sync:
                    output_file.unlink()
                    bar.update(0, f'{output_file.name} removed')
                    files_new.append(file.enc_path)
                else:
                    logger.error(f'{file.enc_path} is different from {file.unenc_path}, exiting...')
                    sys.exit(1)
        for file in files_new:
            input_file = input_path / file.enc_path
            output_file = output_path / file.unenc_path
            if input_file.is_file():
                decrypted_bytes = decrypt_file(fname=input_file,
                                               keys=keys,
                                               needed_content_types=['data'])['data']
                write_bytes(fname=output_file, data=decrypted_bytes)
                bar.update(1, f'{output_file.name} decrypted')
            else:
                output_file.mkdir()
                bar.update(1, f'{output_file.name} created')
        for file in files_remove[::-1]:
            output_file = output_path / file
            output_file.unlink()
            bar.update(1, f'{output_file.name} removed')
    logger.info('Decryption completed!')


def do_decrypt_wrapper(args):
    do_decrypt(
        input=args.input,
        output=args.output,
        keyfile=args.keyfile,
        encrypted_dirnames=~no_encrypt_dirnames,
        sync=args.sync)


def do_check(unencrypted: Union[str, Path], encrypted: Union[str, Path],
             keyfile: Union[str, Path], encrypted_dirnames: bool = True, confirm: bool = True):
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
    if not unencrypted_path.exists():
        logger.error('Unencrypted path does not exist, exiting...')
        sys.exit(1)
    if not encrypted_path.exists():
        logger.error('Encrypted path does not exist, exiting...')
        sys.exit(1)
    keys = load_keys(keyfile)

    if unencrypted_path.is_file():
        if not encrypted_path.is_file():
            logger.error('Unencrypted path leads to a regular file, while encrypted does not, exiting...')
            sys.exit(1)
        files = AnalyzedFiles(unencrypted_only=[], encrypted_only=[],
                              both=[EncryptedFname(unenc_path=unencrypted_path.name, enc_path=encrypted_path.name)])
        unencrypted_path = unencrypted_path.parent
        encrypted_path = encrypted_path.parent
    else:
        if not encrypted_path.is_dir():
            logger.error('Unencrypted path leads to a directory, while encrypted does not, exiting...')
            sys.exit(1)
        files = collect_files(unenc_root=unencrypted_path, enc_root=encrypted_path,
                              keys=keys, encrypted_dirnames=encrypted_dirnames)


    is_ok = (len(files.unencrypted_only) == 0) and (len(files.encrypted_only) == 0)

    to_log = []
    for file in files.unencrypted_only:
        to_log.append(f'Unencrypted only: {file}')

    for file in files.encrypted_only:
        to_log.append(f'Encrypted only: {file}')

    files_both = [file for file in files.both if (unencrypted_path/file.unenc_path).is_file()]

    total = len(files_both)

    logger.info(f'Processing {total} file(s)...')

    with click.progressbar(
            length=total,
            label='Checking',
            item_show_func=lambda x: x) as bar:
        for file in files_both:
            unencrypted_file = unencrypted_path / file.unenc_path
            encrypted_file = encrypted_path / file.enc_path
            content_unencrypted = read_bytes(unencrypted_file)
            content_decrypted = decrypt_file(fname=encrypted_file,
                                             keys=keys,
                                             needed_content_types=['data'])['data']
            if content_unencrypted != content_decrypted:
                to_log.append(f'Different: {file.unenc_path} and {file.enc_path}')
                is_ok = False
            bar.update(1, f'{unencrypted_file.name} checked')

    if not is_ok:
        for s in to_log:
            logger.info(s)
        logger.error('Directory content does not match, exiting...')
        sys.exit(1)
    logger.info('Checking completed!')


def do_check_wrapper(args):
    do_check(
        unencrypted=args.unencrypted,
        encrypted=args.encrypted,
        keyfile=args.keyfile,
        encrypted_dirnames=~args.no_encrypt_dirnames)


def do_test(keep: bool, double_check: bool):
    confirm = False
    i = 0
    while Path(f'./test_{i}').exists():
        i += 1
    test_path = Path(f'./test_{i}')

    logger.info(f'Path for testing is {test_path}')

    if not click.prompt('Ready to proceed?\n[Y]es [n]o',
            type=bool, default=True, show_choices=False, show_default=False):
        logger.info('That\'s all right. Bye!')
        sys.exit(0)

    logger.info('Starting to test...')
    logger.debug(f'keep         = "{keep}"')
    logger.debug(f'double_check = "{double_check}"')
    (test_path / 'unencrypted' / 'plots').mkdir(parents=True)
    (test_path / 'unencrypted' / 'texts').mkdir(parents=True)
    (test_path / 'keys').mkdir(parents=True)
    x = [v / 100.0 for v in range(1000)]
    plt.plot(x, [sin(v) for v in x])
    plt.savefig(test_path / 'unencrypted' / 'plots' / 'sin.png')
    plt.close()
    plt.plot(x, [cos(v) for v in x])
    plt.savefig(test_path / 'unencrypted' / 'plots' / 'cos.png')
    plt.close()
    with open(test_path / 'unencrypted' / 'texts' / 'text.txt', 'w') as f:
        f.write('''
            Lorem ipsum dolor sit amet,
            consectetur adipiscing elit,
            sed do eiusmod tempor incididunt
            ut labore et dolore magna aliqua.
            ''')
    gold_plot_sin = read_bytes(test_path / 'unencrypted' / 'plots' / 'sin.png')
    gold_plot_cos = read_bytes(test_path / 'unencrypted' / 'plots' / 'cos.png')
    gold_text     = read_bytes(test_path / 'unencrypted' / 'texts' / 'text.txt')
    # Test 1
    keys = [{'alg': '3DES', 'pass': 'some{salt0}_e{salt4}{salt1}nc_{salt2}key{salt3}', 'salts': 5},
            {'alg': 'AES256', 'pass': 'prefix{salt0}suffix', 'salts': 1},
            {'alg': 'CAMELLIA256', 'pass': 'some_key', 'salts': 0},
            {'alg': 'TWOFISH', 'pass': '???{salt1}!!!', 'salts': 2},
            {'alg': 'BLOWFISH', 'pass': '{salt0}', 'salts': 1}]
    with open(test_path / 'keys' / '1.key', 'w') as f:
        f.write(json.dumps(keys))
    do_encrypt(
        input=test_path / 'unencrypted',
        output=test_path / 'encrypted_dir',
        keyfile=test_path / 'keys' / '1.key',
        double_check=args.double_check,
        sync=True,
        encrypted_dirnames=True,
        confirm=confirm)
    do_check(
        unencrypted=test_path / 'unencrypted',
        encrypted=test_path / 'encrypted_dir',
        keyfile=test_path / 'keys' / '1.key',
        encrypted_dirnames=True,
        confirm=confirm)
    do_decrypt(
        input=test_path / 'encrypted_dir',
        output=test_path / 'decrypted_dir',
        keyfile=test_path / 'keys' / '1.key',
        sync=True,
        encrypted_dirnames=True,
        confirm=confirm)
    if gold_text != read_bytes(test_path / 'decrypted_dir' / 'texts' / 'text.txt'):
        logger.error(f'There is a problem of encrypting the directory: text...')
        if not keep: shutil.rmtree(test_path)
        sys.exit(1)
    if gold_plot_sin != read_bytes(test_path / 'decrypted_dir' / 'plots' / 'sin.png'):
        logger.error(f'There is a problem of encrypting the directory: sin plot...')
        if not keep: shutil.rmtree(test_path)
        sys.exit(1)
    if gold_plot_cos != read_bytes(test_path / 'decrypted_dir' / 'plots' / 'cos.png'):
        logger.error(f'There is a problem of encrypting the directory: cos plot...')
        if not keep: shutil.rmtree(test_path)
        sys.exit(1)
    # Test 2
    keys = [{'alg': 'AES256', 'pass': 'prefix{salt0}suffix', 'salts': 5}]
    with open(test_path / 'keys' / '2.key', 'w') as f:
        f.write(json.dumps(keys))
    keys = [{'alg': 'TWOFISH', 'pass': '???{salt1}{salt3}!!!', 'salts': 5},
            {'alg': 'AES256', 'pass': 'prefix{salt4}suffix', 'salts': 5}]
    with open(test_path / 'keys' / '3.key', 'w') as f:
        f.write(json.dumps(keys))
    keys = [{'alg': 'TWOFISH', 'pass': '{salt0}{salt3}', 'salts': 4},
            {'alg': 'AES256', 'pass': 'prefixsuffix', 'salts': 0}]
    with open(test_path / 'keys' / '4.key', 'w') as f:
        f.write(json.dumps(keys))
    do_encrypt(
        input=test_path/'unencrypted'/'texts'/'text.txt',
        output=test_path/'encrypted_files'/'text.txt',
        keyfile=test_path/'keys'/'2.key',
        double_check=double_check,
        sync=False,
        encrypted_dirnames=True,
        confirm=confirm)
    do_check(
        unencrypted=test_path / 'unencrypted' / 'texts' / 'text.txt',
        encrypted=test_path / 'encrypted_files' / 'text.txt',
        keyfile=test_path / 'keys' / '2.key',
        confirm=confirm)
    do_decrypt(
        input=test_path / 'encrypted_files' / 'text.txt',
        output=test_path / 'decrypted_files'/'text.txt',
        keyfile=test_path / 'keys' / '2.key',
        sync=False,
        encrypted_dirnames=True,
        confirm=confirm)
    do_encrypt(
        input=test_path / 'unencrypted' / 'plots' / 'sin.png',
        output=test_path / 'encrypted_files'/'sin.png',
        keyfile=test_path / 'keys' / '3.key',
        double_check=double_check,
        sync=False,
        encrypted_dirnames=True,
        confirm=confirm)
    do_check(
        unencrypted=test_path / 'unencrypted' / 'plots' / 'sin.png',
        encrypted=test_path / 'encrypted_files' / 'sin.png',
        keyfile=test_path / 'keys' / '3.key',
        confirm=confirm)
    do_decrypt(
        input=test_path / 'encrypted_files' / 'sin.png',
        output=test_path / 'decrypted_files'/'sin.png',
        keyfile=test_path / 'keys' / '3.key',
        sync=False,
        encrypted_dirnames=True,
        confirm=confirm)
    do_encrypt(
        input=test_path / 'unencrypted' / 'plots' / 'cos.png',
        output=test_path / 'encrypted_files'/'cos.png',
        keyfile=test_path / 'keys' / '4.key',
        double_check=double_check,
        sync=False,
        encrypted_dirnames=True,
        confirm=confirm)
    do_check(
        unencrypted=test_path / 'unencrypted' / 'plots' / 'cos.png',
        encrypted=test_path / 'encrypted_files' / 'cos.png',
        keyfile=test_path / 'keys' / '4.key',
        confirm=confirm)
    do_decrypt(
        input=test_path / 'encrypted_files' / 'cos.png',
        output=test_path / 'decrypted_files' / 'cos.png',
        keyfile=test_path / 'keys' / '4.key',
        sync=False,
        encrypted_dirnames=True,
        confirm=confirm)
    if gold_text != read_bytes(test_path / 'decrypted_files' / 'text.txt'):
        logger.error(f'There is a problem of encrypting the file: text...')
        if not keep: shutil.rmtree(test_path)
        sys.exit(1)
    if gold_plot_sin != read_bytes(test_path / 'decrypted_files' / 'sin.png'):
        logger.error(f'There is a problem of encrypting the file: sin plot...')
        if not keep: shutil.rmtree(test_path)
        sys.exit(1)
    if gold_plot_cos != read_bytes(test_path / 'decrypted_files' / 'cos.png'):
        logger.error(f'There is a problem of encrypting the file: cos plot...')
        if not keep: shutil.rmtree(test_path)
        sys.exit(1)
    if not keep: shutil.rmtree(test_path)
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
    parser.add_argument('-ded', '--no_encrypt_dirnames', action='store_true',
                            help='directory names should not be encrypted')
    subparsers = parser.add_subparsers(dest='command', description='command to perform')
    subparsers.required = True

    parser_encrypt = subparsers.add_parser('encrypt', help='encrypt file or directory')
    parser_encrypt.add_argument('input', type=str,
                            help='input directory or file to encrypt')
    parser_encrypt.add_argument('output', type=str,
                            help='output directory to place the encrypted files')
    parser_encrypt.add_argument('keyfile', type=str,
                            help='path to the key file. Example of key file content: ' +
                           '[{"alg": "aes256", "pass": "some{salt0}_enc{salt3}_key", "salts": 5}, ' +
                           '{"alg": "blowfish", "pass": "prefix{salt0}suffix", "salts": 1}]')
    parser_encrypt.add_argument('-s', '--sync', action='store_true',
                            help='synchronize output to input')
    parser_encrypt.add_argument('-dc', '--double_check', action='store_true',
                            help='double-check the encryption')
    parser_encrypt.set_defaults(func=do_encrypt_wrapper)

    parser_decrypt = subparsers.add_parser('decrypt', help='decrypt file or directory')
    parser_decrypt.add_argument('input', type=str,
                            help='input directory or file to decrypt')
    parser_decrypt.add_argument('output', type=str,
                            help='output directory to place the decrypted files')
    parser_decrypt.add_argument('keyfile', type=str,
                            help='path to the key file. Example of key file content: ' +
                           '[{"alg": "aes256", "pass": "some{salt0}_enc{salt3}_key", "salts": 5}, ' +
                           '{"alg": "blowfish", "pass": "prefix{salt0}suffix", "salts": 1}]')
    parser_decrypt.add_argument('-s', '--sync', action='store_true',
                            help='synchronize output to input')
    parser_decrypt.set_defaults(func=do_decrypt_wrapper)

    parser_test = subparsers.add_parser('test', help='test this script')
    parser_test.add_argument('-k', '--keep', action='store_true',
                            help='keep the test directory and files afterwards')
    parser_test.add_argument('-dc', '--double_check', action='store_true',
                            help='double-check the encryption')
    parser_test.set_defaults(func=do_test_wrapper)

    parser_check = subparsers.add_parser('check', help='check the encryption')
    parser_check.add_argument('unencrypted', type=str,
                            help='unencrypted directory or file')
    parser_check.add_argument('encrypted', type=str,
                            help='encrypted directory or file')
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
