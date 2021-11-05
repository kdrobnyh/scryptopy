import unittest
import scryptopy
import tempfile
from pathlib import Path
import json
import csv
import shutil
import filecmp


def write_lorem_ipsum(fname):
    with open(fname, 'w') as file:
        file.write('''
            Lorem ipsum dolor sit amet,
            consectetur adipiscing elit,
            sed do eiusmod tempor incididunt
            ut labore et dolore magna aliqua.
            ''')


def write_csv_spam(fname):
    with open(fname, 'w', newline='') as csvfile:
        spamwriter = csv.writer(csvfile, delimiter=' ',
                                quotechar='|', quoting=csv.QUOTE_MINIMAL)
        spamwriter.writerow(['Egg', 'bacon'])
        spamwriter.writerow(['Spam'] * 5 + ['Baked Beans'])
        spamwriter.writerow(['Spam', 'Lovely Spam', 'Wonderful Spam'])


def write_csv_dict(fname):
    with open(fname, 'w', newline='') as csvfile:
        fieldnames = ['first_name', 'last_name']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({'first_name': 'Baked', 'last_name': 'Beans'})
        writer.writerow({'first_name': 'Lovely', 'last_name': 'Spam'})
        writer.writerow({'first_name': 'Wonderful', 'last_name': 'Spam'})


class FileEncDecCheckTestCase(unittest.TestCase):

    def __test_file(self, fname, create_func, keys):

        unencrypted_path = self.temp_dir_path / 'unencrypted' / fname
        encrypted_path = self.temp_dir_path / 'encrypted' / fname
        decrypted_path = self.temp_dir_path / 'decrypted' / fname
        keys_path = self.temp_dir_path / 'keys' / fname

        create_func(unencrypted_path)

        with open(keys_path, 'w') as f:
            f.write(json.dumps(keys))

        scryptopy.encrypt(
            input=unencrypted_path,
            output=encrypted_path,
            keyfile=keys_path,
            double_check=True,
            sync=True,
            encrypted_dirnames=True,
            confirm=False)

        scryptopy.check(
            unencrypted=unencrypted_path,
            encrypted=encrypted_path,
            keyfile=keys_path,
            encrypted_dirnames=True,
            confirm=False)

        scryptopy.decrypt(
            input=encrypted_path,
            output=decrypted_path,
            keyfile=keys_path,
            sync=True,
            encrypted_dirnames=True,
            confirm=False)

        self.assertTrue(filecmp.cmp(unencrypted_path, decrypted_path, shallow=False))
        unencrypted_path.unlink()
        encrypted_path.unlink()
        decrypted_path.unlink()
        keys_path.unlink()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)
        (self.temp_dir_path / 'unencrypted').mkdir()
        (self.temp_dir_path / 'encrypted').mkdir()
        (self.temp_dir_path / 'decrypted').mkdir()
        (self.temp_dir_path / 'keys').mkdir()
        print(self.temp_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_lorem_ipsum(self):
        keys = {
            'keys': [
                [{'alg': 'AES256', 'pass': 'prefix{salt0}suffix', 'salts': 5}],
                [{'alg': 'AES256', 'pass': 'prefix{salt1}suffix', 'salts': 5}],
                [{'alg': 'AES256', 'pass': 'prefix{salt3}suffix', 'salts': 5}]
            ],
            'data': 0,
            'fname': 1,
            'dirname': 2
        }
        self.__test_file('lorem.txt', write_lorem_ipsum, keys)

    def test_csv_spam(self):
        keys = {
            'keys': [
                [
                    {'alg': 'TWOFISH', 'pass': '???{salt1}{salt3}!!!', 'salts': 5},
                    {'alg': 'AES256', 'pass': 'prefix{salt4}suffix', 'salts': 5}
                ],
                [{'alg': 'AES256', 'pass': 'prefixsuffix', 'salts': 5}],
                [{'alg': 'AES256', 'pass': 'prefix{salt3}suffix', 'salts': 5}]
            ],
            'data': 0,
            'fname': 2,
            'dirname': 1
        }
        self.__test_file('spam.csv', write_csv_spam, keys)

    def test_csv_dict(self):
        keys = {
            'keys': [
                [{'alg': 'AES256', 'pass': '{salt4}', 'salts': 5}],
                [
                    {'alg': 'TWOFISH', 'pass': '{salt0}{salt3}', 'salts': 4},
                    {'alg': 'AES256', 'pass': 'prefixsuffix', 'salts': 0}
                ],
                [{'alg': 'AES256', 'pass': 'prefix{salt3}suffix', 'salts': 5}]
            ],
            'data': 1,
            'fname': 0,
            'dirname': 1
        }
        self.__test_file('dict.csv', write_csv_dict, keys)


class DirectoryEncDecCheckTestCase(unittest.TestCase):

    def __test_directory(self, dname, keys, encrypted_dirnames):
        unencrypted_path = self.temp_dir_path / 'unencrypted' / dname
        encrypted_path = self.temp_dir_path / 'encrypted' / dname
        decrypted_path = self.temp_dir_path / 'decrypted' / dname
        keys_path = self.temp_dir_path / 'keys' / dname

        with open(keys_path, 'w') as f:
            f.write(json.dumps(keys))

        scryptopy.encrypt(
            input=unencrypted_path,
            output=encrypted_path,
            keyfile=keys_path,
            double_check=True,
            sync=True,
            encrypted_dirnames=encrypted_dirnames,
            confirm=False)

        scryptopy.check(
            unencrypted=unencrypted_path,
            encrypted=encrypted_path,
            keyfile=keys_path,
            encrypted_dirnames=encrypted_dirnames,
            confirm=False)

        scryptopy.decrypt(
            input=encrypted_path,
            output=decrypted_path,
            keyfile=keys_path,
            sync=True,
            encrypted_dirnames=encrypted_dirnames,
            confirm=False)

        dircmp = filecmp.dircmp(unencrypted_path, decrypted_path, ignore=None, hide=None)
        self.assertEqual(dircmp.right_only, [])
        self.assertEqual(dircmp.left_only, [])
        self.assertEqual(dircmp.diff_files, [])
        self.assertEqual(dircmp.funny_files, [])
        shutil.rmtree(encrypted_path)
        shutil.rmtree(decrypted_path)
        keys_path.unlink()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)
        (self.temp_dir_path / 'unencrypted').mkdir()
        (self.temp_dir_path / 'encrypted').mkdir()
        (self.temp_dir_path / 'decrypted').mkdir()
        (self.temp_dir_path / 'keys').mkdir()
        print(self.temp_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def __test_subfolders(self, dname, encrypted_dirnames):
        unencrypted_path = self.temp_dir_path / 'unencrypted' / dname
        unencrypted_path.mkdir()
        (unencrypted_path / 'texts').mkdir()
        write_lorem_ipsum(unencrypted_path / 'texts' / 'lorem.txt')
        (unencrypted_path / 'CSVs').mkdir()
        write_csv_spam(unencrypted_path / 'CSVs' / 'spam.csv')
        write_csv_dict(unencrypted_path / 'CSVs' / 'dict.csv')
        keys = {
            'keys': [
                [
                    {'alg': '3DES', 'pass': 'some{salt0}_e{salt4}{salt1}nc_{salt2}key{salt3}', 'salts': 5},
                    {'alg': 'AES256', 'pass': 'prefix{salt0}suffix', 'salts': 1},
                    {'alg': 'CAMELLIA256', 'pass': 'some_key', 'salts': 0},
                    {'alg': 'TWOFISH', 'pass': '???{salt1}!!!', 'salts': 2},
                    {'alg': 'BLOWFISH', 'pass': '{salt0}', 'salts': 1}
                ]
            ],
            'data': 0,
            'fname': 0,
            'dirname': 0
        }
        self.__test_directory(dname, keys, encrypted_dirnames)
        shutil.rmtree(unencrypted_path)


    def test_subfolders_encrypted_dirnames(self):
        self.__test_subfolders('encrypted_dirnames', encrypted_dirnames=True)


    def test_subfolders_not_encrypted_dirnames(self):
        self.__test_subfolders('not_encrypted_dirnames', encrypted_dirnames=False)


if __name__ == '__main__':
    unittest.main()
