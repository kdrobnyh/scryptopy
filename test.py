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
                [{'algorithm': 'AES256', 'passphrase_template': 'prefix{salt0}suffix', 'num_salts': 5}],
                [{'algorithm': 'AES256', 'passphrase_template': 'prefix{salt1}suffix', 'num_salts': 5}],
                [{'algorithm': 'AES256', 'passphrase_template': 'prefix{salt3}suffix', 'num_salts': 5}]
            ],
            'data_key_index': 0,
            'filename_key_index': 1,
            'dirname_key_index': 2
        }
        self.__test_file('lorem.txt', write_lorem_ipsum, keys)

    def test_csv_spam(self):
        keys = {
            'keys': [
                [
                    {'algorithm': 'TWOFISH', 'passphrase_template': '???{salt1}{salt3}!!!', 'num_salts': 5},
                    {'algorithm': 'AES256', 'passphrase_template': 'prefix{salt4}suffix', 'num_salts': 5}
                ],
                [{'algorithm': 'AES256', 'passphrase_template': 'prefixsuffix', 'num_salts': 5}],
                [{'algorithm': 'AES256', 'passphrase_template': 'prefix{salt3}suffix', 'num_salts': 5}]
            ],
            'data_key_index': 0,
            'filename_key_index': 2,
            'dirname_key_index': 1
        }
        self.__test_file('spam.csv', write_csv_spam, keys)

    def test_csv_dict(self):
        keys = {
            'keys': [
                [{'algorithm': 'AES256', 'passphrase_template': '{salt4}', 'num_salts': 5}],
                [
                    {'algorithm': 'TWOFISH', 'passphrase_template': '{salt0}{salt3}', 'num_salts': 4},
                    {'algorithm': 'AES256', 'passphrase_template': 'prefixsuffix', 'num_salts': 0}
                ],
                [{'algorithm': 'AES256', 'passphrase_template': 'prefix{salt3}suffix', 'num_salts': 5}]
            ],
            'data_key_index': 1,
            'filename_key_index': 0,
            'dirname_key_index': 1
        }
        self.__test_file('dict.csv', write_csv_dict, keys)


class DirectoryEncDecCheckTestCase(unittest.TestCase):

    def __test_directory(self, dname, encrypted_dirnames):
        unencrypted_path = self.temp_dir_path / 'unencrypted' / dname
        encrypted_path = self.temp_dir_path / 'encrypted' / dname
        decrypted_path = self.temp_dir_path / 'decrypted' / dname
        keys_path = self.temp_dir_path / 'keys' / dname
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

    def __generate_keys(self):
        return {
            'keys': [
                [
                    {'algorithm': '3DES', 'passphrase_template': 'some{salt0}_e{salt4}{salt1}nc_{salt2}key{salt3}', 'num_salts': 5},
                    {'algorithm': 'AES256', 'passphrase_template': 'prefix{salt0}suffix', 'num_salts': 1},
                    {'algorithm': 'CAMELLIA256', 'passphrase_template': 'some_key', 'num_salts': 0},
                    {'algorithm': 'TWOFISH', 'passphrase_template': '???{salt1}!!!', 'num_salts': 2},
                    {'algorithm': 'BLOWFISH', 'passphrase_template': '{salt0}', 'num_salts': 1}
                ]
            ],
            'data_key_index': 0,
            'filename_key_index': 0,
            'dirname_key_index': 0
        }

    def __test_subfolders(self, dname, encrypted_dirnames):
        unencrypted_path = self.temp_dir_path / 'unencrypted' / dname
        unencrypted_path.mkdir()
        (unencrypted_path / 'texts').mkdir()
        write_lorem_ipsum(unencrypted_path / 'texts' / 'lorem.txt')
        (unencrypted_path / 'CSVs').mkdir()
        write_csv_spam(unencrypted_path / 'CSVs' / 'spam.csv')
        write_csv_dict(unencrypted_path / 'CSVs' / 'dict.csv')
        keys_path = self.temp_dir_path / 'keys' / dname
        with open(keys_path, 'w') as f:
            f.write(json.dumps(self.__generate_keys()))
        self.__test_directory(dname, encrypted_dirnames)
        shutil.rmtree(unencrypted_path)

    def __test_subfolders_partial(self, dname, encrypted_dirnames):
        unencrypted_path = self.temp_dir_path / 'unencrypted' / dname
        encrypted_path = self.temp_dir_path / 'encrypted' / dname
        decrypted_path = self.temp_dir_path / 'decrypted' / dname
        unencrypted_path.mkdir()
        write_lorem_ipsum(unencrypted_path / 'lorem1.txt')
        write_lorem_ipsum(unencrypted_path / 'lorem3.txt')
        (unencrypted_path / 'texts').mkdir()
        write_lorem_ipsum(unencrypted_path / 'texts' / 'lorem1.txt')
        write_lorem_ipsum(unencrypted_path / 'texts' / 'lorem3.txt')
        (unencrypted_path / 'CSVs').mkdir()
        (unencrypted_path / 'CSVs' / '1').mkdir()
        write_csv_spam(unencrypted_path / 'CSVs' / '1' / 'spam.csv')
        write_csv_dict(unencrypted_path / 'CSVs' / '1' /'dict.csv')
        (unencrypted_path / 'CSVs' / '3').mkdir()
        write_csv_spam(unencrypted_path / 'CSVs' / '3' /'spam.csv')
        write_csv_dict(unencrypted_path / 'CSVs' / '3' /'dict.csv')
        keys_path = self.temp_dir_path / 'keys' / dname
        with open(keys_path, 'w') as f:
            f.write(json.dumps(self.__generate_keys()))
        scryptopy.encrypt(
            input=unencrypted_path,
            output=encrypted_path,
            keyfile=keys_path,
            double_check=True,
            sync=True,
            encrypted_dirnames=encrypted_dirnames,
            confirm=False)
        scryptopy.decrypt(
            input=encrypted_path,
            output=decrypted_path,
            keyfile=keys_path,
            sync=True,
            encrypted_dirnames=encrypted_dirnames,
            confirm=False)
        write_lorem_ipsum(unencrypted_path / 'lorem2.txt')
        write_lorem_ipsum(unencrypted_path / 'texts' / 'lorem2.txt')
        (unencrypted_path / 'CSVs' / '2').mkdir()
        write_csv_spam(unencrypted_path / 'CSVs' / '2' /'spam.csv')
        write_csv_dict(unencrypted_path / 'CSVs' / '2' /'dict.csv')
        (unencrypted_path / 'lorem3.txt').unlink()
        (unencrypted_path / 'texts' / 'lorem3.txt').unlink()
        shutil.rmtree(unencrypted_path / 'CSVs' / '3')
        self.__test_directory(dname, encrypted_dirnames)
        shutil.rmtree(unencrypted_path)


    def test_subfolders_full_encrypted_dirnames(self):
        self.__test_subfolders('full_encrypted_dirnames', encrypted_dirnames=True)


    def test_subfolders_full_not_encrypted_dirnames(self):
        self.__test_subfolders('full_not_encrypted_dirnames', encrypted_dirnames=False)

    def test_subfolders_partial_encrypted_dirnames(self):
        self.__test_subfolders_partial('partial_encrypted_dirnames', encrypted_dirnames=True)

    def test_subfolders_partial_not_encrypted_dirnames(self):
        self.__test_subfolders_partial('partial_not_encrypted_dirnames', encrypted_dirnames=False)


if __name__ == '__main__':
    unittest.main()
