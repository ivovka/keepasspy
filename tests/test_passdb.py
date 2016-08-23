import unittest
import os
import codecs
from keepasspy import consts
from keepasspy.passdb import PassDB
from keepasspy.credentials import PassDBCredentials

class TestConsts(unittest.TestCase):
    def test_cypher(self):
        self.assertEqual(
            consts.Cypher.aes.value,
            codecs.decode(b'31c1f2e6bf714350be5805216afc5aff','hex'))
        self.assertEqual(
            consts.Cypher.twofish.value,
            codecs.decode(b'ad68f29f576f4bb9a36ad47af965346c', 'hex'))

    def test_compression_algo(self):
        self.assertEqual(consts.CompressionAlgo.none.value,0)
        self.assertEqual(consts.CompressionAlgo.gzip.value,1)

    def test_crs_algo(self):
        self.assertEqual(consts.CrsAlgo.null.value,0)
        self.assertEqual(consts.CrsAlgo.arc_four_variant.value,1)
        self.assertEqual(consts.CrsAlgo.salsa20.value,2)

class TestCredentials(unittest.TestCase):
    def setUp(self):
        self.pass_cred = PassDBCredentials(password = '123456')

    def test_password(self):
        self.assertEqual(codecs.encode(self.pass_cred.hash,'hex'),b'ff7f73b854845fc02aa13b777ac090fb1d9ebfe16c8950c7d26499371dd0b479')

    def test_xml_keyfile(self):
        abs_xml_keyfile = os.path.abspath('tests/sample2_keyfile.key')
        xml_keyfile_cred = PassDBCredentials(keyfile = abs_xml_keyfile)
        print(codecs.encode(xml_keyfile_cred.hash,'hex'))
        self.assertNotEqual(xml_keyfile_cred.hash, None)

    def test_empty_credentials(self):
        test_cred = PassDBCredentials(something='wrong')
        self.assertEqual(test_cred.hash, None)

    def test_keyfile_notfound(self):
        with self.assertRaises(FileNotFoundError):
            keyfile_cred = PassDBCredentials(keyfile='asdfs.sss')

    def test_plain_keyfile(self):
        abs_keyfile = os.path.abspath('tests/sample3_keyfile.exe')
        cred = PassDBCredentials(keyfile = abs_keyfile)
        self.assertNotEqual(cred.hash, None)

class TestPassDB(unittest.TestCase):
#    def test_passdb(self):
#        absfile1 = os.path.abspath('tests/sample1.kdbx')
#        with self.assertRaises(ValueError):
#            pass_db = PassDB(open(absfile1,'rb'), password='w31Ca*tR2JMI5D')

    def test_passdb_ok(self):
        absfile1 = os.path.abspath('tests/sample1.kdbx')
        pass_db = PassDB(open(absfile1,'rb'), password='asdf')
        self.assertEqual(1,1)
