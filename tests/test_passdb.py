import unittest
import os
import codecs
from keepasspy import consts
from keepasspy.passdb import PassDB

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

class TestPassDB(unittest.TestCase):
    def test_passdb(self):
        absfile1 = os.path.abspath('tests/sample1.kdbx')
        with self.assertRaises(ValueError):
            pass_db = PassDB(open(absfile1,'rb'), password='w31Ca*tR2JMI5D')

