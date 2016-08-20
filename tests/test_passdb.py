import unittest
import os
from keepasspy.passdb import PassDB

class TestPassDB(unittest.TestCase):
    def test_passdb(self):
        absfile1 = os.path.abspath('tests/sample1.kdbx')
        with self.assertRaises(ValueError):
            pass_db = PassDB(open(absfile1,'rb'), password='w31Ca*tR2JMI5D')

