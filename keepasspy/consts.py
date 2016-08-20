import codecs
from enum import Enum

class Cypher(Enum):
    aes = codecs.decode(b'31c1f2e6bf714350be5805216afc5aff', 'hex')
    twofish = codecs.decode(b'ad68f29f576f4bb9a36ad47af965346c', 'hex')

class CompressionAlgo(Enum):
    none = 0
    gzip = 1

class CrsAlgo(Enum):
    null = 0
    arc_four_variant = 1
    salsa20 = 2

