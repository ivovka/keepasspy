import io
import struct
import sys
import passdb_consts

class PassDBHdrField:

    def __init__(self, raw_value=None):
        self.raw_value = raw_value

    @property
    def raw_value(self):
        return self._raw_value

    @property
    def value(self):
        return self._value

    @raw_value.setter
    def raw_value(self, raw_value):
        self._raw_value = raw_value
        self._value = self.raw_to_value()

    @value.setter
    def value(self, value):
        self._value = value
        self._raw_value = self.value_to_raw()

    """
    Функция преобразования сырых данных в значение.
    Должна переопределяться в потомках.
    По-умолчанию - значение равно сырым данным
    """
    def raw_to_value(self):
        return self._raw_value

    """
    Функция преобразования значения в сырые данные.
    Должна переопределяться в потомках
    По-умолчанию - значение копируется в сырые данные
    """
    def value_to_raw(self):
        return self._value

class VersionField(PassDBHdrField):

    LENGTH = 4

    def raw_to_value(self):
        """
        Сырые данные выглядят (побайтно): 00 01 00 03
        """
        version_content = struct.unpack('<2H',self._raw_value)
        print(version_content)
        return({'version_major': version_content[1], 'version_minor':
            version_content[0]})

    def value_to_raw(self):
        return(struct.pack('<2H', self._value['version_minor'], self._value['version_major']))

class CipherField(PassDBHdrField):
    def raw_to_value(self):
        return passdb_consts.Cypher(self._raw_value)
    def value_to_raw(self):
        return self._value.value


class CompressionField(PassDBHdrField):
    def raw_to_value(self):
        return passdb_consts.CompressionAlgo(struct.unpack('<I', self._raw_value)[0])

    def value_to_raw(self):
        return(struct.pack('<I', self._value.value))

class MasterSeedField(PassDBHdrField):
    def __init__(self, raw_value=None):
        super().__init__(raw_value)

class TransformSeedField(PassDBHdrField):
    def __init__(self, raw_value=None):
        super().__init__(raw_value)

class EncRoundsField(PassDBHdrField):
    def raw_to_value(self):
        return(struct.unpack('<Q', self._raw_value)[0])

    def value_to_raw(self):
        return(struct.pack('<Q', self._value))

class EncIVField(PassDBHdrField):
    def __init__(self, raw_value=None):
        super().__init__(raw_value)

class ProtectedStreamKeyField(PassDBHdrField):
    def __init__(self, raw_value=None):
        super().__init__(raw_value)

class StreamStartBytesField(PassDBHdrField):
    def __init__(self, raw_value=None):
        super().__init__(raw_value)

class CrsAlgoField(PassDBHdrField):
    def raw_to_value(self):
        return passdb_consts.CrsAlgo(struct.unpack('<I', self._raw_value)[0])

    def value_to_raw(self):
        return(struct.pack('<I', self._value.value))

class PassDBHeader:
    """
    Класс представляет заголовок БД
    """
    # ключ - идентификатор поля
    # значение - (наименование поля, наименование класса)
    FIELDS_DICT = {2: ('cipher','CipherField'),
            3: ('compression','CompressionField'),
            4: ('master_seed','MasterSeedField'),
            5: ('transform_seed','TransformSeedField'),
            6: ('enc_rounds','EncRoundsField'),
            7: ('enc_iv','EncIVField'),
            8: ('protected_stream_key','ProtectedStreamKeyField'),
            9: ('stream_start_bytes','StreamStartBytesField'),
            10: ('crs_algo','CrsAlgoField'),
            0: ('version','VersionField')
            }
    SUPPORTED_VERSION_MAJOR = 3

    def __init__(self):
        self.fields = {}

    def read(self, stream):
        if not isinstance(stream, io.IOBase):
            raise TypeError('The stream does not support IOBase interface')
        stream.seek(PassDBSignature.KDBX_SIGNATURE_LENGTH)
        version = VersionField(stream.read(VersionField.LENGTH))
        print(version.value)
        if not version.value['version_major'] == PassDBHeader.SUPPORTED_VERSION_MAJOR:
            raise ValueError('Database version is not supported.')
        self.fields[PassDBHeader.FIELDS_DICT[0][0]] = version
        while True:
            (field_id,field_length) = struct.unpack('<BH', stream.read(3))
            field_content = stream.read(field_length)
            # field_id = 0 маркируется конец заголовка, однако поле с
            # field_id = 0 должно быть прочитано, т.е. оно имеет длину и имеет
            # данные. Видимо, для того, чтобы задать корректное смещение.
            if field_id == 0:
                break
            field_class = getattr(sys.modules[__name__],
                PassDBHeader.FIELDS_DICT[field_id][1])
            self.fields[PassDBHeader.FIELDS_DICT[field_id][0]] = field_class(field_content)
            print(PassDBHeader.FIELDS_DICT[field_id][0])
        print('enc_rounds=', self.fields['enc_rounds'].value)
        print('compression=', self.fields['compression'].value)
        print('crs algorithm=', self.fields['crs_algo'].value)
        print('cipher=', self.fields['cipher'].value)

class PassDBSignature:
    """
    Сигнатура файла БД паролей
    """
    KDBX_SIGNATURE = (0x9AA2D903, 0xB54BFB67)
    KDBX_SIGNATURE_LENGTH = 8
    def __init__(self):
        self.signature = []
        self.valid = False

    def read(self, stream):
        if not isinstance(stream, io.IOBase):
            raise TypeError('The stream does not support IOBase interface')
        self.signature.clear()
        self.valid = False
        stream.seek(0)
        self.signature = struct.unpack('<2L', stream.read(PassDBSignature.KDBX_SIGNATURE_LENGTH))
        if self.signature == PassDBSignature.KDBX_SIGNATURE:
            self.valid = True

