import io
from enum import Enum
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from keepasspy.header import PassDBHeader, PassDBSignature
from keepasspy import consts
from keepasspy.credentials import PassDBCredentials
import codecs
import struct
import zlib
"""
Проекты, с которых понатырил код:
    https://github.com/shirou/kptool
    https://github.com/crass/libkeepass
    https://github.com/keeweb/kdbxweb
    https://github.com/NeoXiD/keepass.io
"""
class PassDB:
    def __init__(self, stream, **credentials):
        self.signature = PassDBSignature()
        self.header = PassDBHeader()
        self.credentials = PassDBCredentials(**credentials)
        self.payload = io.BytesIO()
        if stream is not None:
            self.read(stream)

    """
    Чтение из переданного потока
    """
    def read(self, stream):
        if not isinstance(stream, io.IOBase):
            raise TypeError('The stream does not support IOBase interface.')
        self.signature.read(stream)
        if not self.signature.valid:
            raise ValueError('Invalid database signature.')
        self.header.read(stream)
        # streem теперь указывает на начало области с данными
        # только после чтения заголовка можно получить мастер-ключ
        self.set_master_key()
        self._decrypt(stream)

    """
    Чтение и расшифровка данных
    """
    def _decrypt(self, stream):
        if self.header.fields['cipher'].value == consts.Cypher.aes:
            data = self._aes_decrypt(stream)
            # в последнем байте хранится количество байт, которые необходимо
            # отрезать?
            data = data[:len(data) - bytearray(data)[-1]]
        elif self.header.fields['cipher'].value == consts.Cypher.twofish:
            self._twofish_decrypt(stream)
            print('twofish cypher')
        else:
            raise ValueError('Invalid cypher')
        # Проверка на то, что расшифровали правильно:
        # в поле stream_start_bytes в незашифрованном виде хранится несколько
        # байт БД. Если совпадает с тем, что получилось в результате
        # расшифровки, значит ключ правильный. Иначе - нет.
        start_bytes_length = len(self.header.fields['stream_start_bytes'].value)
        if self.header.fields['stream_start_bytes'].value == \
            data[:start_bytes_length]:
            # ключ правильный. данные начинаются с start_bytes_length
            data = data[start_bytes_length:]
            in_stream = io.BytesIO(data)
            while True:
                num_block,block_hash,block_length = struct.unpack('<I32sI',in_stream.read(40))
                if block_length > 0:
                    block_payload = in_stream.read(block_length)
                    if SHA256.new(block_payload).digest() == block_hash:
                        self.payload.write(block_payload)
                    else:
                        raise ValueError('Invalid block hash')
                else:
                    break
                self.payload.seek(0)
                if self.header.fields['compression'].value == consts.CompressionAlgo.gzip:
                    decmp = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    self.payload = io.BytesIO(decmp.decompress(self.payload.read()))
                    self.payload.seek(0)
                payload_file = open('payload.out', 'wb')
                payload_file.write(self.payload.read())
        else:
            raise ValueError('Invalid master key')
    # TODO: Попробовать переделать в AESStream (например)
    # Для этого нужно определить:
    # __init__(self):
    # readable(self): return True
    # readinto(self,b):
    # try:
    #    l = len(b)
    #    chunk = self.leftover or next(iterable)
    #    output, self.leftover = chunk[:l], chunk[l:]
    #    b[:len(output)] = output
    #    return len(output)
    # except StopIteration:
    #    return 0 # indicate EOF
    # io.BufferedReader(AESStream(), buffer_size=buffer_size)


    def _aes_decrypt(self, stream):
        cipher = AES.new(self.master_key,
                AES.MODE_CBC,
                self.header.fields['enc_iv'].value)

        return(cipher.decrypt(stream.read()))

    def _twofish_decrypt(self, stream):
        pass

    def set_master_key(self, **credentials):
        # Шаг 0: очищаю мастер-ключ
        self.clear_master_key()
        # Шаг 1: в поле transform_seed заголовка файла находится кодовая фраза
        # необходимо комбинированный хэш (пароля и файла) зашифровать этой кодовой
        # фразой с использованием алгоритма AES.
        # При этом количество циклов шифрования указывается в поле enc_rounds заголовка.
        cipher = AES.new(self.header.fields['transform_seed'].value,
                AES.MODE_ECB)
        encrypted_msg = self.credentials.hash
        for i in range(0, self.header.fields['enc_rounds'].value):
            encrypted_msg = cipher.encrypt(encrypted_msg)
        # шаг 4: получить хэш от полученного ключа
        transformed_key = SHA256.new(encrypted_msg).digest()
        self.master_key = SHA256.new(self.header.fields['master_seed'].value +
                transformed_key).digest()
        print(self.master_key)

    def clear_master_key(self):
        self.master_key = None

if __name__ == '__main__':
    pass_db = PassDB(open('passwords.kdbx', 'rb'), password='w31Ca*tR2JMI5D')

