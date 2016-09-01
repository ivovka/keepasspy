from Crypto.Cipher import AES
import io

def aes_generator(key,iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open('encrypted.out', 'rb') as f:
        block = f.read(len(iv))
        while block != b'':
            dec_block = cipher.decrypt(block)
            yield dec_block
            block = f.read(len(iv))

def iterable_to_stream(iterable, buffer_size=io.DEFAULT_BUFFER_SIZE):
    class IterStream(io.RawIOBase):
        def __init__(self):
            self.leftover = None

        def readable(self):
            return True

        def readinto(self, b):
            try:
                l = len(b)
                chunk = self.leftover or next(iterable)
                output, self.leftover = chunk[:l], chunk[l:]
                b[:len(output)] = output
                return len(output)
            except StopIteration:
                return 0
    return io.BufferedReader(IterStream(), buffer_size=buffer_size)

#with open('new_decrypted.out', 'wb') as f_out:
#    for b in aes_generator(master_key, aes_iv):
#        f_out.write(b)

# эта сопрограмма читает и декодирует файл
def co_producer(key, iv, fltr)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open('encrypted.out', 'rb') as f:
        next(fltr)
        block = f.read(len(iv))
        while block != b'':
            dec_block = cipher.decrypt(block)
            fltr.send(dec_block)
            block = f.read(len(iv))

# эта сопрограмма получает декодированный поток
# и передает его дальше, откусив от последнего блока
# сколько то байт
def co_filter1():
    """
    нужно взять буфер размером 512 и заполнять его
    когда заполнится целиком, передать первые 256 байт из него
    и сдвинуть на 256 влево.
    Если входной поток кончился, нужно откусить с конца
    столько байт, сколько записано в последнем байте

    """
    leftover = None
    buf = bytearray()
    while True:
        b = yield
        buflen = len(buf)
        # дописываю в буфер до 512
        buf.extend(b[:(512-buflen)])
        # остаток - в leftover
        leftover = b[(512-buflen):]
        if len(buf) == 512:
            # отдаю первые 256 байт из буфера
            yield buf[:256]
            # и двигаю буфер влево
            buf[:256] = buf[256:]
            del(buf[256:])
        b_len = len(b)


if __name__ == '__main__':
    with open('mk.out', 'rb') as f:
        master_key = f.read()
    with open('iv.out', 'rb') as f:
        aes_iv = f.read()
    with iterable_to_stream(aes_generator(master_key, aes_iv)) as b, \
        open('new_decrypted.out', 'wb') as f_out:
        data = b.read(256)
        while data != b'':
            print(len(data))
            f_out.write(data)
            data = b.read(256)
    fltr_co = co_filter1()
    prod_co = co_producer(master_key, aes_iv, fltr_co)

