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
def co_producer(key, iv, fltr):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open('encrypted.out', 'rb') as f:
        next(fltr)
        block = f.read(len(iv))
        while block != b'':
            dec_block = cipher.decrypt(block)
            fltr.send(dec_block)
            block = f.read(len(iv))
    fltr.close()

# эта сопрограмма получает декодированный поток
# и передает его дальше, откусив от последнего блока
# сколько то байт
def co_filter1(receiver):
    """
    Получаем очередную порцию и записываем в буфер. Если после получения в
    буфере более, чем 256 байт, отдаем первую часть буфера, оставляя 256 байт.
    Сдвигаем буфер влево и так далее. До тех пор, пока будет нечего получать.
    Когда больше ничего не дают, откусываем с конца столько, сколько нужно.
    """
    buf = bytearray()
    next(receiver)
    while True:
        try:
            b = yield
            buf.extend(b)
            buflen = len(buf)
            print("Got "+str(buflen)+" bytes from producer")
            while buflen > 256:
                head, buf = buf[:(buflen-256)], buf[(buflen-256):]
                buflen = len(buf)
                print("Sending "+str(len(head))+" bytes to consumer. Left "+str(len(buf))+" bytes.")
                receiver.send(head)
        except GeneratorExit:
            print("There is "+str(len(buf))+" bytes in the buffer")
            print("Need to cut off "+str(buf[-1])+" bytes")
            receiver.send(buf[:(len(buf)-buf[-1])])
            receiver.close()
            break


def test_receiver(f):
    while True:
        try:
            b = yield
            f.write(b)
        except GeneratorExit:
            break

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
    with open('new_decrypted1.out', 'wb') as f:
        receiver_co = test_receiver(f)
        fltr_co = co_filter1(receiver_co)
        prod_co = co_producer(master_key, aes_iv, fltr_co)

