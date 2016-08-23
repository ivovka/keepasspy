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

with open('mk.out', 'rb') as f:
    master_key = f.read()
with open('iv.out', 'rb') as f:
    aes_iv = f.read()
#with open('new_decrypted.out', 'wb') as f_out:
#    for b in aes_generator(master_key, aes_iv):
#        f_out.write(b)

with iterable_to_stream(aes_generator(master_key, aes_iv)) as b, \
    open('new_decrypted.out', 'wb') as f_out:
    data = b.read(256)
    while data != b'':
        print(len(data))
        f_out.write(data)
        data = b.read(256)
