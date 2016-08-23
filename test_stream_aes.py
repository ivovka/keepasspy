from Crypto.Cipher import AES

with open('mk.out', 'rb') as f:
    master_key = f.read()
with open('iv.out', 'rb') as f:
    aes_iv = f.read()
cipher = AES.new(master_key, AES.MODE_CBC, aes_iv)
with open('encrypted.out', 'rb') as f, open('new_decrypted.out', 'wb') as f_out:
    while True:
        block = f.read(len(aes_iv))
        if block == b'':
            break
        dec_block = cipher.decrypt(block)
        f_out.write(dec_block)
