from Crypto.Hash import SHA256
import xml.etree.ElementTree as ET
import base64

class PassDBCredentials:
    def __init__(self, **credentials):
        self.set_credentials(**credentials)

    def set_credentials(self, **credentials):
        self.hash = None
        keys = []
        if 'password' in credentials:
            # Получаю хэш пароля
            keys.append(SHA256.new(credentials['password'].encode('utf-8')).digest())
        if 'keyfile' in credentials:
            # Получаю хэш файла
            keys.append(self.load_keyfile(credentials['keyfile']))

        # Шаг 2: получаю комбинированный хэш пароля+файла путем взятия хэша
        # от сцепленного хэша пароля и файла
        if len(keys) > 0:
            self.hash = SHA256.new(b''.join(keys)).digest()

    def load_keyfile(self, keyfile):
        """
        Получить хэш по файлу ключа.
        Возвращает хэш по файлу
        Причем вариантов может быть несколько:
            1. xml-файл
            2. текстовый файл, непосредственно в котором находится хэш
            3. просто какой-то файл, хэш которого необходимо получить
        """
        try:
            return self._load_xml_keyfile(keyfile)
        except (ET.ParseError, TypeError):
            pass
        return self._load_plain_keyfile(keyfile)

    def _load_xml_keyfile(self, keyfile):
        """
        Пример файла ключа в формате xml:
        // <?xml version="1.0" encoding="utf-8"?>
        // <KeyFile>
        //     <Meta>
        //         <Version>1.00</Version>
        //     </Meta>
        //     <Key>
        //        <Data>ySFoKuCcJblw8ie6RkMBdVCnAf4EedSch7ItujK6bmI=</Data>
        //     </Key>
        // </KeyFile>
        """
        root = ET.parse(keyfile).getroot()
        key_data = root.find('Key/Data')
        if key_data is not None:
            return base64.b64decode(key_data.text)
        else:
            raise TypeError('Not a xml keyfile!')

    def _load_plain_keyfile(self, keyfile):
        """
        Ключ может храниться в текстовом файле. В этом случае размер файла 32
        или 64 байта
        """
        with open(keyfile,'br') as f:
            key = f.read()
            if len(key) == 32:
                return key
            if len(key) == 64:
                return key.decode('hex')
            return SHA256.new(key).digest()
        raise IOError('Could not read keyfile')
