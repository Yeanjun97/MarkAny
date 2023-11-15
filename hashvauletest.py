import base64
import hashlib
from Crypto.Cipher import AES 

BS = 16 

pad = (lambda s: s+ (BS - len(s) % BS) * chr(BS - len(s) % BS).encode())
unpad = (lambda s: s[:-ord(s[len(s)-1:])])

def get_sha1_hash(image_path):
    with open(image_path, "rb") as f:
        sha1 = hashlib.sha1()
        for chunk in iter(lambda: f.read(4096), b""):
            sha1.update(chunk)
    return sha1.hexdigest()


class AESCipher(object):
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest() 
        print("AES Key(Key문장 암호화) : ", self.key)

    def encrypt(self, message): 
        message = message.encode() 
        raw = pad(message) 
        cipher = AES.new(self.key, AES.MODE_CBC, self.__iv().encode('utf8')) 
        enc = cipher.encrypt(raw) 
        return base64.b64encode(enc).decode('utf-8') 

    def decrypt(self, enc): 
        enc = base64.b64decode(enc) 
        cipher = AES.new(self.key, AES.MODE_CBC, self.__iv().encode('utf8')) 
        dec = cipher.decrypt(enc) 
        return unpad(dec).decode('utf-8') 

    def __iv(self):
        return chr(0) * 16

image_path = input("이미지 경로: ")

key = input("입력할 키 값: ")

print("-"*100, "\n")

msg = get_sha1_hash(image_path)
print("AES KEY: ", key)
print("\n")
print("원본 메시지: ", msg)

aes = AESCipher(key) 

encrypt = aes.encrypt(msg) 
print("\n")
print("암호화된 해시값: ", encrypt)
print("\n")

decrypt = aes.decrypt(encrypt)
print("복호화된 해시값: ", decrypt) 
print("_"*100, "\n")