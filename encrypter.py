from cryptography.fernet import Fernet
import rsa
from rsa import PrivateKey, PublicKey


class Encrypter:
    def __init__(self, is_static_key= False):
        if is_static_key:
            self.key = b'qJTUCnZ2zWbAzaF6DkBotfoQ4UIj4gL-rBzXB2tXj98='
        else:
            self.key = Fernet.generate_key()
        self.fernet_key = Fernet(self.key)

        # asymmetric
        self.public_key, self.private_key = rsa.newkeys(1024)
        self.foreign_public_key = None

    def do_encrypt(self, message: bytes):
        return self.fernet_key.encrypt(message)

    def do_decrypt(self, ciphertext: bytes) -> bytes:
        return self.fernet_key.decrypt(ciphertext)

    # asymmetric
    def do_asym_encrypt(self, message: bytes, public_key: PublicKey) -> bytes:
        return rsa.encrypt(message, public_key)

    def do_asym_decrypt(self, ciphertext: bytes, private_key: PrivateKey) -> bytes:
        return rsa.decrypt(ciphertext, private_key)

    def get_public_key(self) -> bytes:
        return self.public_key.save_pkcs1("PEM")

    def insert_foreign_public_key(self, public_key: bytes):
        self.foreign_public_key = rsa.PublicKey.load_pkcs1(public_key)

    def do_asym_decrypt_of_foreign_message(self, ciphertext: bytes) -> bytes:
        return self.do_asym_decrypt(ciphertext, self.private_key)

    def do_asym_encrypt_of_message(self, ciphertext: bytes) -> bytes:
        return self.do_asym_encrypt(ciphertext, self.foreign_public_key)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    public_key = b'-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAOlcdo2PPZu9ofBmOylDPfTJjmWVX7V5ACB4eDvdJraen5liZVHUl3zP\nNz3ByACis4iGkIRZWQKvjK0i4YDx6VZ/ulDMftWN3/xVotuNsuGoEyKMegLrQmLk\nUMhudQdd44AwIZzJWs/RjuQFNdio0xMlv0gVYe6ifDnMimoBcuATAgMBAAE=\n-----END RSA PUBLIC KEY-----\n'
    private_key = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXwIBAAKBgQDpXHaNjz2bvaHwZjspQz30yY5llV+1eQAgeHg73Sa2np+ZYmVR\n1Jd8zzc9wcgAorOIhpCEWVkCr4ytIuGA8elWf7pQzH7Vjd/8VaLbjbLhqBMijHoC\n60Ji5FDIbnUHXeOAMCGcyVrP0Y7kBTXYqNMTJb9IFWHuonw5zIpqAXLgEwIDAQAB\nAoGAb//+rkZXTU4gUN7f+hfZvoiWHU8p1lEyrGLlYeXsVK2g7973veSIqFBTtQIy\nWYu9GwNqjPrM66sRm28n1hWAe3f62itoYIPfK06LG/Xg91W/72TkTknPdyQVbBov\nQdDwKTWHE/OZwZUFxCcyTvcgWdr1jH9vy0qQAiq5PlO4BnECRQDtCNeagOnYa0GX\n7YW9KiVzbO4SHICKBRLHpRtfK0kiBc2i2lMwY2SuwpRauK/KGZYzQY+4TDxlUF68\nCt+lnQC2ItNADwI9APwIYT8Np8RbeN9mD0P3DAllpN/jrPJ8yjH/YPUaLvSew77x\nmWfjygGe2RlRWVyKNe3FK51SWkFnlZUbvQJEaIS3nTcu5fEVcUqY6DqHXQgxSecr\nfrCSAVp6YVKS4t+wNxkSCYoqQS0ngYFicjkqE9va5acoEnyH6V7aEwrR334nrF0C\nPGorvYuqXPpC7nBtthCTieaLgyEt8DVWjHbzdgzKsu0p1JwjetRhCUAVgq8/rb1m\nG8HGRdFIV+0ljcX6oQJEKBMsS24tjqrgScQ5agha53DqlWdeVnODV03tJgnH6Pz0\nekz7qrj/ZSb1G8aMij5/Etk2Ykfmw3ZfLfgKdBcE4XuVu94=\n-----END RSA PRIVATE KEY-----\n'

    # Sym
    en = Encrypter(is_static_key=True)
    ciphertext = en.do_encrypt("sdjfh".encode("utf-8"))
    print(en.do_decrypt(ciphertext).decode("utf-8"))

    # Asym
    # va2 -> va
    ciphertext = en.do_asym_encrypt("dsfsdfsdfs".encode("utf-8"), en.public_key) # va2
    print(en.do_asym_decrypt_of_foreign_message(ciphertext).decode("utf-8")) # va

    # va -> va2
    en.insert_foreign_public_key(public_key)
    ciphertext = en.do_asym_encrypt_of_message("dsfsdfsdfs".encode("utf-8")) # va
    print(en.do_asym_decrypt(ciphertext, rsa.PrivateKey.load_pkcs1(private_key)).decode("utf-8")) # va2



