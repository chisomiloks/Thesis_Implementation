"""

"""
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from Crypto.Random import get_random_bytes
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import GT


# generate symmetric key from random pairing element
def symmetric_key_gen():
    groupObj = PairingGroup('SS512')
    pairing_element = groupObj.random(GT)
    symmetric_key = groupObj.serialize(pairing_element)
    return pairing_element, symmetric_key


# extract pairing element from symmetric key
def abe_key_extract(sym_key):
    groupObj = PairingGroup('SS512')
    abe_key = groupObj.deserialize(sym_key)
    return abe_key


def encrypt(pwd, data):
    salt = get_random_bytes(8)
    key = KDF.PBKDF2(pwd[:128], salt)  # pwd[:128] truncates key to max 128 byte size for AES encryption (serialize converts to string that is 174 bits)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return salt + iv + cipher.encrypt(data)


def decrypt(pwd, msg):
    key = KDF.PBKDF2(pwd[:128], msg[:8])  # pwd[:128] truncates key to max 128 byte size for AES encryption (serialize converts to string that is 174 bits)
    cipher = AES.new(key, AES.MODE_CFB, msg[8:24])
    return cipher.decrypt(msg[24:])


if __name__ == '__main__':
    original_message = b'Sample message to be decrypted'
    secret_key = b'3:nw2sPUo47KrNHcDRuC5RYsc1XxE0yW2s7WBi9mH+7XVHHW3QfRRhLVYgKzT7LEXLBJExRrZpVy\
                /XNEWkDYC6EC8RLq69fbsbpc4s1oPAiFAcDULzdg350uf728OSKUAe1lYgeTpycf0z0any7JTEWDahj\
                xfTfS6iRh4AhEv1qBg='

    ciphertext = encrypt(secret_key, original_message)
    decrypted_message = decrypt(secret_key, ciphertext)

    assert original_message == decrypted_message, "FAILED!!!"  # expected == actual
