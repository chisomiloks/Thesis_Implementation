"""
Module for the interfacing of ABE components of framework with symmetric file encryption

:Authors: Munachiso Ilokah
:Date: 07-2018
"""

from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from Crypto.Random import get_random_bytes
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import GT
from src.abe_schemes.abenc_omacpabe import OMACPABE
from time import clock
import filecmp
import numpy as np


# generate symmetric key from random pairing element
def symmetric_key_gen():
    """
    Function to generate symmetric key string from abe pairing element
    generated by the charm-crypto library

    :return:    tuple containing abe pairing element and corresponding symmetric key string
    """
    group_object = PairingGroup('SS512')
    pairing_element = group_object.random(GT)
    symmetric_key = group_object.serialize(pairing_element)
    # return pairing_element, symmetric_key
    return symmetric_key


# extract pairing element from symmetric key
def abe_key_extract(sym_key):
    """
    Function to extract abe pairing element from the symmetric key string

    :param sym_key:     symmetric key
    :return:            return abe pairing element that corresponds to symmetric key string
    """
    groupObj = PairingGroup('SS512')
    abe_key = groupObj.deserialize(sym_key)
    return abe_key


def encrypt(pwd, data):
    """
    Encryption function that encrypts a string using EAS encryption with 128 bit key

    :param pwd:     encryption key (first 128 bits to be used if longer than 128)
    :param data:    string to be encrypted
    :return:        ciphertext
    """
    salt = get_random_bytes(8)
    key = KDF.PBKDF2(pwd[:128], salt)  # pwd[:128] truncates key to max 128
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return salt + iv + cipher.encrypt(data)


def decrypt(pwd, msg):
    """
        Decryption function to decrypt ciphertext and return original message

        :param pwd:     decryption key (first 128 bits to be used if longer than 128)
        :param msg:     string to be decrypted
        :return:        plaintext message
    """
    key = KDF.PBKDF2(pwd[:128], msg[:8])  # pwd[:128] truncates key to max 128
    cipher = AES.new(key, AES.MODE_CFB, msg[8:24])
    return cipher.decrypt(msg[24:])


def file_encrypt(input_file, pwd, output_file = None):
    """
    Encryption function for file encryption.

    :param input_file: Name of file to be encrypted.
    :param pwd: Password for file encryption.
    :param output_file: Name of encrypted file. To be given standard name if no argument is given.
    :return: NA
    """
    if output_file is None:
        output_file = input_file + "_enc"
    with open(input_file, "rb") as myfile:
        data = myfile.read()
        enc_data_temp = encrypt(pwd, data)

        with open(output_file, "wb") as encfile:
            encfile.write(enc_data_temp)


def file_decrypt(input_file, pwd, output_file = None):
    """
    Decryption function for file decryption.

    :param input_file: Name of file to be decrypted.
    :param pwd: Password for file decryption.
    :param output_file: Name of decrypted file. To be given standard name if no argument is given.
    :return: NA
    """
    if output_file is None:
        output_file = "/home/munachisoilokah/decrypted_file.txt"
    with open(input_file, "rb") as newfile:
        data = newfile.read()
        dec_data_temp = decrypt(secret_key, data)

        with open(output_file, "wb") as decfile:
            decfile.write(dec_data_temp)

# def generate_policy_string(attribute_master, n_attr):
#     policy_str = ''
#     OPS = ['and', 'or']
#     attr_indices = np.random.randint(0, len(attribute_master), n_attr)
#     for attr_index in attr_indices:
#         attribute = attribute_master[attr_index]
#         op_idx = int(np.random.randint(0, len(OPS), 1))
#         policy_str += attribute + " " + OPS[op_idx] + " "
#
#     print('policy before: ', policy_str)
#     policy_str = "(" + policy_str[:-4].strip() + ")"
#
#     print('policy after: ', policy_str)


if __name__ == '__main__':
    # symmetric key generation
    secret_key = symmetric_key_gen()
    # symmetric file encryption
    file_encrypt("/home/munachisoilokah/nonsense.txt", secret_key)
    # symmetric file decryption
    file_decrypt("/home/munachisoilokah/nonsense.txt_enc", secret_key)

    # assert original_message == decrypted_message, "FAILED!!!"  # expected == actual
    assert filecmp.cmp("/home/munachisoilokah/nonsense.txt", "/home/munachisoilokah/decrypted_file.txt"), "FAILED!!!!"
    print("SUCCESSFUL DECRYPTION")

    # test abe implementation
    abe_key = abe_key_extract(secret_key)
