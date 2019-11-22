from src.abe_schemes.abenc_omacpabe import OMACPABE
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import GT
from src.policy_generator import generate_policy_string as gp
from time import clock
import numpy as np
import random


def basic_test(number_of_basic_trials, number_of_attribute_authorities, number_of_attributes):
    """

    :param number_of_basic_trials: Number of times to run the function and calculate the average
    :param number_of_attribute_authorities: Number of attribute authorities
    :param number_of_attributes: Number of attributes
    :return:
    """

    # scheme setup
    group_object = PairingGroup('SS512')
    omacpabe = OMACPABE(group_object)
    GPP, GMK = omacpabe.abenc_casetup()

    users = {}  # public user data
    authorities = {}  # authority data dictionary

    attribute_authorities = []  # list of attribute authorities
    authorities_and_attributes = {}  # dictionary of attributes and the matching authorities
    attribute_master_list = []  # master list of all possible attributes

    seed_length = int(number_of_attributes / number_of_attribute_authorities)
    seed_attributes = [i + 1 for i in range(seed_length)]  # list comprehension to generate number list to aid in generation of attributes

    for i in range(number_of_attribute_authorities):
        attribute_authority_name = "AUTHORITY" + str(i + 1)  # create attribute authorities
        attribute_authorities.append(attribute_authority_name)  # add new authorities to overall list

        current_attribute_authority_attributes = []  # attributes for current authority
        for seed_attr in seed_attributes:
            authority_attribute = attribute_authority_name + "." + str(seed_attr)  # create attribute
            current_attribute_authority_attributes.append(authority_attribute)  # add attribute to authority attribute list

        authorities_and_attributes[attribute_authority_name] = current_attribute_authority_attributes  # add authority as key and its attributes as value to the dictionary
        attribute_master_list += current_attribute_authority_attributes  # add attributes created to master attribute list

    for authority in authorities_and_attributes.keys():
        omacpabe.abenc_aareg(GPP, authority, authorities_and_attributes[authority], authorities)

    alice = {'id': 'alice', 'authoritySecretKeys': {}, 'keys': None}  # new user alice

    alice['keys'], users[alice['id']] = omacpabe.abenc_userreg(GPP)

    for authority in authorities.keys():
        alice['authoritySecretKeys'][authority] = {}
        for attr in authorities_and_attributes[authority]:
            omacpabe.abenc_keygen(GPP, authorities[authority], attr, users[alice['id']], alice['authoritySecretKeys'][authority])

    plain_text_secret_key_group_element = group_object.random(GT)

    # showing usage of serialize and deserialize for converting group elements
    bit_string_from_group_element = group_object.serialize(plain_text_secret_key_group_element)
    assert isinstance(bit_string_from_group_element, object)
    group_element_from_bit_string = group_object.deserialize(bit_string_from_group_element)
    assert group_element_from_bit_string == plain_text_secret_key_group_element, 'SERIALIZATION ERROR!'

    policy_string = gp(attribute_master_list, number_of_attributes)  # generate policy

    # benchmarking
    encryption_times = []  # list to hold encryption times for multiple iterations
    for i in range(number_of_basic_trials):
        start_time = clock()
        ciphertexts = omacpabe.abenc_encrypt(GPP, policy_string, plain_text_secret_key_group_element, authorities)
        duration = clock() - start_time
        encryption_times.append(duration)

    # average_encryption_time = sum(encryption_times) / len(encryption_times)
    # print("average encryption time = ", average_encryption_time)

    token, partially_decrypted_ciphertext = omacpabe.abenc_generatetoken(GPP, ciphertexts, alice['authoritySecretKeys'], alice['keys'][0])

    decryption_times = []  # list to hold decryption times for multiple iterations
    for i in range(number_of_basic_trials):
        start_time = clock()
        plaintext = omacpabe.abenc_decrypt(partially_decrypted_ciphertext, token, alice['keys'])
        duration = clock() - start_time
        decryption_times.append(duration)

    # average_decryption_time = sum(decryption_times) / len(decryption_times)
    # print("average decryption time = ", average_decryption_time)

    assert plain_text_secret_key_group_element == plaintext, 'FAILED DECRYPTION!'
    # print('SUCCESSFUL DECRYPTION')

    return encryption_times, decryption_times
    # return average_encryption_time, average_decryption_time


def revocation_test(number_of_revocation_trials, number_of_attribute_authorities, number_of_attributes, number_attributes_to_revoke):
    """

    :param number_of_revocation_trials:
    :param number_of_attribute_authorities:
    :param number_of_attributes:
    :return:
    """

    # scheme setup
    group_object = PairingGroup('SS512')
    omacpabe = OMACPABE(group_object)
    GPP, GMK = omacpabe.abenc_casetup()

    users = {}  # public user data
    authorities = {}  # authority data dictionary

    attribute_authorities = []  # list of attribute authorities
    authorities_and_attributes = {}  # dictionary of attributes and the matching authorities
    attribute_master_list = []  # master list of all possible attributes

    seed_length = int(number_of_attributes/number_of_attribute_authorities)
    seed_attributes = [i + 1 for i in range(seed_length)]  # list comprehension to generate number list to aid in generation of attributes

    for i in range(number_of_attribute_authorities):
        attribute_authority_name = "AUTHORITY" + str(i + 1)  # create attribute authorities
        attribute_authorities.append(attribute_authority_name)  # add new authorities to overall list

        current_attribute_authority_attributes = []  # attributes for current authority
        for seed_attr in seed_attributes:
            authority_attribute = attribute_authority_name + "." + str(seed_attr)  # create attribute
            current_attribute_authority_attributes.append(authority_attribute)  # add attribute to authority attribute list

        authorities_and_attributes[attribute_authority_name] = current_attribute_authority_attributes  # add authority as key and its attributes as value to the dictionary
        attribute_master_list += current_attribute_authority_attributes  # add attributes created to master attribute list

    for authority in authorities_and_attributes.keys():
        omacpabe.abenc_aareg(GPP, authority, authorities_and_attributes[authority], authorities)

    alice = {'id': 'alice', 'authoritySecretKeys': {}, 'keys': None}  # new user alice
    bob = {'id': 'bob', 'authoritySecretKeys': {}, 'keys': None}  # new user bob

    alice['keys'], users[alice['id']] = omacpabe.abenc_userreg(GPP)
    bob['keys'], users[bob['id']] = omacpabe.abenc_userreg(GPP)

    for authority in authorities.keys():
        alice['authoritySecretKeys'][authority] = {}
        bob['authoritySecretKeys'][authority] = {}
        for attr in authorities_and_attributes[authority]:
            omacpabe.abenc_keygen(GPP, authorities[authority], attr, users[alice['id']], alice['authoritySecretKeys'][authority])
            omacpabe.abenc_keygen(GPP, authorities[authority], attr, users[bob['id']], bob['authoritySecretKeys'][authority])

    plain_text_secret_key_group_element = group_object.random(GT)

    # policy_string = '((AUTHORITY1.1 or AUTHORITY2.1 or AUTHORITY3.1 or AUTHORITY4.1))'
    policy_string = gp(attribute_master_list, number_of_attributes)

    ciphertexts = omacpabe.abenc_encrypt(GPP, policy_string, plain_text_secret_key_group_element, authorities)

    alice_token_v1, alice_partially_decrypted_ciphertext_v1 = omacpabe.abenc_generatetoken(GPP, ciphertexts, alice['authoritySecretKeys'], alice['keys'][0])
    bob_token_v1, bob_partially_decrypted_ciphertext_v1 = omacpabe.abenc_generatetoken(GPP, ciphertexts, bob['authoritySecretKeys'], bob['keys'][0])

    alice_plain_text_v1 = omacpabe.abenc_decrypt(alice_partially_decrypted_ciphertext_v1, alice_token_v1, alice['keys'])
    bob_plain_text_v1 = omacpabe.abenc_decrypt(bob_partially_decrypted_ciphertext_v1, bob_token_v1, bob['keys'])

    assert plain_text_secret_key_group_element == alice_plain_text_v1, 'FAILED DECRYPTION (1a)!'
    assert plain_text_secret_key_group_element == bob_plain_text_v1, 'FAILED DECRYPTION (1b)!'
    # print('SUCCESSFUL DECRYPTION 1')

    # testing the selection of random attribute for revocation
    # sample_attribute = attribute_master_list[random.sample(range(1, len(attribute_master_list)), 1)[0]]

    # revoke bob on an attribute
    # get random attribute from existing policy
    # attribute_to_be_revoked = policy_string.split()[0][1:]

    # derive authority name from attribute name
    # revocation_authority = attribute_to_be_revoked.split(".")[0]

    revoked_attributes = []
    random_elements = random.sample(range(1, number_of_attributes), number_attributes_to_revoke)

    update_keys_temp = {}

    for element in random_elements:
        revoked_attributes.append(attribute_master_list[element])

    # print(revoked_attributes)

    revocation_times = []  # list to hold revocation times for multiple iterations
    for i in range(number_of_revocation_trials):
        # update_keys = omacpabe.abenc_ukeygen(GPP, authorities[revocation_authority], attribute_to_be_revoked, users[alice['id']])  # create update keys for user secret keys and ciphertexts
        # omacpabe.abenc_ctupdate(GPP, ciphertexts, attribute_to_be_revoked, update_keys_temp[attribute_to_be_revoked]['CUK'])  # update ciphertexts
        # omacpabe.abenc_skupdate(alice['authoritySecretKeys'][revocation_authority], attribute_to_be_revoked, update_keys_temp[attribute_to_be_revoked]['KUK'])  # update the user secret key
        for temp_attribute in revoked_attributes:
            update_keys_temp[temp_attribute] = omacpabe.abenc_ukeygen(GPP, authorities[temp_attribute.split(".")[0]], temp_attribute, users[alice['id']])
            # print(update_keys_temp)
        for temp_attribute in revoked_attributes:
            omacpabe.abenc_ctupdate(GPP, ciphertexts, temp_attribute, update_keys_temp[temp_attribute]['CUK'])
        start_time = clock()
        for temp_attribute in revoked_attributes:
            omacpabe.abenc_skupdate(alice['authoritySecretKeys'][temp_attribute.split(".")[0]], temp_attribute, update_keys_temp[temp_attribute]['KUK'])
        duration = clock() - start_time
        revocation_times.append(duration)

    # average_revocation_time = sum(revocation_times) / len(revocation_times)
    # print("average revocation time = ", average_revocation_time)

    alice_token_v2, alice_partially_decrypted_ciphertext_v2 = omacpabe.abenc_generatetoken(GPP, ciphertexts, alice['authoritySecretKeys'], alice['keys'][0])
    bob_token_v2, bob_partially_decrypted_ciphertext_v2 = omacpabe.abenc_generatetoken(GPP, ciphertexts, bob['authoritySecretKeys'], bob['keys'][0])

    alice_plaintext_v2 = omacpabe.abenc_decrypt(alice_partially_decrypted_ciphertext_v2, alice_token_v2, alice['keys'])
    bob_plaintext_v2 = omacpabe.abenc_decrypt(bob_partially_decrypted_ciphertext_v2, bob_token_v2, bob['keys'])

    assert plain_text_secret_key_group_element == alice_plaintext_v2, 'FAILED DECRYPTION (2a)!'
    assert plain_text_secret_key_group_element != bob_plaintext_v2, 'SUCCESSFUL DECRYPTION (2b)!'
    # print('SUCCESSFUL DECRYPTION 2')

    # return average_revocation_time
    return revocation_times


if __name__ == '__main__':
    # basic_test(number_of_trials, number_of_authorities, number_of_attributes)
    number_of_trials = 1
    # number_of_attribute_authorities = [5, 10, 15, 20, 25]
    number_of_attribute_authorities = [1, 2, 3, 4, 5]

    encryption_time_data = []
    decryption_time_data = []
    revocation_time_data = []

    for number_of_authorities in number_of_attribute_authorities:
        enc_time, dec_time = basic_test(number_of_trials, number_of_authorities, number_of_authorities * 5)
        rev_time = revocation_test(number_of_trials, number_of_authorities, number_of_authorities * 5, number_of_authorities * 3)

        encryption_time_data.append(enc_time)
        decryption_time_data.append(dec_time)
        revocation_time_data.append(rev_time)

    print("encryption times", encryption_time_data)
    print("decryption times", decryption_time_data)
    print("revocation times", revocation_time_data)

    # combine lists and convert to numpy array
    # enc_dec_times = np.array([encryption_time_data, decryption_time_data]).transpose()
    # # save as npy file
    # np.save('my_test_data', enc_dec_times)
    #
    # for number_of_authorities in number_of_attribute_authorities:
    #     revocation_test(number_of_trials, number_of_authorities, 5)
