from src.abe_schemes.abenc_omacpabe import OMACPABE
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import GT
from src.policy_generator import generate_policy_string as gp
from time import clock
import numpy as np

def basicTest(n_trials, n_att_authorities, n_attributes):
    """

    :param n_trials: Number of times to run the function and calculate the average
    :param n_att_authorities: Number of attribute authorities
    :param n_attributes: Number of attributes
    :return:
    """
    print("RUN basicTest")

    # scheme setup
    group_object = PairingGroup('SS512')
    omacpabe = OMACPABE(group_object)
    GPP, GMK = omacpabe.abenc_casetup()

    t1_e = 0
    t1_d = 0

    users = {}  # public user data
    authorities = {}

    # charles ideas
    # n_authorities = n_att_authorities
    # n_authority_attr = n_attributes
    authority_names = []
    authorityAttributes = {}
    attribute_master = []

    seed_attributes = [i + 1 for i in range(n_attributes)]

    for i in range(n_att_authorities):
        authority_name = "AUTHORITY" + str(i + 1)
        authority_names.append(authority_name)

        current_auth_attributes = []
        for seed_attr in seed_attributes:
            authority_attribute = authority_name + "." + str(seed_attr)
            current_auth_attributes.append(authority_attribute)

        authorityAttributes[authority_name] = current_auth_attributes
        attribute_master += current_auth_attributes

    for authority in authorityAttributes.keys():
        omacpabe.abenc_aareg(GPP, authority, authorityAttributes[authority], authorities)

    alice = {'id': 'alice', 'authoritySecretKeys': {}, 'keys': None}
    alice['keys'], users[alice['id']] = omacpabe.abenc_userreg(GPP)

    for authority in authorities.keys():
        alice['authoritySecretKeys'][authority] = {}
        for attr in authorityAttributes[authority]:
            omacpabe.abenc_keygen(GPP, authorities[authority], attr, users[alice['id']], alice['authoritySecretKeys'][authority])

    k = group_object.random(GT)

    # showing usage of serialize and deserialize for converting group elements
    q = group_object.serialize(k)
    assert isinstance(q, object)
    obj = group_object.deserialize(q)

    # policy_str = '((AUTHORITY3.9 and AUTHORITY9.2 and AUTHORITY5.2 or AUTHORITY9.4 or AUTHORITY2.2 or AUTHORITY6.2 or AUTHORITY2.3 or AUTHORITY1.10 or AUTHORITY10.4 and AUTHORITY10.5 or AUTHORITY10.2 or AUTHORITY1.9 and AUTHORITY4.10))'

    policy_str = gp(attribute_master, n_attributes)

    # attempt at benchmarking
    t1_enc_list = []
    for i in range(n_trials):
        start = clock()
        CT = omacpabe.abenc_encrypt(GPP, policy_str, k, authorities)
        t1_e = clock() - start
        t1_enc_list.append(t1_e)

    avg_encryption_time = sum(t1_enc_list) / len(t1_enc_list)
    # print("average encryption time = ", avg_encryption_time)

    TK, C = omacpabe.abenc_generatetoken(GPP, CT, alice['authoritySecretKeys'], alice['keys'][0])

    t1_dec_list = []
    for i in range(n_trials):
        start = clock()
        PT = omacpabe.abenc_decrypt(C, TK, alice['keys'])
        t1_d = clock() - start
        t1_dec_list.append(t1_d)

    avg_decryption_time = sum(t1_dec_list) / len(t1_dec_list)
    # print("average decryption time = ", avg_decryption_time)

    assert k == PT, 'FAILED DECRYPTION!'
    # print('SUCCESSFUL DECRYPTION')

    return avg_encryption_time, avg_decryption_time


def revokedTest(n_trials, n_att_authorities, n_attributes):
    """

    :param n_trials:
    :param n_att_authorities:
    :param n_attributes:
    :return:
    """
    print("RUN revokedTest")

    # scheme setup
    group_object = PairingGroup('SS512')
    omacpabe = OMACPABE(group_object)
    GPP, GMK = omacpabe.abenc_casetup()

    t1_rev = 0

    users = {}  # public user data
    authorities = {}

    # charles ideas
    # n_authorities = n_att_authorities
    # n_authority_attr = n_attributes
    authority_names = []
    authorityAttributes = {}
    attribute_master = []

    seed_attributes = [i + 1 for i in range(n_attributes)]

    for i in range(n_att_authorities):
        authority_name = "AUTHORITY" + str(i + 1)
        authority_names.append(authority_name)

        current_auth_attributes = []
        for seed_attr in seed_attributes:
            authority_attribute = authority_name + "." + str(seed_attr)
            current_auth_attributes.append(authority_attribute)

        authorityAttributes[authority_name] = current_auth_attributes
        attribute_master += current_auth_attributes

    for authority in authorityAttributes.keys():
        omacpabe.abenc_aareg(GPP, authority, authorityAttributes[authority], authorities)


    alice = {'id': 'alice', 'authoritySecretKeys': {}, 'keys': None}
    bob = {'id': 'bob', 'authoritySecretKeys': {}, 'keys': None}

    alice['keys'], users[alice['id']] = omacpabe.abenc_userreg(GPP)
    bob['keys'], users[bob['id']] = omacpabe.abenc_userreg(GPP)

    for authority in authorities.keys():
        alice['authoritySecretKeys'][authority] = {}
        bob['authoritySecretKeys'][authority] = {}
        for attr in authorityAttributes[authority]:
            omacpabe.abenc_keygen(GPP, authorities[authority], attr, users[alice['id']], alice['authoritySecretKeys'][authority])
            omacpabe.abenc_keygen(GPP, authorities[authority], attr, users[bob['id']], bob['authoritySecretKeys'][authority])

    k = group_object.random(GT)

    # policy_str = '((AUTHORITY1.1 or AUTHORITY2.1 or AUTHORITY3.1 or AUTHORITY4.1))'
    policy_str = gp(attribute_master, n_attributes)

    CT = omacpabe.abenc_encrypt(GPP, policy_str, k, authorities)

    TK1a, C1a = omacpabe.abenc_generatetoken(GPP, CT, alice['authoritySecretKeys'], alice['keys'][0])
    TK1b, C1b = omacpabe.abenc_generatetoken(GPP, CT, bob['authoritySecretKeys'], bob['keys'][0])

    PT1a = omacpabe.abenc_decrypt(C1a, TK1a, alice['keys'])
    PT1b = omacpabe.abenc_decrypt(C1b, TK1b, bob['keys'])

    assert k == PT1a, 'FAILED DECRYPTION (1a)!'
    assert k == PT1b, 'FAILED DECRYPTION (1b)!'
    print('SUCCESSFUL DECRYPTION 1')

    # revoke bob on an attribute
    attribute = policy_str.split()[0][1:]
    revocation_authority = policy_str.split()[0][1:-2]

    t1_rev_list = []
    for i in range(n_trials):
        start = clock()
        UK = omacpabe.abenc_ukeygen(GPP, authorities[revocation_authority], attribute, users[alice['id']])
        omacpabe.abenc_skupdate(alice['authoritySecretKeys'][revocation_authority], attribute, UK['KUK'])
        omacpabe.abenc_ctupdate(GPP, CT, attribute, UK['CUK'])
        t1_rev = clock() - start
        t1_rev_list.append(t1_rev)

    avg_revocation_time = sum(t1_rev_list) / len(t1_rev_list)
    print("average revocation time = ", avg_revocation_time)

    TK2a, C2a = omacpabe.abenc_generatetoken(GPP, CT, alice['authoritySecretKeys'], alice['keys'][0])
    TK2b, C2b = omacpabe.abenc_generatetoken(GPP, CT, bob['authoritySecretKeys'], bob['keys'][0])

    PT2a = omacpabe.abenc_decrypt(C2a, TK2a, alice['keys'])
    PT2b = omacpabe.abenc_decrypt(C2b, TK2b, bob['keys'])

    assert k == PT2a, 'FAILED DECRYPTION (2a)!'
    assert k != PT2b, 'SUCCESSFUL DECRYPTION (2b)!'
    print('SUCCESSFUL DECRYPTION 2')


if __name__ == '__main__':
    # basicTest(n_trials, n_att_authorities, n_attributes)
    n_trials = 1
    # n_att_authorities = [5, 10, 15, 20, 25]
    n_att_authorities = [3]

    enc_time_att_authorities = []
    dec_time_att_authorities = []

    for n_attauth in n_att_authorities:
        enc_time, dec_time = basicTest(n_trials, n_attauth, 15)
        enc_time_att_authorities.append(enc_time)
        dec_time_att_authorities.append(dec_time)


    print(enc_time_att_authorities)
    print(dec_time_att_authorities)

    # combine lists and convert to numpy array
    enc_dec_times = np.array([enc_time_att_authorities, dec_time_att_authorities]).transpose()
    # save as npy file
    np.save('my_test_data', enc_dec_times)

    for n_attauth in n_att_authorities:
        revokedTest(n_trials, n_attauth, 5)
