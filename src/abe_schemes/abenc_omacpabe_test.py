from src.abe_schemes.abenc_omacpabe import OMACPABE
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import GT
from time import clock


def basicTest():
    """

    :return:
    """
    print("RUN basicTest")
    group_object = PairingGroup('SS512')
    omacpabe = OMACPABE(group_object)
    GPP, GMK = omacpabe.abenc_casetup()

    t1_e = 0
    t1_d = 0

    users = {}  # public user data
    authorities = {}

    authority1 = "authority1"
    authority2 = "authority2"
    authority3 = "authority3"
    authority4 = "authority4"

    authorityAttributes = {authority1: ["ONE", "TWO", "THREE", "FOUR", "FIVE"],
                           authority2: ["AB", "AC", "AA", "AD", "AE"],
                           authority3: ["SIX", "SEVEN", "EIGHT", "NINE", "TEN"],
                           authority4: ["EF", "AG", "AH", "AI", "AJ"]}

    for authority in authorityAttributes.keys():
        omacpabe.abenc_aareg(GPP, authority, authorityAttributes[authority], authorities)

    alice = {'id': 'alice', 'authoritySecretKeys': {}, 'keys': None}

    alice['keys'], users[alice['id']] = omacpabe.abenc_userreg(GPP)

    for authority in authorities.keys():
        alice['authoritySecretKeys'][authority] = {}
        for attr in authorityAttributes[authority]:
            # print(attr)
            omacpabe.abenc_keygen(GPP, authorities[authority], attr, users[alice['id']], alice['authoritySecretKeys'][authority])

    k = group_object.random(GT)

    # showing usage of serialize and deserialize for converting group elements
    q = group_object.serialize(k)
    assert isinstance(q, object)
    obj = group_object.deserialize(q)

    policy_str = '((THREE and TWO and SEVEN or EIGHT and FIVE and ONE and NINE and TEN) and \
                (AB and AC and AA and AD and AE and EF and AG and AH and AI and AJ))'

    # attempt at benchmarking
    # for i in range(1):
    #    start = clock()
    #    CT = omacpabe.abenc_encrypt(GPP, policy_str, k, authorities)
    #    t1_e += clock() - start

    start = clock()
    CT = omacpabe.abenc_encrypt(GPP, policy_str, k, authorities)
    t1_e += clock() - start

    print("the encryption time is ", t1_e)

    TK, C = omacpabe.abenc_generatetoken(GPP, CT, alice['authoritySecretKeys'], alice['keys'][0])

    start = clock()
    PT = omacpabe.abenc_decrypt(C, TK, alice['keys'])
    t1_d += clock() - start

    print("the decryption time is ", t1_d)

    assert k == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')


def revokedTest():
    """

    :return:
    """
    print("RUN revokedTest")
    group_object = PairingGroup('SS512')
    omacpabe = OMACPABE(group_object)
    GPP, GMK = omacpabe.abenc_casetup()

    users = {}  # public user data
    authorities = {}

    authority1 = "authority1"
    authority2 = "authority2"
    authority3 = "authority3"
    authority4 = "authority4"

    authorityAttributes = {authority1: ["ONE", "TWO", "THREE", "FOUR", "FIVE"],
                           authority2: ["AB", "AC", "AA", "AD", "AE"],
                           authority3: ["SIX", "SEVEN", "EIGHT", "NINE", "TEN"],
                           authority4: ["EF", "AG", "AH", "AI", "AJ"]}

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

    policy_str = '((THREE and TWO and SEVEN or EIGHT and FIVE and ONE and NINE and TEN) and \
                 (AB and AC and AA and AD and AE and EF and AG and AH and AI and AJ))'

    CT = omacpabe.abenc_encrypt(GPP, policy_str, k, authorities)

    TK1a, C1a = omacpabe.abenc_generatetoken(GPP, CT, alice['authoritySecretKeys'], alice['keys'][0])
    TK1b, C1b = omacpabe.abenc_generatetoken(GPP, CT, bob['authoritySecretKeys'], bob['keys'][0])

    PT1a = omacpabe.abenc_decrypt(C1a, TK1a, alice['keys'])
    PT1b = omacpabe.abenc_decrypt(C1b, TK1b, bob['keys'])

    assert k == PT1a, 'FAILED DECRYPTION (1a)!'
    assert k == PT1b, 'FAILED DECRYPTION (1b)!'
    print('SUCCESSFUL DECRYPTION 1')

    # revoke bob on "ONE"
    attribute = "ONE"
    UK = omacpabe.abenc_ukeygen(GPP, authorities[authority1], attribute, users[alice['id']])
    omacpabe.abenc_skupdate(alice['authoritySecretKeys'][authority1], attribute, UK['KUK'])
    omacpabe.abenc_ctupdate(GPP, CT, attribute, UK['CUK'])

    TK2a, C2a = omacpabe.abenc_generatetoken(GPP, CT, alice['authoritySecretKeys'], alice['keys'][0])
    TK2b, C2b = omacpabe.abenc_generatetoken(GPP, CT, bob['authoritySecretKeys'], bob['keys'][0])

    PT2a = omacpabe.abenc_decrypt(C2a, TK2a, alice['keys'])
    PT2b = omacpabe.abenc_decrypt(C2b, TK2b, bob['keys'])

    assert k == PT2a, 'FAILED DECRYPTION (2a)!'
    assert k != PT2b, 'SUCCESSFUL DECRYPTION (2b)!'
    print('SUCCESSFUL DECRYPTION 2')


if __name__ == '__main__':
    basicTest()
    revokedTest()
