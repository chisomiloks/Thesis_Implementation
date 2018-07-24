"""
Kan Yang, Xiaohua Jia

| From: Expressive, Efficient, and Revocable Data Access Control for Multi-Authority Cloud Storage
| Published in: IEEE Transactions on Parallel and Distributed Systems, Vol. 25, No. 7, July 2014
| Available From: http://ieeexplore.ieee.org/xpls/abs_all.jsp?arnumber=6620875&tag=1

* type: Multi-Authority Ciphertext Policy Attribute Based Encryption
* setting: Pairing

:Authors: Munachiso Ilokah
:Date: 05-2016
"""

from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR
from charm.toolbox.pairinggroup import G1
from charm.toolbox.pairinggroup import GT
from charm.toolbox.pairinggroup import pair
from charm.toolbox.secretutil import SecretUtil
from time import clock
# import timeit


class EERDAC(object):
    def __init__(self, groupObj):
        # create secret sharing scheme
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj

    def CASetup(self):
        """
        Global setup for scheme run by the CA to generate the Global Master Key (GMK)
        and the Global Public Parameters (GPP)

        :return: GMK, GPP
        """
        # bilinear group G of prime p is selected
        # select generator g of G
        g = self.group.random(G1)
        # select random oracle which maps inputs to an element of G
        H = lambda x: self.group.hash(x, G1)
        a, b = self.group.random(ZR), self.group.random(ZR)
        g_a = g ** a
        g_b = g ** b

        # Global Public Parameters
        GPP = {'g': g, 'g_a': g_a, 'g_b': g_b, 'H': H}
        # Global Master Key
        GMK = {'a': a, 'b': b}

        return (GPP, GMK)

    def UserReg(self, GPP, entity='user'):
        """
        Registration of users carried out by the CA to generate their
        corresponding key pairs (i.e Public and Private Keys)

        :param GPP: Global Public Parameters (GPP)
        # :param entity: the entity executing algorithm
        # :param registered_users: Dictionary of already registered users
        :return: GSK_uid, GSK_uid_prime, GPK_uid, GPK_uid_prime
        """
        g = GPP['g']
        u_uid, u_uid_prime = self.group.random(ZR), self.group.random(ZR)
        g_u_uid = g ** u_uid
        g_u_uid_prime = g ** (1 / u_uid_prime)

        GSK_uid_prime, GPK_uid = u_uid_prime, g_u_uid
        GSK_uid, GPK_uid_prime = u_uid, g_u_uid_prime

        return (GPK_uid, GSK_uid_prime), {'GSK_uid': GSK_uid, 'GPK_uid_prime': GPK_uid_prime, 'u_uid': u_uid}

    def AAReg(self, GPP, authorityID, attributes, registered_authorities):
        """
        Registration of Attribute Authorities by the CA
        :param GPP: Global Public Parameters
        :param authorityID: Unique ID for the Authority
        :param attributes: Attributes managed by the authority
        :param registered_authorities: Dictionary of already registered authorities
        :return: Authority secret and public key pair together with the version and public keys for its individual attributes
        """
        # check if authority has been registered already
        if authorityID not in registered_authorities:
            alpha_aid = self.group.random(ZR)
            beta_aid = self.group.random(ZR)
            gamma_aid = self.group.random(ZR)
            SK_aid = {'alpha_aid': alpha_aid, 'beta_aid': beta_aid, 'gamma_aid': gamma_aid}
            PK_aid = {
                'e_alpha': pair(GPP['g'], GPP['g']) ** alpha_aid,
                'g_beta_aid': GPP['g'] ** beta_aid,
                'g_beta_aid_inv': GPP['g'] ** (1 / beta_aid)
            }
            authority_attributes = {}
            registered_authorities[authorityID] = (SK_aid, PK_aid, authority_attributes)
        else:
            SK_aid, PK_aid, authority_attributes = registered_authorities[authorityID]

        for attrib in attributes:
            if attrib in authority_attributes:
                continue
            versionKey = self.group.random(ZR)
            h = GPP['H'](attrib)
            PK_1_attrib, PK_2_attrib = h ** versionKey, h ** (versionKey * SK_aid['gamma_aid'])
            PK_attrib_aid = (PK_1_attrib, PK_2_attrib)
            authority_attributes[attrib] = {
                'VK': versionKey,
                'PK': PK_attrib_aid
            }

        return (SK_aid, PK_aid, authority_attributes)

    def KeyGen(self, GPP, authority, attribute, userObj, USK=None):
        """
        Generate the user secret keys for a specific attribute (executed by an attribute authority)
        :param GPP: Global Public Parameters
        :param authority: Attribute Authority Parameters
        :param attribute: Attribute for which secret key is being generated
        :param userObj: User
        :param USK: Generated user secret key
        :return: User Secret Key (USK)
        """
        if 't' not in userObj:
            userObj['t'] = self.group.random(ZR)
        t = userObj['t']

        ASK, APK, authAttrs = authority
        u = userObj

        if USK is None:
            USK = {}

        if 'K' not in USK or 'K_prime' not in USK or 'AK' not in USK:
            USK['K'] = (u['GPK_uid_prime'] ** ASK['alpha_aid']) * \
                       (GPP['g_a'] ** u['u_uid']) * \
                       (GPP['g_b'] ** t)
            USK['K_prime'] = GPP['g'] ** t
            USK['AK'] = {}

        AK = (GPP['g'] ** (t * ASK['beta_aid'])) * \
             authAttrs[attribute]['PK'][0] ** (ASK['beta_aid'] * (u['u_uid'] + ASK['gamma_aid']))
        USK['AK'][attribute] = AK

        return USK

    def encrypt(self, GPP, policy_str, k, authority):
        """
        Encryption algorithm that generates the ciphertext from the content (-key) and a policy. This is executed by the data owner
        :param GPP:  Global Public Parametes
        :param policy_str: Policy String
        :param k: Content key (i.e group element based on AES key)
        :param authority: authority tuple
        :return: Ciphertext
        """
        APK = {}
        authAttrs = {}
        attrg_inv = {}

        for auth in authority.keys():
            c = auth
            temp = authority[auth][1]
            APK[c] = temp

            for item in authority[auth][2].keys():
                authAttrs[item] = authority[auth][2][item]
                attrg_inv[item] = APK[auth]['g_beta_aid_inv']

        policy = self.util.createPolicy(policy_str)
        secret = self.group.random(ZR)
        shares = self.util.calculateSharesList(secret, policy)
        shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in shares])

        blinding_factor = 1

        for auth in authority.keys():
            blinding_factor *= APK[auth]['e_alpha']

        C = k * (blinding_factor ** secret)
        C_prime = GPP['g'] ** secret
        C_prime_prime = GPP['g_b'] ** secret
        C_i = {}
        C_i_prime = {}
        D_i = {}
        D_i_prime = {}

        for attr, s_share in shares.items():
            k_attr = self.util.strip_index(attr)
            r_i = self.group.random(ZR)
            attrPK = authAttrs[attr]

            C_i[attr] = (GPP['g_a'] ** s_share) * ~(attrPK['PK'][0] ** r_i)
            C_i_prime[attr] = GPP['g'] ** r_i
            D_i[attr] = attrg_inv[attr] ** r_i
            D_i_prime[attr] = attrPK['PK'][1] ** r_i

        return {'C': C, 'C_prime': C_prime, 'C_prime_prime': C_prime_prime, 'C_i': C_i,
                'C_i_prime': C_i_prime, 'D_i': D_i, 'D_i_prime': D_i_prime, 'policy': policy_str}

    def generateToken(self, GPP, CT, UASK, user_keys):
        usr_attribs = []

        for auth in UASK.keys():
            usr_attribs.extend(UASK[auth]['AK'].keys())

        policy = self.util.createPolicy(CT['policy'])
        pruned = self.util.prune(policy, usr_attribs)

        # print usr_attribs

        if not pruned:
            return False

        coeffs = self.util.getCoefficients(policy)

        dividend = 1

        for auth in UASK.keys():
            newTemp = \
                pair(CT['C_prime'], UASK[auth]['K']) * \
                ~pair(CT['C_prime_prime'], UASK[auth]['K_prime'])
            dividend *= newTemp

        n_a = 1
        an_divisor = 1
        a_new_temp = {}
        list_of_attr = {}

        for auth in UASK.keys():
            list_of_attr.update(UASK[auth]['AK'])

        for item in pruned:
            c = str(item)
            a_new_temp[c] = list_of_attr[c]

        for auth in UASK.keys():

            divisor = 1

            for attr in pruned:
                x = attr.getAttributeAndIndex()
                y = attr.getAttribute()

                # print UASK[auth]['AK']

                temp = \
                    pair(CT['C_i'][y], user_keys) * \
                    pair(CT['D_i'][y], a_new_temp[y]) * \
                    ~pair(CT['C_i_prime'][y], UASK[auth]['K_prime']) * \
                    ~pair(GPP['g'], CT['D_i_prime'][y])

                divisor *= temp ** (coeffs[x] * n_a)
            an_divisor *= divisor
        return (dividend / an_divisor, CT['C'])

    def decrypt(self, CT, TK, user_keys):
        return CT / (TK ** user_keys[1])

    # def ukeygen(self, GPP, authority, attribute, userObj):
    #     ASK, _, authAttrs = authority
    #     oldVersionKey = authAttrs[attribute]['VK']
    #     newVersionKey = oldVersionKey
    #
    #     while oldVersionKey == newVersionKey:
    #         newVersionKey = self.group.random(ZR)
    #
    #     authAttrs[attribute]['VK'] = newVersionKey
    #
    #     u = userObj['u_uid']
    #
    #     h = GPP['H'](attribute)
    #
    #     KUK = h ** (ASK['beta_aid'] * (newVersionKey - oldVersionKey) * (u + ASK['gamma_aid']))
    #
    #     CUK_1 = newVersionKey / oldVersionKey
    #     CUK_2 = (oldVersionKey - newVersionKey) / (oldVersionKey * ASK['gamma_aid'])
    #
    #     CUK = (CUK_1, CUK_2)
    #
    #     authAttrs[attribute]['PK'] = (authAttrs[attribute]['PK'][0] ** CUK_1, authAttrs[attribute]['PK'][1] ** CUK_1)
    #
    #     return {'KUK': KUK, 'CUK': CUK}
    #
    # def skupdate(self, USK, attribute, KUK):
    #     USK['AK'][attribute] = USK['AK'][attribute] * KUK
    #
    # def ctupdate(self, GPP, CT, attribute, CUK):
    #     CT['C_i'][attribute] = CT['C_i'][attribute] * (CT['D_i_prime'][attribute] ** CUK[1])
    #
    #     CT['D_i_prime'][attribute] = CT['D_i_prime'][attribute] ** CUK[0]


def wrapper(func, *args, **kwargs):
    """
    Wrapper function to enable the use of timeit
    for function which takes arguments

    :param func:    function which is to be time
    :param args:    arguments for the function
    :return:        return the wrapped function within which runs
                    the function that was given with its arguments
    """

    def wrapped():
        return func(*args, **kwargs)

    return wrapped


def basicTest():
    print("RUN basicTest")
    groupObj = PairingGroup('SS512')
    eerdac = EERDAC(groupObj)
    GPP, GMK = eerdac.CASetup()

    t1_e = 0
    t1_d = 0

    users = {}  # public user data
    authorities = {}

    authorityAttributes1 = ["ONE", "TWO", "THREE", "FOUR", "FIVE"]
    authorityAttributes2 = ["AB", "AC", "AA", "AD", "AE"]
    authorityAttributes3 = ["SIX", "SEVEN", "EIGHT", "NINE", "TEN"]
    authorityAttributes4 = ["EF", "AG", "AH", "AI", "AJ"]

    authority1 = "authority1"
    authority2 = "authority2"
    authority3 = "authority3"
    authority4 = "authority4"

    eerdac.AAReg(GPP, authority1, authorityAttributes1, authorities)
    eerdac.AAReg(GPP, authority2, authorityAttributes2, authorities)
    eerdac.AAReg(GPP, authority3, authorityAttributes3, authorities)
    eerdac.AAReg(GPP, authority4, authorityAttributes4, authorities)

    alice = {'id': 'alice', 'authoritySecretKeys': {}, 'authoritySecretKeys1': {}, 'authoritySecretKeys2': {}, 'authoritySecretKeys3': {}, 'authoritySecretKeys4': {}, 'keys': None}
    alice['keys'], users[alice['id']] = eerdac.UserReg(GPP)

    for attr in authorityAttributes1:
        eerdac.KeyGen(GPP, authorities[authority1], attr, users[alice['id']], alice['authoritySecretKeys1'])

    for attr in authorityAttributes2:
        eerdac.KeyGen(GPP, authorities[authority2], attr, users[alice['id']], alice['authoritySecretKeys2'])

    for attr in authorityAttributes3:
        eerdac.KeyGen(GPP, authorities[authority3], attr, users[alice['id']], alice['authoritySecretKeys3'])

    for attr in authorityAttributes4:
        eerdac.KeyGen(GPP, authorities[authority4], attr, users[alice['id']], alice['authoritySecretKeys4'])

    alice['authoritySecretKeys'][authority1] = alice['authoritySecretKeys1']
    alice['authoritySecretKeys'][authority2] = alice['authoritySecretKeys2']
    alice['authoritySecretKeys'][authority3] = alice['authoritySecretKeys3']
    alice['authoritySecretKeys'][authority4] = alice['authoritySecretKeys4']

    k = groupObj.random(GT)

    # showing usage of serialize and deserialize for converting group elements
    print(k)
    q = groupObj.serialize(k)
    print(q)
    y = str(q, 'utf-8')
    print(y)
    obj = groupObj.deserialize(q)
    print(obj)

    policy_str = '((THREE and TWO and SEVEN or EIGHT and FIVE and ONE and NINE and TEN) and \
                (AB and AC and AA and AD and AE and EF and AG and AH and AI and AJ))'

    # for i in range(1):
    #    start = clock()
    #    CT = eerdac.encrypt(GPP, policy_str, k, authorities)
    #    t1_e += clock() - start

    start = clock()
    CT = eerdac.encrypt(GPP, policy_str, k, authorities)
    t1_e += clock() - start

    print("the encryption time is ", t1_e)

    TK, C = eerdac.generateToken(GPP, CT, alice['authoritySecretKeys'], alice['keys'][0])

    start = clock()
    PT = eerdac.decrypt(C, TK, alice['keys'])
    t1_d += clock() - start

    print("the decryption time is ", t1_d)

    # print "CT", CT['C']
    # print "k", k
    # print "PT", PT

    assert k == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')


# def revokedTest():
#     print("RUN revokedTest")
#     groupObj = PairingGroup('SS512')
#     eerdac = EERDAC(groupObj)
#     GPP, GMK = eerdac.CASetup()
#
#     users = {}  # public user data
#     authorities = {}
#
#     authorityAttributes1 = ["ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX",
#                             "SEVEN", "EIGHT", "NINE", "TEN"]
#     authorityAttributes2 = ["AB", "AC", "AA", "AD", "AE", "EF", "AG", "AH", "AI", "AJ"]
#
#     authority1 = "authority1"
#     authority2 = "authority2"
#
#     eerdac.AAReg(GPP, authority1, authorityAttributes1, authorities)
#     eerdac.AAReg(GPP, authority2, authorityAttributes2, authorities)
#
#     alice = {'id': 'alice', 'authoritySecretKeys': {}, 'authoritySecretKeys1': {},
#              'authoritySecretKeys2': {}, 'keys': None}
#     bob = {'id': 'bob', 'authoritySecretKeys': {}, 'authoritySecretKeys1': {},
#            'authoritySecretKeys2': {}, 'keys': None}
#
#     alice['keys'], users[alice['id']] = eerdac.UserReg(GPP)
#     bob['keys'], users[bob['id']] = eerdac.UserReg(GPP)
#
#     for attr in authorityAttributes1:
#         eerdac.KeyGen(GPP, authorities[authority1], attr, users[alice['id']], alice['authoritySecretKeys1'])
#         eerdac.KeyGen(GPP, authorities[authority1], attr, users[bob['id']], bob['authoritySecretKeys1'])
#
#     for attr in authorityAttributes2:
#         eerdac.KeyGen(GPP, authorities[authority2], attr, users[alice['id']], alice['authoritySecretKeys2'])
#         eerdac.KeyGen(GPP, authorities[authority2], attr, users[bob['id']], bob['authoritySecretKeys2'])
#
#     alice['authoritySecretKeys'][authority1] = alice['authoritySecretKeys1']
#     alice['authoritySecretKeys'][authority2] = alice['authoritySecretKeys2']
#
#     bob['authoritySecretKeys'][authority1] = bob['authoritySecretKeys1']
#     bob['authoritySecretKeys'][authority2] = bob['authoritySecretKeys2']
#
#     k = groupObj.random(GT)
#
#     policy_str = '((THREE and TWO and SEVEN or EIGHT and FIVE and ONE and NINE and TEN) and \
#                  (AB and AC and AA and AD and AE and EF and AG and AH and AI and AJ))'
#
#     CT = eerdac.encrypt(GPP, policy_str, k, authorities)

    # PT1a = eerdac.decrypt(GPP, CT, alice['authoritySecretKeys'], alice['keys'])
    # PT1b = eerdac.decrypt(GPP, CT, bob['authoritySecretKeys'], bob['keys'])

    # assert k == PT1a, 'FAILED DECRYPTION (1a)!'
    # assert k == PT1b, 'FAILED DECRYPTION (1b)!'
    # print('SUCCESSFUL DECRYPTION 1')

    # # revoke bob on "ONE"
    # attribute = "ONE"
    # UK = eerdac.ukeygen(GPP, authorities[authority1], attribute, users[alice['id']])
    # eerdac.skupdate(alice['authoritySecretKeys'], attribute, UK['KUK'])
    # eerdac.ctupdate(GPP, CT, attribute, UK['CUK'])
    #
    # PT2a = eerdac.decrypt(GPP, CT, alice['authoritySecretKeys'], alice['keys'])
    # PT2b = eerdac.decrypt(GPP, CT, bob['authoritySecretKeys'], bob['keys'])
    #
    #
    # # print "k", k
    # # print "PT2a", PT2a
    # # print "PT2b", PT2b
    #
    # assert k == PT2a, 'FAILED DECRYPTION (2a)!'
    # assert k != PT2b, 'SUCCESSFUL DECRYPTION (2b)!'
    # print('SUCCESSFUL DECRYPTION 2')


if __name__ == '__main__':
    basicTest()
    # revokedTest()
