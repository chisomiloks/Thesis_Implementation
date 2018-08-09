"""
| Attribute Based Encryption (ABE) scheme for MASC Thesis (Design of a Secure Privacy Preserving Cloud Based Sharing Platform for Electronic Health Data)
| Scheme name: Outsourced Multi-Authority Ciphertext Policy Attribute Based Encryption (OMACPABE)

| Adapted from:

    | Expressive, Efficient, and Revocable Data Access Control for Multi-Authority Cloud Storage
    | Implementation by artjomb in charm-crypto library available at https://github.com/JHUISI/charm/blob/dev/charm/schemes/abenc/abenc_maabe_yj14.py
    | Paper available at: http://ieeexplore.ieee.org/xpls/abs_all.jsp?arnumber=6620875&tag=1

* type: Multi-Authority Ciphertext Policy Attribute Based Encryption
* setting: Pairing

:Author: Munachiso Ilokah
:Date: 07-2018
"""

from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR
from charm.toolbox.pairinggroup import G1
from charm.toolbox.pairinggroup import GT
from charm.toolbox.pairinggroup import pair
from charm.toolbox.secretutil import SecretUtil


class OMACPABE(object):
    def __init__(self, group_object):
        # initialize class object with secret sharing utility
        # and appropriate group object
        self.util = SecretUtil(group_object, verbose=False)
        self.group = group_object

    # certificate authority (CA) setup function
    def ca_setup(self):
        """
        Global setup function run by the CA to generate the
        Global Master Key (GMK) and the Global Public Parameters (GPP)

        :return: GMK, GPP
        """
        # initialize bilinear group G of prime p with generator g
        g = self.group.random(G1)
        # initialize hash function that maps to an element of G
        H = lambda x: self.group.hash(x, G1)
        # select random elements from Z_p
        a = self.group.random(ZR)
        b = self.group.random(ZR)

        g_a = g ** a
        g_b = g ** b

        # Global Public Parameters (GPP) = g, g_a, g_b, H
        GPP = {'g': g, 'g_a': g_a, 'g_b': g_b, 'H': H}

        # Global Master Key (GMK) = a, b
        GMK = {'a': a, 'b': b}

        return (GPP, GMK)

    def user_reg(self, GPP, entity='user'):
        """
        User registration by Certificate Authority (CA) to generate corresponding
        key pairs (i.e. Public and Private keys)

        :param GPP: Global Public Parameters (GPP)
        # :param entity: the entity executing algorithm
        # :param registered_users: Dictionary of already registered users
        :return: User Global Secret and Public Keys (GSK_uid, GSK_uid_prime, GPK_uid, GPK_uid_prime)
        """
        # group generator from GPP
        g = GPP['g']
        # random numbers as user global secret keys
        u_uid = self.group.random(ZR)
        u_uid_prime = self.group.random(ZR)
        # user global public keys
        g_u_uid = g ** u_uid
        g_u_uid_prime = g ** (1 / u_uid_prime)

        # secret public key pair sent to user
        GSK_uid_prime = u_uid_prime
        GPK_uid = g_u_uid

        # secret public key pair to be sent to  registered Attribute Authorities (AAs)
        GSK_uid = u_uid
        GPK_uid_prime = g_u_uid_prime

        return (GPK_uid, GSK_uid_prime), {'GSK_uid': GSK_uid, 'GPK_uid_prime': GPK_uid_prime, 'u_uid': u_uid}

    def aa_reg(self, GPP, authority_id, attributes, registered_authorities):
        """
        Registration of Attribute Authorities (AA) by the Certificate Authority (CA)
        :param GPP: Global Public Parameters (GPP)
        :param authority_id: Unique ID for Attribute Authority
        :param attributes: Attributes managed by the authority
        :param registered_authorities: Dictionary of already registered authorities
        :return: Attribute Authority Secret and Public Key pairs with Version and Public keys for the attributes
        """
        # check if authority has already been registered
        if authority_id not in registered_authorities:
            # generate random values to serves as attribute authority secret key
            alpha_aid = self.group.random(ZR)
            beta_aid = self.group.random(ZR)
            gamma_aid = self.group.random(ZR)
            # attribute authority secret key values
            SK_aid = {'alpha_aid': alpha_aid, 'beta_aid': beta_aid, 'gamma_aid': gamma_aid}
            # attribute authority public key values
            PK_aid = {
                'e_alpha': pair(GPP['g'], GPP['g']) ** alpha_aid,
                'g_beta_aid': GPP['g'] ** beta_aid,
                'g_beta_aid_inv': GPP['g'] ** (1 / beta_aid)
            }
            authority_attributes = {}
            registered_authorities[authority_id] = (SK_aid, PK_aid, authority_attributes)
        else:
            SK_aid, PK_aid, authority_attributes = registered_authorities[authority_id]

        # generate version and public keys for attributes
        for attribute in attributes:
            # check if attributes already exist with public and version keys
            # if they do, skip generation process
            if attribute in authority_attributes:
                continue
            # generate random element as version key
            version_key = self.group.random(ZR)
            h = GPP['H'](attribute)
            PK_1_attribute = h ** version_key
            PK_2_attribute = h ** (version_key * SK_aid['gamma_aid'])
            PK_attribute_aid = (PK_1_attribute, PK_2_attribute)
            authority_attributes[attribute] = {
                'VK': version_key,
                'PK': PK_attribute_aid
            }
        return (SK_aid, PK_aid, authority_attributes)

    def key_gen(self, GPP, authority, attribute, userObj, USK=None):
        """
        
        :param GPP:
        :param authority:
        :param attribute:
        :param userObj:
        :param USK:
        :return:
        """
