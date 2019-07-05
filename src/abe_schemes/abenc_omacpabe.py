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

# from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.pairinggroup import ZR
from charm.toolbox.pairinggroup import G1
# from charm.toolbox.pairinggroup import GT
from charm.toolbox.pairinggroup import pair
from charm.toolbox.secretutil import SecretUtil


class OMACPABE(object):
    def __init__(self, group_object):
        # initialize class object with secret sharing utility
        # and appropriate group object
        self.util = SecretUtil(group_object, verbose=False)
        self.group = group_object

    # certificate authority (CA) setup function
    def abenc_casetup(self):
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
        GPP = {'g': g,
               'g_a': g_a,
               'g_b': g_b,
               'H': H,
               }

        # Global Master Key (GMK) = a, b
        GMK = {'a': a,
               'b': b,
               }

        return (GPP, GMK)

    def abenc_userreg(self, GPP, entity='user'):
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

        return (GPK_uid, GSK_uid_prime), {'GSK_uid': GSK_uid,
                                          'GPK_uid_prime': GPK_uid_prime,
                                          'u_uid': u_uid,
                                          }

    def abenc_aareg(self, GPP, authority_id, attributes, registered_authorities):
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
            SK_aid = {'alpha_aid': alpha_aid,
                      'beta_aid': beta_aid,
                      'gamma_aid': gamma_aid
                      }
            # attribute authority public key values
            PK_aid = {'e_alpha': pair(GPP['g'], GPP['g']) ** alpha_aid,
                      'g_beta_aid': GPP['g'] ** beta_aid,
                      'g_beta_aid_inv': GPP['g'] ** (1 / beta_aid),
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
            PK_attribute_aid = [PK_1_attribute, PK_2_attribute]
            authority_attributes[attribute] = {'VK': version_key,
                                               'PK': PK_attribute_aid,
                                               }
        return (SK_aid, PK_aid, authority_attributes)

    def abenc_keygen(self, GPP, authority, attribute, user_object, USK=None):
        """
        Generate attribute authority related secret keys for users (executed by the corresponding attribute authority)
        :param GPP: Global Public Parameters
        :param authority: Attribute Authority Parameters
        :param attribute: Attribute for which secret key is being generated
        :param user_object: User
        :param USK: Generated attribute authority related user secret key
        :return: User Secret Key (USK)
        """
        # generate random integer to tie attribute secret key to user
        if 't' not in user_object:
            user_object['t'] = self.group.random(ZR)
        t = user_object['t']

        # assign corresponding attribute authority parameters
        ASK, APK, authority_attrs = authority

        u = user_object

        # create USK data set if none exists already
        if USK is None:
            USK = {}

        if 'K_uid_aid' not in USK or 'K_uid_aid_prime' not in USK or 'AK_uid_aid' not in USK:
            USK['K_uid_aid'] = (u['GPK_uid_prime'] ** ASK['alpha_aid']) * (GPP['g_a'] ** u['u_uid']) * (GPP['g_b'] ** t)
            USK['K_uid_aid_prime'] = GPP['g'] ** t
            USK['AK_uid_aid'] = {}

        # generate attribute specific secret key parameters
        AK_uid_aid = (GPP['g'] ** (t * ASK['beta_aid'])) * authority_attrs[attribute]['PK'][0] \
            ** (ASK['beta_aid'] * (u['u_uid'] + ASK['gamma_aid']))
        USK['AK_uid_aid'][attribute] = AK_uid_aid

        return USK

    def abenc_encrypt(self, GPP, policy_string, k, authority):
        """
        Encryption algorithm which encrypts the message given, based on the policy
        :param GPP: Global Public Parameters
        :param policy_string: Policy
        :param k: Content Key (i.e group element based on AES key)
        :param authority: Attribute Authority Parameters
        :return: Ciphertext
        """
        APK = {}
        authority_attributes = {}
        authority_g_beta_inv = {}

        # extract the APK for the different authorities
        for authority_temp in authority.keys():
            APK[authority_temp] = authority[authority_temp][1]

            # extract the PK values of the attributes of the attribute authorities
            # extract the corresponding g_beta_inverse values for the attribute authorities
            for item in authority[authority_temp][2].keys():
                authority_attributes[item] = authority[authority_temp][2][item]
                authority_g_beta_inv[item] = APK[authority_temp]['g_beta_aid_inv']

        # extract policy and use policy elements to slit the secret
        # into their corresponding shares for encryption
        policy = self.util.createPolicy(policy_string)

        # generate secret through random element
        secret = self.group.random(ZR)

        # split secret into shares (this returns a list)
        shares = self.util.calculateSharesList(secret, policy)

        # process shares list to create a dict with attribute as key
        # and corresponding shares as value
        shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in shares])

        # initialize blinding factor to hide key
        blinding_factor = 1

        for authority_temp in authority.keys():
            blinding_factor *= APK[authority_temp]['e_alpha']

        # create C elements of encrypted file
        C = k * (blinding_factor ** secret)
        C_prime = GPP['g'] ** secret
        C_prime_prime = GPP['g_b'] ** secret

        # create structure (dict) to hold the C_i and D_i elements of the encrypted file
        # these are the components related to the attributes
        C_i = {}
        C_i_prime = {}
        D_i = {}
        D_i_prime = {}

        # generate C_i and D_i elements
        for attribute, secret_share in shares.items():
            # attribute_temp = self.util.strip_index(attribute)
            # generate random r_i element
            k_attr = self.util.strip_index(attribute)
            r_i = self.group.random(ZR)
            attribute_PK = authority_attributes[attribute]

            C_i[attribute] = (GPP['g_a'] ** secret_share) * ~(attribute_PK['PK'][0] ** r_i)
            C_i_prime[attribute] = GPP['g'] ** r_i
            D_i[attribute] = authority_g_beta_inv[attribute] ** r_i
            D_i_prime[attribute] = attribute_PK['PK'][1] ** r_i

        return {'C': C,
                'C_prime': C_prime,
                'C_prime_prime': C_prime_prime,
                'C_i': C_i,
                'C_i_prime': C_i_prime,
                'D_i': D_i,
                'D_i_prime': D_i_prime,
                'policy': policy_string,
                }

    def abenc_generatetoken(self, GPP, CT, UASK, user_keys):
        """
        Partial decryption of the ciphertext

        :param GPP: Global Public Parameters
        :param CT: Ciphertext elements
        :param UASK: Secret Keys for user gotten from Attribute Authorities
        :param user_keys: User global keys
        :return: Partially decrypted ciphertext
        """

        # list to hold corresponding attributes possessed by the user
        user_attributes = []

        for authority in UASK.keys():
            user_attributes.extend(UASK[authority]['AK_uid_aid'].keys())

        # access ciphertext policy
        encryption_policy = self.util.createPolicy(CT['policy'])

        # generate list of minimum policy elements needed for encryption
        # returns False if user fails policy assessment
        minimal_policy_list = self.util.prune(encryption_policy, user_attributes)

        # print(minimal_policy_list)

        # this is an error handling implementation that should be fixed later
        if not minimal_policy_list:
            return False

        # get attribute coefficients to be able to access their share of the secret
        coefficients = self.util.getCoefficients(encryption_policy)
        # initialize the dividend value for the token generation computation
        dividend = 1

        for authority in UASK.keys():
            dividend *= (pair(CT['C_prime'], UASK[authority]['K_uid_aid']) * ~pair(CT['C_prime_prime'], UASK[authority]['K_uid_aid_prime']))

        # attribute authority index?
        n_a = 1

        # initialize divisor value for token generation computation
        divisor = 1

        # create dict to hold attributes for the authorities and their corresponding secret keys
        attribute_keys = {}

        # create dict to hold attributes contained in the pruned list and their corresponding secret keys
        pruned_attribute_keys = {}

        # populate attribute with with corresponding key value pairs
        for authority in UASK.keys():
            attribute_keys.update(UASK[authority]['AK_uid_aid'])

        # populate pruned attribute with corresponding key value pairs
        # from attribute list
        for attribute in minimal_policy_list:
            pruned_attribute_keys[str(attribute)] = attribute_keys[str(attribute)]

        # compute divisor
        for authority in UASK.keys():

            temp_divisor = 1

            for attribute in minimal_policy_list:
                x = attribute.getAttributeAndIndex()
                y = attribute.getAttribute()

                temp_divisor *= ((
                        pair(CT['C_i'][y], user_keys) *
                        pair(CT['D_i'][y], pruned_attribute_keys[y]) *
                        ~pair(CT['C_i_prime'][y], UASK[authority]['K_uid_aid_prime']) *
                        ~pair(GPP['g'], CT['D_i_prime'][y])
                ) ** (coefficients[x] * n_a))

            divisor *= temp_divisor

        Token = dividend / divisor

        return (Token, CT['C'])

    def abenc_decrypt(self, CT, TK, user_keys):
        """
        Final decryption algorithm to reveal original message. To be run by the user

        :param CT: Original component of ciphertext that contains the encrypted message
        :param TK: Token generated during partial decryption of ciphertext
        :param user_keys: User global keys
        :return: Decrypted message
        """
        message = CT / (TK ** user_keys[1])
        return message

    def abenc_ukeygen(self, GPP, authority, attribute, user_object):
        """
        Generate update keyss used in the revocation process for users and the cloud service provider.

        This will be run by the Attribute Authority.

        :param GPP: Global Public Parameters
        :param authority: Attribute Authority
        :param attribute: Attribute to be updated
        :param user_object: User
        :return: User attribute update keys and ciphertext update keys
        """

        ASK, _, authAttrs = authority
        # attribute version key to be updated
        old_version_key = authAttrs[attribute]['VK']
        # set new version key to old value
        new_version_key = old_version_key
        # ensure that new version key is different from original version key
        while old_version_key == new_version_key:
            new_version_key = self.group.random()

        # update version key of the attribute in the dictionary
        authAttrs[attribute]['VK'] = new_version_key

        u_uid = user_object['u_uid']

        # create update key for users i.e to update the attribute involved
        KUK = GPP['H'](attribute) ** (ASK['beta_aid'] * (new_version_key - old_version_key) * (u_uid + ASK['gamma_aid']))

        # create update key for ciphertexts encrypted with attribute involved
        CUK = (new_version_key/old_version_key, (old_version_key - new_version_key)/(old_version_key * ASK['gamma_aid']))

        # update the public parameters of the attribute involved
        authAttrs[attribute]['PK'][0] = authAttrs[attribute]['PK'][0] ** CUK[0]
        authAttrs[attribute]['PK'][1] = authAttrs[attribute]['PK'][1] ** CUK[0]

        return {'KUK': KUK,
                'CUK': CUK,
                }

    def abenc_skupdate(self, USK, attribute, KUK):
        """
        Updates the attribute secret key for the specific attribute.

        This is executed by a non-revoked user.

        :param USK: User secret key
        :param attribute: Attribute whose secret key is to be updated
        :param KUK: Update key for users
        :return: NA
        """

        # update the secret key component of the affected attribute
        # print(USK)
        USK['AK_uid_aid'][attribute] = USK['AK_uid_aid'][attribute] * KUK

    def abenc_ctupdate(self, GPP, CT, attribute, CUK):
        """
        Updates the ciphertexts that contain the specific attribute (revoked attribute).

        This is executed by the cloud service provider.

        :param GPP: Global Public Parameters
        :param CT: The affected ciphertext
        :param attribute: Attribute that is affected by the revocation process
        :param CUK: The Ciphertext Update Key
        :return: NA
        """
        # update the corresponding components of the ciphertext that are related to the affected attribute
        CT['C_i'][attribute] = CT['C_i'][attribute] * (CT['D_i_prime'][attribute] ** CUK[1])
        CT['D_i_prime'][attribute] = CT['D_i_prime'][attribute] ** CUK[0]
