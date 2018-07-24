"""
| Attribute Based Encryption (ABE) scheme for MASC Thesis (Design of a Secure Privacy Preserving Cloud Based Sharing Platform for Electronic Health Data)
| Scheme name: Outsourced Multi-Authority Ciphertext Policy Attribute Based Encryption (OMACPABE)

| Adapted from:

    | Expressive, Efficient, and Revocable Data Access Control for Multi-Authority Cloud Storage
    | Implementation by artjomb in charm-crypto library available at https://github.com/JHUISI/charm/blob/dev/charm/schemes/abenc/abenc_maabe_yj14.py
    | Paper available at: http://ieeexplore.ieee.org/xpls/abs_all.jsp?arnumber=6620875&tag=1

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
        # initialize class object with secret sharing utility and appropriate group object
        self.util = SecretUtil(group_object, verbose=False)
        self.group = group_object

    # certificate authority (CA) setup function
    def ca_setup(self):
        """
        Global setup function run by the CA to generate the Global Master Key (GMK)
        and the Global Public Parameters (GPP)

        :return: GMK, GPP
        """

        pass