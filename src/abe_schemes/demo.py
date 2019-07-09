# from src.abe_schemes.other_abe_schemes.kan_yang_eerdac_scheme_test import basicTest as bt1
# from src.abe_schemes.abenc_omacpabe_test import basicTest as bt2
import src.abe_schemes.abenc_omacpabe_test as omacpabe
import src.abe_schemes.other_abe_schemes.kan_yang_eerdac_scheme_test as kan_yang
import numpy as np

# basicTest(n_trials, n_att_authorities, n_attributes)
n_trials = 100
n_att_authorities = [5, 10, 15, 20, 25]

enc_time_att_authorities = []
enc_time_att_authorities_kan = []
dec_time_att_authorities = []
dec_time_att_authorities_kan = []
rev_time_att_authorities = []
rev_time_att_authorities_kan = []

for n_attauth in n_att_authorities:
    print("Running experiment for encryption, decryption, and revocation for my scheme and kan yang for", n_attauth, "authorities and", n_attauth * 10, "attributes.")
    enc_time_kan, dec_time_kan = kan_yang.basicTest(n_trials, n_attauth, n_attauth * 10)
    enc_time, dec_time = omacpabe.basicTest(n_trials, n_attauth, n_attauth * 10)
    rev_time = omacpabe.revokedTest(n_trials, n_attauth, n_attauth * 10)
    rev_time_kan = kan_yang.revokedTest(n_trials, n_attauth, n_attauth * 10)

    enc_time_att_authorities.append(enc_time)
    dec_time_att_authorities.append(dec_time)
    rev_time_att_authorities.append(rev_time)
    enc_time_att_authorities_kan.append(enc_time_kan)
    dec_time_att_authorities_kan.append(dec_time_kan)
    rev_time_att_authorities_kan.append(rev_time)


dec_times = np.array([dec_time_att_authorities, dec_time_att_authorities_kan]).transpose()
enc_times = np.array([enc_time_att_authorities, enc_time_att_authorities_kan]).transpose()
rev_times = np.array([rev_time_att_authorities, rev_time_att_authorities_kan]).transpose()

np.save("decryption_time_data", dec_times)
np.save("encryption_time_data", enc_times)
np.save("revocation_time_data", rev_times)
