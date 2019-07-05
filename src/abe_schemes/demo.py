from src.abe_schemes.other_abe_schemes.kan_yang_eerdac_scheme_test import basicTest as bt1
from src.abe_schemes.abenc_omacpabe_test import basicTest as bt2
import numpy as np

# basicTest(n_trials, n_att_authorities, n_attributes)
n_trials = 100
n_att_authorities = [5, 10, 15, 20, 25]

enc_time_att_authorities = []
enc_time_att_authorities_kan = []
dec_time_att_authorities = []
dec_time_att_authorities_kan = []

for n_attauth in n_att_authorities:
    enc_time_kan, dec_time_kan = bt1(n_trials, n_attauth, n_attauth * 10)
    enc_time, dec_time = bt2(n_trials, n_attauth, n_attauth * 10)
    enc_time_att_authorities.append(enc_time)
    dec_time_att_authorities.append(dec_time)
    enc_time_att_authorities_kan.append(enc_time_kan)
    dec_time_att_authorities_kan.append(dec_time_kan)

dec_times = np.array([dec_time_att_authorities, dec_time_att_authorities_kan]).transpose()
enc_times = np.array([enc_time_att_authorities, enc_time_att_authorities_kan]).transpose()

np.save("decryption_time_data", dec_times)
np.save("encryption_time_data", enc_times)