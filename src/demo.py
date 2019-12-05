import src.abenc_omacpabe_test as omacpabe
import src.kan_yang_eerdac_scheme_test as kan_yang
import numpy as np
import datetime as dt
import src.write_to_file as wt


start_time = dt.datetime.now()
print("Start time is", start_time)

# basic_test(number_of_trials, number_of_attribute_authorities, number_of_attributes)
# for framework experiment
number_of_trials = 500
number_of_attribute_authorities = [5, 10, 15, 20, 25]

# for testing code
# number_of_trials = 5
# number_of_attribute_authorities = [2, 4, 6, 8, 10]

# create dictionaries to hold time data for number of attribute authorities
# key: value -- Number of authorities: time to run algorithm
encryption_time_data_my_scheme = {}
encryption_time_data_kan_yang_scheme = {}
decryption_time_data_my_scheme = {}
decryption_time_data_kan_yang_scheme = {}
revocation_time_data_my_scheme = {}
revocation_time_data_kan_yang_scheme = {}

print("Running experiment for", number_of_trials, "trials")

for number_of_authorities in number_of_attribute_authorities:
    print("Experiment for encryption, decryption, and revocation for my scheme and kan yang for", number_of_authorities, "authorities and", number_of_authorities * 10, "attributes.")

    # basic test i.e encryption and decryption
    encryption_time_my_scheme_temp, decryption_time_my_scheme_temp = omacpabe.basic_test(number_of_trials, number_of_authorities, number_of_authorities * 10)
    encryption_time_kan_yang_temp, decryption_time_kan_yang_temp = kan_yang.basicTest(number_of_trials, number_of_authorities, number_of_authorities * 10)
    # revocation tests
    revocation_time_my_scheme_temp = omacpabe.revocation_test(number_of_trials, number_of_authorities, number_of_authorities * 10, number_of_authorities * 5)
    revocation_time_kan_yang_temp = kan_yang.revokedTest(number_of_trials, number_of_authorities, number_of_authorities * 10, number_of_authorities * 5)

    # add average encryption, decryption, and revocation times for my scheme to the appropriate dict using the number of authorities as the key
    encryption_time_data_my_scheme[number_of_authorities] = sum(encryption_time_my_scheme_temp)/len(encryption_time_my_scheme_temp)
    decryption_time_data_my_scheme[number_of_authorities] = sum(decryption_time_my_scheme_temp)/len(decryption_time_my_scheme_temp)
    revocation_time_data_my_scheme[number_of_authorities] = sum(revocation_time_my_scheme_temp) / len(revocation_time_my_scheme_temp)

    # add average encryption, decryption, and revocation times for kan yang scheme to the appropriate dict using the number of authorities as the key
    encryption_time_data_kan_yang_scheme[number_of_authorities] = sum(encryption_time_kan_yang_temp) / len(encryption_time_kan_yang_temp)
    decryption_time_data_kan_yang_scheme[number_of_authorities] = sum(decryption_time_kan_yang_temp) / len(decryption_time_kan_yang_temp)
    revocation_time_data_kan_yang_scheme[number_of_authorities] = sum(revocation_time_kan_yang_temp) / len(revocation_time_kan_yang_temp)

    # writing individual run time for the trials to the appropriate file
    data_time_stamp = dt.datetime.now().strftime("%d-%m-%y_%H:%M:%S")

    # my scheme data
    wt.write_to_text_file(encryption_time_my_scheme_temp, "My Scheme - Enc_Times_" + str(number_of_authorities) + "_Authorities_" + str(number_of_trials) + "_trials_" + data_time_stamp)
    wt.write_to_text_file(decryption_time_my_scheme_temp, "My Scheme - Dec_Times_" + str(number_of_authorities) + "_Authorities_" + str(number_of_trials) + "_trials_" + data_time_stamp)
    wt.write_to_text_file(revocation_time_my_scheme_temp, "My Scheme - Rev_Times_" + str(number_of_authorities) + "_Authorities_" + str(number_of_trials) + "_trials_" + data_time_stamp)

    # kan yang scheme data
    wt.write_to_text_file(encryption_time_kan_yang_temp, "Kan Yang Scheme - Enc_Times_" + str(number_of_authorities) + "_Authorities_" + str(number_of_trials) + "_trials_" + data_time_stamp)
    wt.write_to_text_file(decryption_time_kan_yang_temp, "Kan Yang Scheme - Dec_Times_" + str(number_of_authorities) + "_Authorities_" + str(number_of_trials) + "_trials_" + data_time_stamp)
    wt.write_to_text_file(revocation_time_kan_yang_temp, "Kan Yang Scheme - Rev_Times_" + str(number_of_authorities) + "_Authorities_" + str(number_of_trials) + "_trials_" + data_time_stamp)

end_time = dt.datetime.now()
print("End time is", end_time)

duration = end_time - start_time
print("Total duration is", duration)

# extract list of encryption, decryption, and revocation times for my scheme from the dict for plotting
my_scheme_encryption_times = list(encryption_time_data_my_scheme.values())
my_scheme_decryption_times = list(decryption_time_data_my_scheme.values())
my_scheme_revocation_times = list(revocation_time_data_my_scheme.values())

# extract list of encryption, decryption, and revocation times for kan yang scheme from the dict for plotting
kan_yang_scheme_encryption_times = list(encryption_time_data_kan_yang_scheme.values())
kan_yang_scheme_decryption_times = list(decryption_time_data_kan_yang_scheme.values())
kan_yang_scheme_revocation_times = list(revocation_time_data_kan_yang_scheme.values())

# combine the corresponding time data for the two different schemes in a numpy array for use in the bar plots
encryption_time_data = np.array([my_scheme_encryption_times, kan_yang_scheme_encryption_times]).transpose()
decryption_time_data = np.array([my_scheme_decryption_times, kan_yang_scheme_decryption_times]).transpose()
revocation_time_data = np.array([my_scheme_revocation_times, my_scheme_revocation_times]).transpose()

data_time_stamp = dt.datetime.now().strftime("%d-%m-%y_%H:%M:%S")
# write the corresponding data to a npy file for plotting
wt.write_to_npy_file(encryption_time_data, "encryption_time_data_" + str(number_of_trials) + "_trials_" + data_time_stamp)
wt.write_to_npy_file(decryption_time_data, "decryption_time_data_" + str(number_of_trials) + "_trials_" + data_time_stamp)
wt.write_to_npy_file(revocation_time_data, "revocation_time_data_" + str(number_of_trials) + "_trials_" + data_time_stamp)
