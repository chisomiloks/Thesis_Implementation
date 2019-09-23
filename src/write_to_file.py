"""
Module to write info to a file to be used to store the data compiled from the
individual trials into the appropriate file for storage and future analysis.

To contain function to write file
"""

import os.path
import numpy as np

data_folder = '/home/munachisoilokah/Google Drive/UOIT/MASc Thesis/Framework Source Code/results/'


def write_to_text_file(info, file_name="Sample Data File"):
    """
    Write content of info into the a text file

    :param info: Details to be written to file (List)
    :param file_name: File name (use default is no name is provided).
    """

    # destination = os.path.join(os.path.expanduser('~'), 'Google Drive', 'UOIT', 'MASc Thesis', 'Framework Source Code', 'results', file_name+'.txt')
    destination = os.path.join(data_folder, 'time_data', file_name+'.txt')

    if not isinstance(info, list):
        print("Function only works with Lists.")
        return False

    with open(destination, 'a') as fopen:
        for item in info:
            fopen.write(str(item) + '\n')


def write_to_npy_file(info, file_name="Sample Data File"):
    """
    Write content of info into a numpy file
    :param info:
    :param file_name:
    :return:
    """

    destination = os.path.join(data_folder, 'numpy', file_name)
    np.save(destination, info)
