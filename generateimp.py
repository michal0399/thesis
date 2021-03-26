import pefile
import os
import argparse
import pyimpfuzzy
import pickle
import shutil
import itertools
import collections

##############################################################
#     usage: python2 generateimp.py -p <path-to-folder>      #
##############################################################

ap = argparse.ArgumentParser()
ap.add_argument('-p', '--path', required=True, help='Path to malware samples')
args = ap.parse_args()
path = args.path


def getimphash(path):

    """function to recursively parse a file directory
       and get the imphash and fuzzy imphash of a PE file.
       The hashes are stored in a dictionary, with the filepath as key"""
    hashes = {}
    for root, subdirs, files in os.walk(path):
        for f in files:
            # surround code with try/ except to skip non-PE or non-readable files
            try:
                filepath = os.path.join(root, f) # full file path
                pe = pefile.PE(filepath) # pe file object
                imphash = pe.get_imphash() # get the impash
                impfuzzy = pyimpfuzzy.get_impfuzzy(filepath) # get the fuzzy hash
                hashes[f] = [imphash, impfuzzy] # dictionary -> filepath: [imphash, fuzzyhash]
                #shutil.move(filepath, 'dumpfolder/'+ f) # move the file to the dump folder
            except:
                continue
    print hashes
    pickle.dump(hashes, open('hashes.pkl', 'wb')) # save dictionary to disk for clustering by similarity


# run the code and save to file
getimphash(path)

# loads the dictionary
dict = pickle.load(open('hashes.pkl', 'rb'))

