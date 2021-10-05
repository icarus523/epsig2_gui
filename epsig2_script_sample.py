import os
import csv
import subprocess

from epsig2_gui import epsig2, Seed

def main():
    # Set Input Options
    hash_type = "HMAC-SHA1"                         # valid type: "HMAC-SHA1", "HMAC-SHA256"
    
    # set complete path, e.g.: """G:\OLGR-TECHSERV\BINIMAGE\AGT\GDQL163A_1I6A_003.bnk"""
    bnk_or_bin_file = "bnkfiles/5D81F_W4QLQ05M.BNK"         
    #bnk_or_bin_file = 'G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK'
    bad_contents_bnk_file = 'G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1985GCXX_393_002.BNK'
    #bnk_or_bin_file = 'G:/OLGR-TECHSERV/BINIMAGE/IGT/000A_B1010_0_004.bnk'
    seed = "0000000000000000000000000000000000000000000000000000000000000000"   # set appropriate seed, script will adjust size of seed

# Set Output Options
    options_d = dict() 
    options_d['cache_file_f'] = False               # False / True - uses cache_file - just use False here. 
    options_d['uppercase'] = False                  # False / True - output in uppercase characters
    options_d['eightchar'] = False                  # False / True - output hash with eight char spaces
    options_d['reverse'] = False                    # False / True - reverse byte output
    options_d['usr_cache_file'] = False             # False / True - user cache file - just use False here

    cache_d = dict()

    my_seed = Seed(seed, hash_type)
    options_d['selectedHashtype'] = hash_type        

# generate the hash
    verify_with_epsigexe = True # True: use epsig.exe to verify bnk file format
                                # False: use builtin function to verify BNK format

    myp = epsig2(my_seed.seed, bnk_or_bin_file, options_d, cache_d, hash_type, verify_with_epsigexe)
    if myp.filepath != None:  # if filepath = None, then error in file/filename format
        myp.processfile()

    # format based on output options
        xor_result = epsig2.format_output(None, myp.xor_result, options_d)
        p_seed = epsig2.format_output(None, my_seed.seed, options_d)

        print(p_seed + "\t" + xor_result) 

    else: 
        print("invalid file - error in file/filename format: " + bnk_or_bin_file)

if __name__ == "__main__": main()