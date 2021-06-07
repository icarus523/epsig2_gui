# epsig2_gui.py 
# Ported from R## L######'ss LUA script version to python. 
# 
##	from R##'s original epsig2.lua 
##  Usage:
##		lua epsig2.lua bnkfilename [seed [reverse] ]
##
##	examples: 	lua epsig2.lua ARI\10163088_F23B_6040_1.bnk
##				lua epsig2.lua ARI\10163088_F23B_6040_1.bnk 1234
##				lua epsig2.lua ARI\10163088_F23B_6040_1.bnk 00 reverse
##      If no seed supplied then a seed of 00 is used
##
##	Note wrt a Casino "reverse"'d result, the result wrt Casino datafiles is the
##      last 8 chars of the result displayed. E.g.
##	Result: 3371cc5638d735cefde5fb8da904ac8d54c2050c the result is 54c2050c

# Version History
# v1.0 - Initial Release
# v1.1 - Add support to SL1 datafile seed files via combobox and file chooser widget,
#        updated GUI
# v1.2 - Add support to use MSL (QCAS) files and automatically flip the SEED as
#        expected for completing CHK01 (Yick's request)
# v1.3  - Add support for multiple selection of BNK files
#       - introduces Caching of Hashes
# v1.3.1 - Fixes Cache to also uniquely identify Seed
# v1.4 - Adds Cache File support to DEFAULT_CACHE_FILE
# v1.4.1 - cache is now a dict of a dicts,
#       i.e. { "fname":
#               { "seed": "hash_result",
#                 "filename": "C:\blah\blah\cache.json"
#               }
#            } - for readability.
#       - fixed cache file location to "\\\Justice.qld.gov.au\\Data
#               \\OLGR-TECHSERV\\TSS Applications Source\\J#####\\epsig2_cachefile.json"
#           - supports multiple seeds for each file
#       - adds user specifiable Cache File (when you want to control your own cache)
#       - adds automatic validation of Cache File, the file is signed and
#         verified prior to loading automatically, via SHA1 hash and a .sigs file
# v1.4.2 - add option to write to formatted log file (request by Y### L##)
#        - add option to display flipped bits for Seed in Console Log as an option.
#          (request by D### N#####)
#        - Update json signature file verifications to use SHA256
# v1.4.4 - was here somewhere
# v1.5  - separate epsig2 class (for use with: from epsig2_gui import epsig2)
#       - separate Cache File as a separate class
#       - By Default, a File Cache is now used as the OS can manage the resource being used
#       - new Seed class, to add support to formatting and different behaviours when using different hash types
#           - seed is automatically padded/truncated automatically based on Hash-Type selected
#       - Add support to BIN hashing (SG Gaming's ArgOS)
#       - Add support to paste a complete path in the BNK/BIN file text edit field (for Bang's processes)
#       - Now includes unit tests, to exercise the functions being utilised
#       - Output to Output Field, has been changed to the format: <SEED>/t<HASH>/t<FNAME> - 
#       - GUI has been standardised: button sizes, padding, relief, etc.
# v1.5b - add check for when contents of BNK file does not exist in expected path
# 
import os
import sys
import csv
import hashlib
import hmac
import binascii
import struct
import array
import datetime
import string
import tkinter
import json
import tkinter as tk
import getpass
import logging
import threading
import time 
import concurrent.futures
import atexit

from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from tkinter import filedialog
from threading import Thread
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait, as_completed

VERSION = "1.5"

TEST=True

EPSIG_LOGFILE = "epsig2.log"
MAXIMUM_BLOCKSIZE_TO_READ = 65535

if TEST: 
    DEFAULT_CACHE_FILE="epsig2_cachefile_v3.json"
else: 
    DEFAULT_CACHE_FILE = "\\\Justice.qld.gov.au\\Data\\OLGR-TECHSERV\\TSS Applications Source\\James\\epsig2_cachefile_v3.json"

DEFAULT_STR_LBL_SEED_FILE = "Details of Seed File: <No SL1/MSL Seed File Selected>"

p_reset = "\x08"*8

## CacheFile class
class CacheFile(): 

    def __init__(self, fname):
        logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s- %(message)s')    

        self.user_cache_file = fname
        self.cache_dict = self.importCacheFile() # read file

    def clearFile(self): 
        cache_data = dict() # empty
        self.updateCacheFile(cache_data)

    def importCacheFile(self):
        cache_data = dict() # empty

        if self.user_cache_file: # Handle User selectable Cache File
            cache_location = self.user_cache_file
        else: 
            cache_location = DEFAULT_CACHE_FILE
        
        if os.path.isfile(cache_location): 
            # Verify Cache Integrity
            if self.verifyCacheIntegrity(cache_location[:-4] + "sigs"): 
                with open(cache_location,'r') as json_cachefile: 
                    cache_data = json.load(json_cachefile)
            else: 
                logging.warning("**** WARNING **** File Cache integrity issue: " +
                        " Cannot Verify signature")
                logging.info("Generating new File Cache file: " + cache_location)
                cache_data = {} # return empty cache
        else:
            logging.info(cache_location + 
                " cannot be found. Generating default file...")
            with open(cache_location, 'w') as json_cachefile:
                # write empty json file
                json.dump({}, 
                    json_cachefile, 
                    sort_keys=True, 
                    indent=4, 
                    separators=(',', ': '))
        
        return(cache_data)

    def verifyCacheIntegrity(self, cache_location_sigs): 
        if os.path.isfile(cache_location_sigs): # Sigs file exist?
            with open(cache_location_sigs, 'r') as sigs_file: 
                cache_sigs_data = json.load(sigs_file)
                my_hash = cache_sigs_data['cachefile_hash']
                fname = cache_sigs_data['filename']
                
                generated_hash = epsig2.dohash_sha256(self, fname)
                if my_hash == generated_hash: 
                    return True
                else: 
                    return False     
        else: 
            # advise user
            logging.warning("**** WARNING **** Generating new Cache Sigs file") 
            if self.user_cache_file: # Handle User selectable Cache File
                cache_location = self.user_cache_file
            else: 
                cache_location = DEFAULT_CACHE_FILE
            
            self.signCacheFile(cache_location) # Generate Cache
        
    def signCacheFile(self, cache_location):
        sigsCacheFile = cache_location[:-4] + "sigs" # .json file renaming to .sigs file
        
        with open(sigsCacheFile,'w') as sigs_file: 
            h = epsig2.dohash_sha256(self, cache_location) # requires file name as input
            
            timestamp = datetime.now()
            sigs_dict = { 'cachefile_hash' : h,
                          'filename': cache_location,
                          'last_generated_by_user' : getpass.getuser(),
                          'date': str(timestamp.strftime("%Y-%m-%d %H:%M"))
                        }
            
            json.dump(sigs_dict,
                      sigs_file,
                      sort_keys=True,
                      indent=4,
                      separators=(',', ': '))
        
    def updateCacheFile(self, cache_dict):
        if self.user_cache_file:
            cache_location = self.user_cache_file
        else: 
            cache_location = DEFAULT_CACHE_FILE
            
        if os.path.isfile(cache_location):
            with open(cache_location, 'w') as json_cachefile:
                json.dump(cache_dict,
                          json_cachefile,
                          sort_keys=True,
                          indent=4,
                          separators=(',', ': '))
            
            self.signCacheFile(cache_location) # Sign Cache

## Main epsig2 class
class epsig2():

    def __init__(self, seed, filepath, options_d, cache_dict, hash_type_str):
        logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s- %(message)s')

        self.seed = seed 
        self.filepath = filepath
        self.options_d = options_d
        self.mandir = os.path.dirname(self.filepath)
        self.cache_dict = dict()
        self.xor_result = ''
        self.LogOutput = list() 
        self.user_cache_file = options_d['usr_cache_file']
        self.selectedHashtype = hash_type_str

        self.processfile(self.filepath, chunks=8192) 

    # returns Hashstring or None (if faiiled)
    def checkCacheFilename(self, filename, seed_input, alg_input): # alg_input 
        # For filename_seed, concatenate to form unique string. 
        if filename in self.cache_dict.keys(): # a hit?
            data = self.cache_dict.get(filename) # now a list
            for item in data:
                # Check if Seed and Algorithm matches. 
                if item['seed'] == seed_input and item['alg'] == alg_input: 
                    # verified_time = item['verify'] 
                    return(str(item['hash'])) # return Hash result
        
        return None    

    def checkCacheFilename_BNK(self, filename, seed_input, alg_input): # alg_input 
        # For filename_seed, concatenate to form unique string. 
        if filename in self.cache_dict.keys(): # a hit?
            data = self.cache_dict.get(filename) # now a list
            # print(json.dumps(data, indent=4, sort_keys=True))
            for item in data:
                # Check if Seed and Algorithm matches. 
                if item['seed'] == seed_input and item['alg'] == alg_input: 
                    # verified_time = item['verify'] 
                    return(str(item['hash'])) # return Hash result
        
        return None  

    # input: file to be CRC32 
    def dohash_crc32(self, fname):
        buf = open(fname,'rb').read()
        buf = (binascii.crc32(buf) & 0xFFFFFFFF)

        return "%08X" % buf

    # input: file to be hashed using sha256()
    # output: hexdigest of input file    
    def dohash_sha256(self, fname, chunksize=8192): 
        m = hashlib.sha256()         

        # Read in chunksize blocks at a time
        with open(fname, 'rb') as f:
            while True:
                block = f.read(chunksize)
                if not block: break
                m.update(block)    

        return m.hexdigest()

    # input: file to be hashed using hmac-sha1
    # output: hexdigest of input file    
    def dohash_hmacsha(self, fname, chunksize, hash_type):
        # time.sleep(1)
        # change this if you want other hashing types for HMAC, e.g. hashlib.md5
        key = bytes.fromhex(self.seed)
        m = None
        if hash_type == 'HMAC-SHA1': 
            m = hmac.new(key, digestmod = hashlib.sha1) 
        elif hash_type == 'HMAC-SHA256': 
            m = hmac.new(key, digestmod = hashlib.sha256) 
        else: 
            logging.error("unknown hash type: " + hash_type)
            sys.exit(1)

        done = 0
        size = os.path.getsize(fname)
        # Read in chunksize blocks at a time
        with open(fname, 'rb') as f:
            while True:
                # time.sleep(1)
                block = f.read(chunksize)
                done += chunksize
                sys.stdout.write("%7d"%(done*100/size) + "%" + p_reset)
                if not block: break
                m.update(block)      
        return m.hexdigest()
    
    def checkhexchars(self, text):
        return (all(c in string.hexdigits for c in text))            

    def dobin(self, fname, blocksize):
        #time.sleep(1)
        oh = "0000000000000000000000000000000000000000000000000000000000000000"

        if self.options_d['cache_file_f'] == True: # Use Cache File
            # Overwrite self.cache_dict with contents of file
            cache_file = CacheFile(self.user_cache_file) 
            self.cache_dict = cache_file.cache_dict

        if (len(self.seed) < 2 or not self.checkhexchars(self.seed)):
            messagebox.showerror("Error in Seed Input",
                                 "Expected atleast two Hexadecimal characters as the Seed input" +
                                 ".\n\nCheck your Seed string again: " + self.seed)
            return -1
        else:
            logging.debug("Processing: " + fname +  "\t[" + str(threading.currentThread().getName()) + "]")
            try: 
                hash_type = self.selectedHashtype # this is HMAC-SHA1 or HMAC-SHA256
                if (os.path.isfile(fname)):
                    # The following should return a list    
                    cachedhit = self.checkCacheFilename(fname, self.seed, hash_type) # TODO: for BIN FILES?
                    # logging.debug("%-50s\tSEED" % (self.format_output(self.seed, self.options_d)))
                    
                    if cachedhit:
                        localhash = cachedhit
                    else: # append to cachelist
                        new_cache_list = list()

                        localhash = self.dohash_hmacsha(fname, blocksize, self.selectedHashtype)

                        seed_info = { 
                            'seed': self.seed, 
                            'alg': hash_type, 
                            'hash': localhash 
                        }        
                        
                        cache_entry_list = self.cache_dict.get(fname) # Should return a list. 
                        
                        if cache_entry_list : # File Entry Exists, append to list
                            cache_entry_list.append(seed_info) # print this
                            self.cache_dict[fname] = cache_entry_list # keep unique
                        else:  # No File Entry Exits generate new list entry in cache_dict
                            new_cache_list.append(seed_info)
                            self.cache_dict[fname] = new_cache_list # keep unique
                        
                        # if self.useCacheFile.get() == 1:
                        if self.options_d['cache_file_f'] == True:
                            # self.updateCacheFile(self.cache_dict) # Update file cache
                            cache_file.updateCacheFile(self.cache_dict) # Update file cache
                        else: 
                            self.cache_dict[fname] = new_cache_list # update local cache
                            
                    # Append Object to Log object
                    self.LogOutput.append({'filename': os.path.basename(fname), 
                        'filepath': self.mandir + "/" , 
                        'seed' : self.seed, 
                        'alg': hash_type, 
                        'hash': localhash})
                    
                    oh = hex(int(oh,16) ^ int(str(localhash), 16)) # XOR result
                    
                    if cachedhit:
                        outputstr = "%-50s\t%-s\t%-10s" % (self.format_output(str(localhash), 
                            self.options_d), os.path.basename(fname), "(cached)")
                    else:
                        outputstr = "%-50s\t%-s\t" % (self.format_output(str(localhash), self.options_d), 
                            os.path.basename(fname))
                    
                    logging.debug(outputstr + "[" + str(threading.currentThread().getName()) + "]")
                else: 
                    logging.error("\n!!!!!!!!!!!!!! ERROR: Could not read file: " + fname)

            except KeyboardInterrupt:
                logging.debug("Keyboard interrupt during processing of files. Exiting")
                sys.exit(1)

        return oh # { 'oh': oh, 'cache_dict' : self.cache_dict, 'rv': self.LogOutput ,'filename' : fname} 

    # limitations: currently only supports bnk file with SHA1 contents        
    def dobnk(self, fname, blocksize):
        #time.sleep(1)
        cache_file = None
        outputstr = None
        
        if self.options_d['cache_file_f'] == True: # Use Cache File
            # Overwrite self.cache_dict with contents of file
            cache_file = CacheFile(self.user_cache_file) 
            self.cache_dict = cache_file.cache_dict

        oh = "0000000000000000000000000000000000000000" # 40 chars

        # Verify Seed is a number String format, and atleast 2 digits long 
        if (len(self.seed) < 2 or not epsig2.checkhexchars(self, self.seed)):
            messagebox.showerror("Error in Seed Input",
                                 "Expected atleast two Hexadecimal characters as the Seed input" +
                                 ".\n\nCheck your Seed string again: " + self.seed)
            return -1
        else:
            try:
                logging.debug("Processing: " + fname +  "\t[" + str(threading.currentThread().getName()) + "]")

                with open(fname, 'r') as infile: 
                    fdname = ['fname', 'type', 'blah']
                    reader = csv.DictReader(infile, delimiter=' ', fieldnames = fdname)

                    # logging.debug("%-50s\tSEED" % (self.format_output(self.seed, self.options_d)))
                    #futures = list() 
                    #pool = ThreadPoolExecutor(5) # 5 threads max

                    for row in reader:
                        if str(row['type']).upper() == 'SHA1' or str(row['type']).upper() == 'SHA256':
                            # check if the file exists
                            fp = self.mandir + "/" + str(row['fname']) # can't use: os.path.join(self.mandir, str(row['fname'])), as the Cache expects "/"
                            if (os.path.isfile(fp)):

                                # The following should return a string if matches or None   
                                cachedhit = epsig2.checkCacheFilename_BNK(self, fp, self.seed, str(row['type']).upper())
                                
                                if cachedhit != None:
                                    localhash = cachedhit
                                else: 
                                    new_cache_list = list()

                                    localhash = epsig2.dohash_hmacsha(self, self.mandir + "/" \
                                        + str(row['fname']), blocksize, 'HMAC-' \
                                        + str(row['type']).upper()) # BLNK only supports HMAC-SHA1 or HMAC-SHA256

                                    #fp = self.mandir + "/" + str(row['fname'])
                                    #futures.append(pool.submit(self.dohash_hmacsha, fp, blocksize, self.selectedHashtype)) # add processs to threadpool
                                    
                                    #for x in as_completed(futures): 
                                    #    localhash = x.result()     

                                    # generate dict for new Filename entry
                                    seed_info = { 
                                        'seed': self.seed, 
                                        'alg': row['type'].upper(), 
                                        'hash': localhash 
                                    }        
                                    
                                    cache_entry_list = self.cache_dict.get(self.mandir + "/" + 
                                        str(row['fname'])) # Should return a list. 
                                    
                                    if cache_entry_list : # File Entry Exists, append to list
                                        cache_entry_list.append(seed_info) # print this
                                        self.cache_dict[self.mandir + "/" 
                                            + str(row['fname'])] = cache_entry_list # keep unique
                                    else:  # No File Entry Exits generate new list entry in cache_dict
                                        new_cache_list.append(seed_info)
                                        self.cache_dict[self.mandir + "/" + 
                                            str(row['fname'])] = new_cache_list # keep unique
                                    
                                    # if self.useCacheFile.get() == 1:
                                    if self.options_d['cache_file_f'] == True:
                                        # self.updateCacheFile(self.cache_dict) # Update file cache
                                        cache_file.updateCacheFile(self.cache_dict) # Update file cache
                                    else: 
                                        self.cache_dict[self.mandir + "/" + 
                                                    str(row['fname'])] = new_cache_list # update local cache
                                        
                                # Append Object to Log object
                                self.LogOutput.append({'filename': str(row['fname']), 
                                    'filepath': self.mandir + "/" , 
                                    'seed' : self.seed, 
                                    'alg': row['type'].upper(), 
                                    'hash': localhash})

                                # handle incorrect seed length
                                if localhash == 0:
                                    break # exit out cleanly
                                
                                # change to string to Hexadecimal - int(str,16), then XOR result
                                oh = hex(int(oh,16) ^ int(str(localhash), 16)) # XOR'ed result
                                
                                if cachedhit:
                                    outputstr = "%-50s\t%-s\t%-10s" % (epsig2.format_output(self, str(localhash), 
                                        self.options_d), str(row['fname']), "(cached)")
                                else:
                                    outputstr = "%-50s\t%-s" % (epsig2.format_output(self, str(localhash), self.options_d), 
                                        str(row['fname']))
                                
                                logging.debug(outputstr + "[" + str(threading.currentThread().getName()) + "]")
                                # self.output.append(outputstr)
                                
                            else: 
                                error_text =  "\n!!!!!!!!!!!!!! ERROR: Could not read file: " + str(row['fname']) + " in: " + fname + "\n\n"
                                logging.error("Could not read file: " + str(row['fname']) + " in: " + fname)
                                return -1
                                # self.output.append(error_text)
                        else: 
                            messagebox.showerror("Not Yet Implemented!", "Unsupported hash algorithm: " + row['type'].upper() + ".\n\nExiting. Sorry!")
                            logging.error('Unsupported hash algorithm: ' + row['type'])
                            return -1
                            # Need to implement CR16, CR32, PS32, PS16, OA4F and OA4R, and SHA256 if need be. 


            except KeyboardInterrupt:
                logging.debug("Keyboard interrupt during processing of files. Exiting")
                #sys.exit(1)
                return -1
            
        return oh # { 'oh': oh } , 'cache_dict' : self.cache_dict, 'rv': self.LogOutput ,'filename' : fname} 
    
    # Inserts spaces on [text] for every [s_range]
    def insert_spaces(self, text, s_range):
        return " ".join(text[i:i+s_range] for i in range(0, len(text), s_range))

    # Formats inputstr based on options_d dictionary
    def format_output(self, inputstr, options_d):
        outputstr = ''

        if options_d['selectedHashtype'] == 'HMAC-SHA1': 
            outputstr = inputstr.lstrip('0X').lstrip('0x').zfill(40) #strip 0x first
        elif options_d['selectedHashtype'] == 'HMAC-SHA256': 
            outputstr = inputstr.lstrip('0X').lstrip('0x').zfill(64) #strip 0x first

        # include a space for every eight chars
        if (options_d['eightchar'] == True):
            s_range = 8
            outputstr = " ".join(outputstr[i:i+s_range] for i in range(0, len(outputstr), s_range)) # self.insert_spaces(inputstr, 8)
        
        # uppercase
        if options_d['uppercase'] == True: 
            outputstr = outputstr.upper()
        
        # QCAS expected result
        if options_d['reverse'] == True:
            outputstr = epsig2.getQCAS_Expected_output(self, outputstr)
        
        return outputstr

    def getQCAS_Expected_output(self, text):
        tmpstr = text[:8] # Returns from the beginning to position 8 of uppercase text
        return "".join(reversed([tmpstr[i:i+2] for i in range(0, len(tmpstr), 2)]))

    def processfile(self, fname, chunks):
        # time.sleep(1) 
        h = None
        do_output = None
        
        future = list()
        if fname.upper().endswith(".BNK"): 
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future.append(executor.submit(self.dobnk, fname, chunks))
            # h = self.dobnk(fname, chunks)
        #elif fname.upper().endswith(".BIN"): 
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future.append(executor.submit(self.dobin, fname, chunks))
            # h = self.dobin(fname, chunks)
        #else: 
        #    logging.error("unknown file type selected: " + fname)
        #    messagebox.showerror("Invalid files selected", "Please select either .BNK or .BIN files only")
        #    return 

        for x in as_completed(future): 
            # time.sleep(1) 
            h = x.result()                    

            if h == -1: 
                return # handle error in seed input
            else:
                # self.text_BNKoutput.insert(END, "%-50s\t%s\n" % (str(h).zfill(40), "RAW output"))
                # raw_outputstr = "%-50s\t%s" % (str(h).zfill(40), "RAW output")
                # logging.debug(raw_outputstr + "\t[" + str(threading.currentThread().getName()) + "]")
                # self.output.append(raw_outputstr)

                #### 
                # processfile must occur before any reads to self.xor_result!!  
                self.xor_result = h
                #### 

                outputstr = "%-50s" % (str(self.format_output(str(h), self.options_d)))
                if fname.upper().endswith(".BNK"): 
                    logging.debug(outputstr + "\tXOR Formatted Result" + "\t [" + str(threading.currentThread().getName()) + "]")
                else: 
                    logging.debug(outputstr + "\tFormatted Result" + "\t [" + str(threading.currentThread().getName()) + "]")

class Seed(): 

    def __init__(self, seed, hash_type):
        self.hash_type = hash_type 

        valid_hash_types = ['HMAC-SHA256', 'HMAC-SHA1']
        if hash_type in valid_hash_types: 
            self.seed = self.getSeed(seed)
            logging.warning("Seed Modifed to: " + self.seed)
        else:
            self.seed = None
            return -1


    def getSeed(self, s): 
        output_str = ''
        # need to append '0' to include appropriate length
        if self.hash_type == 'HMAC-SHA256' and len(s) < 64: 
            # append
            output_str = s.ljust(64, '0')
        elif self.hash_type == 'HMAC-SHA1' and len(s) < 40:
            output_str = s.ljust(40, '0')
        elif self.hash_type == 'HMAC-SHA256' and len(s) > 64: 
            # truncate
            output_str = s[:64] 
        elif self.hash_type == 'HMAC-SHA1' and len(s) > 40: 
            output_str = s[:40] 
        else: 
            return s

        return output_str

class epsig2_gui(threading.Thread):

    # Constructor
    def __init__(self):
        logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s- %(message)s')
        logging.debug('Start of epsig2_gui')
        
        self.bnk_filename = ''
        self.filepath = ''
        self.seed_filepath = ''
        self.bnk_filename_list = list()
        self.filelist = list()
        self.user_cache_file = None
        self.cache_dict = {} # Clear cache_dict
        self.root = Tk()
        self.selectedHashtype = StringVar() 
        self.seed = None

        Thread(self.setupGUI()).start()        

    def writetoLogfile(self, filename, epsig2_p, bnkfile, multi_logf):
        timestamp = datetime.timestamp(datetime.now())
        outputfile = ''
        
        #if self.logtimestamp.get() == 1: # Multi log files not overwritten saved in different directory
        if multi_logf == True: 
            outputfile = "epsig2-logs/" + filename[:-4] + "-" + str(timestamp) + ".log"
        else: # Single log file that's overwritten
            outputfile = filename

        with open(outputfile, 'a+') as outfile:
            outfile.writelines("#--8<-----------GENERATED: " + 
                str(datetime.fromtimestamp(timestamp)) + " --------------------------\n")
            outfile.writelines("Processsed: " + bnkfile + "\n")
            # outfile.writelines("%40s \t %40s \t %60s\n" % ("SEED", "HASH", "FILENAME"))
            my_seed = ''
            outfile.writelines("%-40s \t %-40s \t %-60s\n" % ("Seed", "Hash", "Filename"))
            for item in epsig2_p.LogOutput:
                outfile.writelines("%40s \t %40s \t %-60s\n" % (epsig2.format_output(self, str(item['seed']), self.gui_getOptions()), 
                    epsig2.format_output(self, str(item['hash']), self.gui_getOptions()), item['filename']))
                my_seed = str(item['seed'])

            if epsig2_p.filepath.upper().endswith('.BNK'): 
                outfile.writelines("%40s \t %40s \t XOR\n" % (epsig2.format_output(self, my_seed, self.gui_getOptions()), 
                    epsig2.format_output(self, epsig2_p.xor_result.replace(" ", ""), self.gui_getOptions())))
            else: 
                outfile.writelines("%40s \t %40s \t Formatted Output\n" % (epsig2.format_output(self, my_seed, self.gui_getOptions()), 
                    epsig2.format_output(self, epsig2_p.xor_result.replace(" ", ""), self.gui_getOptions())))

    # Returns flipped bits of full length
    def getClubsQSIM_Expected_output(self, text): 
        return "".join(reversed([text[i:i+2] for i in range(0, len(text), 2)]))

    # Generates the Seed object everytime the "start" button is pressed. 
    def GetSeedText(self):
        tmp_seed = ''
        # reverse the seed.
        if (self.reverse.get() == 1): 
            tmp_seed = epsig2.getQCAS_Expected_output(self, self.combobox_SelectSeed.get())
        else: 
            tmp_seed = self.combobox_SelectSeed.get()

        self.seed = Seed(tmp_seed, self.selectedHashtype.get())
        logging.warning("Seed Modifed to: " + self.seed.seed)

    def gui_getOptions(self): 
        options_d = dict() 
        options_d['cache_file_f'] = self.useCacheFile.get() == 1
        options_d['uppercase'] = self.uppercase.get() == 1
        options_d['eightchar'] = self.eightchar.get() == 1
        options_d['reverse'] = self.reverse.get() == 1
        options_d['usr_cache_file'] = self.CacheFileButtonText.get()        
        options_d['selectedHashtype'] = self.selectedHashtype.get()

        return options_d

    # refer: https://stackoverflow.com/questions/38987/how-do-i-merge-two-dictionaries-in-a-single-expression
    def merge_two_dicts(self, x, y):
        z = x.copy()   # start with x's keys and values
        z.update(y)    # modifies z with y's keys and values & returns None
        return z

    def updateGUI(self, epsig2_process): 
        # update main text area window
        #     def format_output(self, inputstr, options_d):

        # Display Filename to be processed
        self.text_BNKoutput.insert(END, "\nProcessing: " + epsig2_process.filepath + "\n")

        if epsig2_process.filepath.upper().endswith('.BNK'): 
            # Display BNK details
            for hash_result in epsig2_process.LogOutput: 
                # bnk_details_hash_output = hash_result['seed'] + "\t" + hash_result['hash'] + "\t" + hash_result['filename']
                seed_str = epsig2.format_output(self, hash_result['seed'], self.gui_getOptions())
                hash_str = epsig2.format_output(self, hash_result['hash'], self.gui_getOptions())
                
                bnk_details_hash_output = seed_str + "\t" + hash_str + "\t" + hash_result['filename']
                self.text_BNKoutput.insert(END, bnk_details_hash_output + "\n")
            
            self.text_BNKoutput.insert(END, "XOR Result: " + "\n")
        else: 
            self.text_BNKoutput.insert(END, "Formatted Result: " + "\n")

        # Format seed and XOR/Formatted Result
        seed_output = epsig2.format_output(self, self.seed.seed, self.gui_getOptions())
        str_output = epsig2.format_output(self, epsig2_process.xor_result, self.gui_getOptions())
        
        self.text_BNKoutput.insert(END, seed_output + "\t" + str_output + "\t" + os.path.basename(epsig2_process.filepath + "\n"))

    def startEpsig2GUI(self, filepath): 
        #futures = list() 
        #pool = ThreadPoolExecutor(len(self.filelist)) # one thread per file     
        self.bnk_filename = os.path.basename(filepath)
        self.mandir = os.path.dirname(filepath)

        self.GetSeedText() 

        if (self.clubs_expected_output.get() == 1):
            message = "\nQSIM reversed seed to use: " + self.getClubsQSIM_Expected_output(self.seed.seed) + "\n"
            logging.info(message)
            self.text_BNKoutput.insert(END, message)

        logging.info("Seed is: " + self.seed.seed + " length is: " + str(len(self.seed.seed)))

        # create process for hashing a file 
        my_p = epsig2(self.seed.seed, filepath, self.gui_getOptions(), self.cache_dict, str(self.selectedHashtype.get())) 
        #futures.append(pool.submit(my_p.processfile, filepath, MAXIMUM_BLOCKSIZE_TO_READ)) # add processs to threadpool

        # update dict() 
        self.cache_dict = self.merge_two_dicts(self.cache_dict, my_p.cache_dict)

        self.updateGUI(my_p)

    #    def writetoLogfile(self, filename, xor_result, bnkfile, multi_logf):

        if self.writetolog.get() == 1: 
            self.writetoLogfile(EPSIG_LOGFILE, my_p, filepath, self.logtimestamp.get() == 1)

        # Create and launch a thread 
        # t = Thread(group=None, target=my_p.processfile, name=self.bnk_filename, args=(filepath, MAXIMUM_BLOCKSIZE_TO_READ, )) 
        # t.start()
        # xor_result = self.processfile(filepath, MAXIMUM_BLOCKSIZE_TO_READ)
    
    def verifyFileExists(self, f):
        if f.endswith(".BNK"): 
            with open(f, 'r') as infile: 
                fdname = ['fname', 'type', 'blah']
                reader = csv.DictReader(infile, delimiter=' ', fieldnames = fdname)
                for row in reader: 
                    path = os.path.dirname(f)
                    fp = os.path.join(path, str(row['fname'])) # can't use: os.path.join(self.mandir, str(row['fname'])), as the Cache expects "/"
                    if not os.path.isfile(fp): 
                        msg = "**** ERROR: " + fp + " cannot be read from disk"
                        logging.error(msg)                        
                        return False    
        else: 
            if not os.path.isfile(f): 
                return False    

        return True


    def handleButtonPress(self, myButtonPress):
        
        if myButtonPress == '__selected_bnk_file__':
            if (os.name == 'nt'): # Windows OS
                tmp = filedialog.askopenfilenames(initialdir='G:/OLGR-TECHSERV/BINIMAGE')
            elif (os.name == 'posix'): # Linux OS
                tmp = filedialog.askopenfilenames(initialdir='.')
            else: 
                tmp = filedialog.askopenfilenames(initialdir='.')

            if tmp:
                self.textfield_SelectedBNK.delete(0, END)
                self.filelist = tmp
                for fname in self.filelist:
                    fname_basename = os.path.basename(fname)
                    self.bnk_filename_list.append(fname_basename)
                    self.textfield_SelectedBNK.insert(0, fname_basename + "; ")
                    
                    if not self.verifyFileExists(fname):
                        msg = "**** ERROR: " + fname + " cannot be read check contents"
                        self.text_BNKoutput.insert(END, msg)
                        logging.error(msg)

        elif myButtonPress == '__start__':
            if len(self.filelist) > 0: 
           
                for filepath in self.filelist:
                    logging.info("Processing: " + filepath)
                    if (os.path.isfile(filepath)):                 
                        self.startEpsig2GUI(filepath)
                    else: 
                        logging.warning(filepath + " does not exist")
                        messagebox.showerror(filepath + " does not exist", "Error in file selection")

            else:
                # try reading the text box if file exits: 
                tmp_fname = self.textfield_SelectedBNK.get() 
                if os.path.isfile(tmp_fname): 
                    self.startEpsig2GUI(tmp_fname)
                else: 
                    messagebox.showerror("BNK files not selected.", "Please select files first")
                    logging.error(str(len(self.filelist)))
        
        elif myButtonPress == '__clear_output__':
                self.text_BNKoutput.delete(1.0, END)
                
        elif myButtonPress == '__clear__':
                self.text_BNKoutput.delete(1.0, END)
                self.cb_reverse.deselect()
                self.filepath = ''
                self.bnk_filename = ''
                self.textfield_SelectedBNK.delete(0, END)
                self.reverse.set(0)
                self.mslcheck.set(0)
                self.cb_uppercase.deselect()
                self.cb_mslcheck.deselect()
                self.uppercase.set(1)
                self.eightchar.set(0)
                self.cb_eightchar.deselect()
                self.writetolog.set(0)
                self.logtimestamp.set(0)
                self.clubs_expected_output.set(0)
                self.label_SeedPath.configure(text=DEFAULT_STR_LBL_SEED_FILE) 
                self.combobox_SelectSeed.set('0000000000000000000000000000000000000000')
                self.combobox_SelectSeed['values'] = ()
                self.bnk_filename_list = list()
                self.filelist = list()
                self.useCacheFile.set(1)
                self.CacheFileButtonText.set(DEFAULT_CACHE_FILE)
                self.user_cache_file = None
                self.selectedHashtype.set("HMAC-SHA1")
                
        elif myButtonPress == '__clear_cache__':
                if self.user_cache_file:
                    cache_location = self.user_cache_file
                else: 
                    cache_location = DEFAULT_CACHE_FILE
                    
                if self.useCacheFile.get() == 1: # Use Cache File
                    cache_file = CacheFile(self.user_cache_file) # read cache file
                    cache_file.clearFile() # clear file cache
                    self.cache_dict = cache_file.cache_dict # Overwrite self.cache_dict with contents of file
                else:
                    self.cache_dict = {} # empty_cache_data # Clear cache_dict


        elif myButtonPress == '__print_cache__':
                self.text_BNKoutput.insert(END, "\nCache Entries: ")
                if self.useCacheFile.get() == 1: # Use Cache File
                    cache_file = CacheFile(self.CacheFileButtonText.get())
                    self.cache_dict = cache_file.cache_dict # Overwrite self.cache_dict with contents of file

                message = json.dumps(self.cache_dict, sort_keys=True, indent=4, separators=(',',':'))                    
                self.text_BNKoutput.insert(END, message + "\n")


        elif myButtonPress == '__select_cache_file__':
                input_cachefile_dir = filedialog.askdirectory(initialdir='.', title='Select Directory to save cache file...')
                self.CacheFileButtonText.set(os.path.join(input_cachefile_dir,os.path.basename(DEFAULT_CACHE_FILE)))
                self.user_cache_file = self.CacheFileButtonText.get()

        elif myButtonPress == '__selected_seed_file__':
            if (os.name == 'nt'): # Windows OS
                if (self.mslcheck.get() == 1): # Handle MSL file option for QCAS datafiles
                    tmp = filedialog.askopenfile(initialdir='G:\OLGR-TECHSERV\MISC\BINIMAGE\qcas')
                else: 
                    tmp = filedialog.askopenfile(initialdir='S:\cogsp\docs\data_req\download\master') # put S:\ dir here. 
            elif (os.name == 'posix'): # Linux OS (my dev box)
                tmp = filedialog.askopenfile(initialdir='.')
            else: 
                tmp = filedialog.askopenfile(initialdir='.')
                
            if tmp: # Selected something
                self.seed_filepath = tmp.name
                self.getComboBoxValues(self.seed_filepath)
                
                # Generate Year and Date based on numbers extracted
                sl1date = datetime.strptime(self.sl1_year + "/" + self.sl1_month, "%Y/%m")
                self.label_SeedPath.configure(text="Seed File: " + sl1date.strftime("(%b %Y)") + ": " + self.seed_filepath) 

    def processsl1file(self, fname): 
        seedlist = ()
        with open(fname,'r') as sl1file:
            sl1entry = csv.reader(sl1file, delimiter=',')
            try:
                # Select the Columns we want - index starts at 0
                included_cols = [2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]
                for row in sl1entry:
                    seedlist = list(row[i] for i in included_cols) # create a list with only the columns we need
                    self.sl1_year = row[0] # extract year
                    self.sl1_month = row[1] # extract month
            except csv.Error as e:
                sys.exit('file %s, line %d: %s' % (fname, sl1file.line_num, e))
        return seedlist      

    def getComboBoxValues(self, fname):
        if (os.path.isfile(fname)):
            self.combobox_SelectSeed['values'] = self.processsl1file(fname)
        else:
            messagebox.showerror("Expected SL1 or MSL file to Process", fname + " is not a valid seed file")
            # sys.exit(1)                 

    def aboutwindow(self):
        about_script = "Version: v" + VERSION + " by aceretjr\n Python3 script for processing BNK and BIN files."
        messagebox.showinfo("About This Script", about_script)

    def SelectHashType(self, value): 
        self.selectedHashtype.set(value)

    def seed_selection(self):
        print(self.box_value.get())

    def setupGUI(self):
        self.root.wm_title("epsig2 BNK/BIN file hashing tool v" + VERSION)
        self.root.resizable(1,1)

        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        #optionmenu = tk.Menu(menubar, tearoff=1)
        helpmenu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=filemenu)
        # menubar.add_cascade(label="Option", menu=optionmenu)
        menubar.add_cascade(label="Help", menu=helpmenu)
        filemenu.add_command(label="Exit", command=self.root.destroy)
        helpmenu.add_command(label="About...", command=self.aboutwindow)
        #optionmenu.add_command(label="Preferences...", command=self.MenuBar_Config) # start this script now. 
        
        self.root.config(menu=menubar)
        
        ######## Top Frame
        frame_toparea = ttk.Frame(self.root)
        frame_toparea.pack(side = TOP, fill=X, expand=False)
        frame_toparea.config(relief = None, borderwidth = 2)

        frame_toparea2 = ttk.Frame(frame_toparea)
        frame_toparea2.pack(side = TOP, fill=X, expand=False)
        frame_toparea2.config(relief = None, borderwidth = 2)
        
        ttk.Label(frame_toparea2, justify=LEFT,
                                  text = 'GUI script to process BNK/BIN files (Supports only HMAC-SHA1/HMAC-SHA256) - Please Select: ').pack(side=LEFT, padx=3, pady=3, fill=Y, expand=False, anchor='w')

        self.selectedHashtype = StringVar()
        optionMenuHashType = OptionMenu(frame_toparea2, self.selectedHashtype, 'HMAC-SHA1', 'HMAC-SHA256', command=self.SelectHashType).pack(side=LEFT, padx=3, pady=3, fill=X, expand=False, anchor='w')
        self.selectedHashtype.set("HMAC-SHA1")

        ######## BNK Selection Frame
        frame_bnkSelectionFrame = ttk.Frame(frame_toparea)
        frame_bnkSelectionFrame.config(relief = RIDGE, borderwidth = 2)
        frame_bnkSelectionFrame.pack(side = TOP, padx  = 3, pady = 3, expand = False, fill=X, anchor = 'w')       

        button_SelectedBNKfile = ttk.Button(frame_bnkSelectionFrame, text = "Select BNK/BIN file...", width=20, 
                                                      command = lambda: self.handleButtonPress('__selected_bnk_file__'))                                             
        button_SelectedBNKfile.pack(side=LEFT, padx = 3, pady = 3, fill=X, expand=False)
        
        # Text Entry Selected BNK file
        self.textfield_SelectedBNK = ttk.Entry(frame_bnkSelectionFrame, width = 120)
        self.textfield_SelectedBNK.pack(side=LEFT, fill=X, padx = 3, pady = 3, expand=True)

        ########### Seed Frame Area
        frame_SeedFrame = ttk.Frame(frame_toparea) 
        frame_SeedFrame.config(relief = RIDGE, borderwidth = 2)
        frame_SeedFrame.pack(side=TOP, fill=X, padx = 3, pady = 3, expand=True)
 
        frame_SelectSeed = ttk.Frame(frame_toparea)
        frame_SelectSeed.config(relief= None, borderwidth = 2)
        frame_SelectSeed.pack(side=TOP, fill=X, padx = 3, pady = 3, expand=True)

        # Button Selected Seed file (sl1)
        button_Selectedsl1file = ttk.Button(frame_SeedFrame, 
            text = "Seed or SL1/MSL file...", width = 20, 
            command = lambda: self.handleButtonPress('__selected_seed_file__'))                                             
        button_Selectedsl1file.pack(side=LEFT, fill=X, padx = 3, pady = 3, expand=False)

        # Combo Box for Seeds, default to 0x00
        self.box_value = StringVar()
        self.combobox_SelectSeed = ttk.Combobox(frame_SeedFrame, 
            justify=LEFT, 
            textvariable=self.box_value, 
            # command=self.seed_selection,
            width = 70)
        self.combobox_SelectSeed.pack(side=LEFT, fill=X, padx = 3, pady = 3, expand=True)
        self.combobox_SelectSeed.set('0000000000000000000000000000000000000000')

        # Checkbutton MSL file (casinos)
        self.mslcheck = IntVar()
        self.mslcheck.set(0)
        self.cb_mslcheck = Checkbutton(frame_SeedFrame, 
            text="MSL (Use Casino MSL File)", 
            justify=LEFT, 
            variable = self.mslcheck, 
            onvalue=1, 
            offvalue=0)
        self.cb_mslcheck.pack(side=LEFT, fill=X, padx = 3, pady = 3, expand=False)
        
        # Text Label sl1 location
        self.label_SeedPath = ttk.Label(frame_toparea, 
            text = DEFAULT_STR_LBL_SEED_FILE, width = 80)
        self.label_SeedPath.pack(side=BOTTOM, fill=X, padx = 3, pady = 3, expand=True)
        
        ######################### MIDDLE FRAME
        frame_middleframe = ttk.Frame(self.root)
        frame_middleframe.pack(side = TOP, fill=BOTH, expand=True)

        # Need to use .pack() for scrollbar and text widget
        frame_textarea = ttk.Labelframe(frame_middleframe, text="Output Field")
        frame_textarea.pack(side = LEFT, fill=BOTH, expand=True)
        frame_textarea.config(relief = RIDGE, borderwidth = 2)

        # Text Area output of BNK file generation
        self.text_BNKoutput = Text(frame_textarea, height=25, width =80)
        myscrollbar = Scrollbar(frame_textarea, command=self.text_BNKoutput.yview)
        myscrollbar.pack(side=RIGHT, fill=Y)
        self.text_BNKoutput.configure(yscrollcommand=myscrollbar.set)
        self.text_BNKoutput.pack(side=LEFT, fill=BOTH, expand=True)
        
        #Frame for Checkbuttons
        frame_checkbuttons = ttk.Labelframe(frame_middleframe, text="Output Options")
        frame_checkbuttons.pack(side = RIGHT, fill=Y, expand = False)
        frame_checkbuttons.config(relief = RIDGE, borderwidth = 2)
        
        # Checkbutton Reverse
        self.reverse = IntVar()
        self.reverse.set(0)
        self.cb_reverse = Checkbutton(
            frame_checkbuttons, 
            text="QCAS expected output", 
            justify=LEFT, 
            variable = self.reverse, 
            onvalue=1, 
            offvalue=0)
        self.cb_reverse.grid(row=1, column=1, sticky='w')

        # Checkbutton QSIM expected Seed 
        self.clubs_expected_output = IntVar()
        self.clubs_expected_output.set(0)
        self.cb_clubs_expected_output = Checkbutton(
            frame_checkbuttons, 
            text="Display QSIM expected seed", 
            justify=LEFT, 
            variable = self.clubs_expected_output, 
            onvalue=1, 
            offvalue=0)
        self.cb_clubs_expected_output.grid(row=2, column=1, sticky='w')

        # Checkbutton Uppercase
        self.uppercase = IntVar()
        self.uppercase.set(1)
        self.cb_uppercase = Checkbutton(
            frame_checkbuttons, 
            text="Uppercase", 
            justify=LEFT, 
            variable = self.uppercase, 
            onvalue=1, 
            offvalue=0)
        self.cb_uppercase.grid(row=3, column=1, sticky='w')

        # Checkbutton 8 Char
        self.eightchar = IntVar()
        self.eightchar.set(0)
        self.cb_eightchar = Checkbutton(
            frame_checkbuttons, 
            text="8 character spacing", 
            justify=LEFT, 
            variable = self.eightchar, 
            onvalue=1, 
            offvalue=0)
        self.cb_eightchar.grid(row=4, column=1, sticky='w',)

        # Checkbutton Write to Log
        self.writetolog = IntVar()
        self.writetolog.set(1)
        self.cb_writetolog = Checkbutton(
            frame_checkbuttons, 
            text="Log File: epsig2.log", 
            justify=LEFT, 
            variable = self.writetolog, 
            onvalue=1, 
            offvalue=0)
        self.cb_writetolog.grid(row=5, column=1, sticky='w',)

        # Timestamp logs
        self.logtimestamp = IntVar()
        self.logtimestamp.set(0)
        self.cb_logtimestamp = Checkbutton(
            frame_checkbuttons, 
            text="Multiple Log Files: epsig2-logs/", 
            justify=LEFT, 
            variable = self.logtimestamp, 
            onvalue=1, 
            offvalue=0)
        self.cb_logtimestamp.grid(row=6, column=1, sticky='w',)

        ################ Bottom FRAME ##############
        frame_bottombuttons = ttk.Frame(self.root)
        frame_bottombuttons.pack(side=BOTTOM, fill=X, expand = False)
        frame_bottombuttons.config(relief = None, borderwidth = 2)

        ################ Bottom Control FRAME ##############
        frame_controlbuttons = ttk.Frame(frame_bottombuttons)
        frame_controlbuttons.pack(side=TOP, fill=X, expand = True)
        frame_controlbuttons.config(relief = RIDGE, borderwidth = 2)
        
        # Clear Button
        self.button_clear = ttk.Button(
            frame_controlbuttons, 
            text = "Reset Form to Defaults", 
            command = lambda: self.handleButtonPress('__clear__'), 
            width = 20)
        self.button_clear.grid(row=1, column = 1, padx=5, pady=5, sticky='w',)

        # Clear Output
        button_clear_output = ttk.Button(
            frame_controlbuttons, 
            text = "Clear Output Field",
            command = lambda: self.handleButtonPress('__clear_output__'),
            width = 20)
        button_clear_output.grid(row=1, column=2, sticky='w', padx=5, pady=5)

        # Start Button
        self.button_start = ttk.Button(
            frame_controlbuttons, 
            text = "Generate Hash...",
            command = lambda: self.handleButtonPress('__start__'), 
            width = 20)
        self.button_start.grid(row=1, column=3, sticky='w', padx=5, pady=5)

        ################ Bottom Cache FRAME ##############
        frame_cachebuttons = ttk.Frame(frame_bottombuttons)
        frame_cachebuttons.pack(side=BOTTOM, fill=X, expand = True)
        frame_cachebuttons.config(relief = RIDGE, borderwidth = 2)

        # Print Cache Button
        button_cache = ttk.Button(frame_cachebuttons, 
            text = "Print Cache",
            command = lambda: self.handleButtonPress('__print_cache__'),
            width = 20)
        button_cache.grid(row=1, column=3, sticky='w', padx=5, pady=5)
        
        # Clear Cache Button
        self.button_clear_cache = ttk.Button(
            frame_cachebuttons, 
            text = "Clear Cache",
            command = lambda: self.handleButtonPress('__clear_cache__'), 
            width = 20)
        self.button_clear_cache.grid(row=1, column=4, sticky='w', padx=5, pady=5)

        # Checkbutton Use Cache File
        self.useCacheFile = IntVar()
        self.useCacheFile.set(1)
        self.cb_useCacheFile = Checkbutton(
            frame_cachebuttons, 
            text="Use File Cache:", 
            justify=LEFT, 
            variable = self.useCacheFile, 
            onvalue=1, 
            offvalue=0)
        self.cb_useCacheFile.grid(row=1, column=1, sticky='w', padx=3, pady=3)
        
        # Select Cache file button
        self.CacheFileButtonText = StringVar()
        self.CacheFileButtonText.set(DEFAULT_CACHE_FILE)
        self.button_select_cache_button = ttk.Button(
            frame_cachebuttons, 
            textvariable = self.CacheFileButtonText,
            command = lambda: self.handleButtonPress('__select_cache_file__'))
        self.button_select_cache_button.grid(row=1, column=2, sticky='w', padx=3, pady=3)
        
        #if self.useCacheFile.get() == 1: # Use Cache File
        #    self.button_clear_cache.state(["disabled"])
        #    self.button_clear_cache.config(state=DISABLED)
        # else:
        #    self.button_clear_cache.state(["!disabled"])
        #    self.button_clear_cache.config(state=not DISABLED)

        self.root.mainloop()
        
def exit_handler():
    logging.getLogger().info("==== epsig2_gui STOPPED/INTERRUPTED: " + str(datetime.now()) + " by: " + getpass.getuser()  + " ====")
 
def main():
    app = None
    logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s- %(message)s')    
    atexit.register(exit_handler)
    
    try: 
        # app = epsig2_gui()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future = executor.submit(epsig2_gui())   

    except KeyboardInterrupt:       
        logging.debug("Program Exiting.")
        app.root.quit()
        sys.exit(0)

if __name__ == "__main__": main()

