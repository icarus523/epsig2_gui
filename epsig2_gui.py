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
# v1.5 - separate hashing function (epsig2) from GUI
#       - separate Cache File as a separate class
#        - hashing function is now threaded

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

VERSION = "1.5"

EPSIG_LOGFILE = "epsig2.log"
MAXIMUM_BLOCKSIZE_TO_READ = 65535
DEFAULT_CACHE_FILE = "\\\Justice.qld.gov.au\\Data\\OLGR-TECHSERV\\TSS Applications Source\\James\\epsig2_cachefile_v2.json"
p_reset = "\x08"*8

## CacheFile class
class CacheFile(): 

    def __init__(self, fname):
        logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s- %(message)s')    

        self.user_cache_file = fname
        self.cache_dict = self.importCacheFile() # read file

    def importCacheFile(self):
        cache_data = ''
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
                logging.info("Generating new File Cache file:" + cache_location)
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
            logging.warning("\n**** WARNING **** Generating new Cache Sigs file\n") 
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

    def __init__(self, seed, filepath, options_d, cache_dict):
        logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s- %(message)s')
        self.seed = seed 
        self.bnk_filepath = filepath
        self.options_d = options_d
        self.mandir = os.path.dirname(self.bnk_filepath)
        self.cache_dict = cache_dict
        self.xor_result = ''
        self.LogOutput = list() 
        self.output = list() 
        self.user_cache_file = options_d['usr_cache_file']

    def checkCacheFilename(self, filename, seed_input, alg_input): # alg_input 
        # For filename_seed, concatenate to form unique string. 
        if filename in self.cache_dict.keys(): # a hit?
            data = self.cache_dict.get(filename) # now a list
            for item in data:
                # Check if Seed and Algorithm matches. 
                if item['seed'] == seed_input and item['alg'] == alg_input: 
                    verified_time = item['verify'] 
                    return(str(item['hash'])) # return Hash result
        else:
            return 0

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
    def dohash_hmacsha1(self, fname, chunksize=8192):
        # change this if you want other hashing types for HMAC, e.g. hashlib.md5
        key = bytes.fromhex(self.seed)
        m = hmac.new(key, digestmod = hashlib.sha1) 
        done = 0
        size = os.path.getsize(fname)
        # Read in chunksize blocks at a time
        with open(fname, 'rb') as f:
            while True:
                block = f.read(chunksize)
                done += chunksize
                sys.stdout.write("%7d"%(done*100/size) + "%" + p_reset)
                if not block: break
                m.update(block)      
        return m.hexdigest()
    
    def checkhexchars(self, text):
        return (all(c in string.hexdigits for c in text))            


    # limitations: currently only supports bnk file with SHA1 contents        
    def dobnk(self, fname, blocksize):
        time.sleep(1)
        cache_file = None
        if self.options_d['cache_file_f'] == True: # Use Cache File
            # Overwrite self.cache_dict with contents of file
            cache_file = CacheFile(self.user_cache_file) 
            self.cache_dict = cache_file.cache_dict

        oh = "0000000000000000000000000000000000000000"
        # Verify Seed is a number String format, and atleast 2 digits long 
        if (len(self.seed) < 2 or not self.checkhexchars(self.seed)):
            messagebox.showerror("Error in Seed Input",
                                 "Expected atleast two Hexadecimal characters as the Seed input" +
                                 ".\n\nCheck your Seed string again: " + self.seed)
            return -1
        else:
            try:
                logging.debug("Processing: " + fname +  "[" + str(threading.currentThread().getName()) + "]")

                with open(fname, 'r') as infile: 
                # infile = open(fname, 'r')
                    fdname = ['fname', 'type', 'blah']
                    reader = csv.DictReader(infile, delimiter=' ', fieldnames = fdname)

                    logging.debug("%-50s\tSEED" % (self.format_output(self.seed, self.options_d)))
                
                    for row in reader:
                        if row['type'].upper() == 'SHA1':
                            # check if the file exists
                            if (os.path.isfile(self.mandir + "/" + row['fname'])):

                                # The following should return a list    
                                cachedhit = self.checkCacheFilename(self.mandir + "/" + str(row['fname']), self.seed, row['type'].upper())
                                
                                if cachedhit:
                                    localhash = cachedhit
                                else: 
                                    new_cache_list = list()

                                    localhash = self.dohash_hmacsha1(self.mandir + "/" + 
                                        str(row['fname']), blocksize)

                                    seed_info = { 
                                        'seed': self.seed, 
                                        'alg': row['type'].upper(), 
                                        'verify':'0', 
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
                                    'hash': localhash })

                                # handle incorrect seed length
                                if localhash == 0:
                                    break # exit out cleanly

                                self.resulthash = self.format_output(str(localhash), self.options_d)
                                
                                oh = hex(int(oh,16) ^ int(str(localhash), 16)) # XOR'ed result
                                
                                outputstr = None
                                if cachedhit:
                                    outputstr = "%-50s\t%-s\t%-10s" % (self.format_output(str(localhash), 
                                        self.options_d), str(row['fname']), "(cached)")
                                else:
                                    outputstr = "%-50s\t%-s" % (self.format_output(str(localhash), self.options_d), 
                                        str(row['fname']))
                                
                                logging.debug(outputstr + "[" + str(threading.currentThread().getName()) + "]")
                                # self.output.append(outputstr)
                                
                            else: 
                                error_text =  "\n!!!!!!!!!!!!!! ERROR: Could not read file: " + str(row['fname']) + " in: " + fname + "\n\n"
                                logging.error("Could not read file: " + str(row['fname']) + " in: " + fname)
                                # self.output.append(error_text)
                        else: 
                            messagebox.showerror("Not Yet Implemented!", "Unsupported hash algorithm: " + row['type'].upper() + ".\n\nExiting. Sorry!")
                            logging.error('Unsupported hash algorithm: ' + row['type'])
                            # Need to implement CR16, CR32, PS32, PS16, OA4F and OA4R, and SHA256 if need be. 


            except KeyboardInterrupt:
                logging.debug("Keyboard interrupt during processing of files. Exiting")
                sys.exit(1)
            
        return { 'oh': oh, 'cache_dict' : self.cache_dict } 
    
    # Inserts spaces on [text] for every [s_range]
    def insert_spaces(self, text, s_range):
        return " ".join(text[i:i+s_range] for i in range(0, len(text), s_range))

    def format_output(self, inputstr, options_d):
        outputstr = ''

        # include a space for every eight chars
        if (options_d['eightchar'] == True):
            s_range = 8
            outputstr = " ".join(inputstr[i:i+s_range] for i in range(0, len(inputstr), s_range)) # self.insert_spaces(inputstr, 8)
        else: 
            outputstr = inputstr
        
        # uppercase
        if options_d['uppercase'] == True: 
            outputstr = outputstr.upper()
        
        # QCAS expected result
        if options_d['reverse'] == True:
            outputstr = self.getQCAS_Expected_output(outputstr)
        
        return outputstr

    def processfile(self, fname, chunks):
        time.sleep(1) 
        h = None

        #dobnk_output = self.dobnk(fname, chunks)
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future = executor.submit(self.dobnk, fname, chunks)
            dobnk_output = future.result()        

        h = dobnk_output['oh'] # output
        self.cache_dict = dobnk_output['cache_dict'] # update

        outstr = ''
        tmpStr = ''
        
        # display to screen
        #for item in self.LogOutput:
        #    logging.debug("\n" + json.dumps(item, sort_keys=True, indent=4, separators=(',', ': ')))

        style = ttk.Style()
        if h == -1: 
            return # handle error in seed input
        else:
            # self.text_BNKoutput.insert(END, "%-50s\t%s\n" % (str(h).zfill(40), "RAW output"))
            raw_outputstr = "%-50s\t%s" % (str(h).zfill(40), "RAW output")
            logging.debug(raw_outputstr + "[" + str(threading.currentThread().getName()) + "]")
            # self.output.append(raw_outputstr)

            #strip 0x first
            tmpStr = str(h).lstrip('0X').zfill(40) # forces 40 characters with starting 0 characters. 
            tmpStr = str(h).lstrip('0x').zfill(40)

            # style.configure('self.text_BNKoutput', fg='red') # RED text
            #self.text_BNKoutput.tag_add("alltext", END, len())
            #self.text_BNKoutput.tag_config("alltext", background="yellow", foreground="red")
            
            self.xor_result = self.format_output(tmpStr, self.options_d) # save result
            outputstr = "%-50s\t%s" % (str(self.xor_result), "XOR Formatted Result")
            # self.output.append(outputstr)
            logging.debug(outputstr + "[" + str(threading.currentThread().getName()) + "]")

    def writetoLogfile(self, filename, xor_result, bnkfile, multi_logf):
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
            for item in self.LogOutput:
                outfile.writelines("%40s \t %40s \t %-60s\n" % (self.format_output(str(item['seed']), self.options_d), 
                    self.format_output(str(item['hash']), self.options_d), item['filename']))
                my_seed = str(item['seed'])

            outfile.writelines("%40s \t %40s \t XOR\n" % (self.format_output(my_seed, self.options_d), 
                self.format_output(xor_result.replace(" ", ""), self.options_d)))

    def getQCAS_Expected_output(self, text):
        tmpstr = text[:8] # Returns from the beginning to position 8 of uppercase text
        return "".join(reversed([tmpstr[i:i+2] for i in range(0, len(tmpstr), 2)]))


class epsig2_gui():

    # Constructor
    def __init__(self):
        logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s- %(message)s')
        logging.debug('Start of epsig2_gui')
        
        self.bnk_filename = ''
        self.bnk_filepath = ''
        self.seed_filepath = ''
        self.bnk_filename_list = list()
        self.bnk_filelist = list()
        self.seed = ''
        self.user_cache_file = None
        self.cache_dict = {} # Clear cache_dict
        self.root = Tk()

        self.processes = list() 
        Thread(self.setupGUI()).start()        

    def getClubsQSIM_Expected_output(self, text): # Returns flipped bits of full length HMACSHA1 (60 Chars? )
        return "".join(reversed([text[i:i+2] for i in range(0, len(text), 2)]))

    def handleButtonPress(self, myButtonPress):
        
        if myButtonPress == '__selected_bnk_file__':
            if (os.name == 'nt'): # Windows OS
                tmp = filedialog.askopenfilenames(initialdir='G:\OLGR-TECHSERV\BINIMAGE')
            elif (os.name == 'posix'): # Linux OS
                tmp = filedialog.askopenfilenames(initialdir='.')
            else: 
                tmp = filedialog.askopenfilenames(initialdir='.')

            if tmp:
                self.textfield_SelectedBNK.delete(0, END)
                self.bnk_filelist = tmp
                for fname in self.bnk_filelist:
                    fname_basename = os.path.basename(fname)
                    self.bnk_filename_list.append(fname_basename)
                    self.textfield_SelectedBNK.insert(0, fname_basename + "; ")
                    
        elif myButtonPress == '__start__':
            if len(self.bnk_filelist) > 0: 
                for bnk_filepath in self.bnk_filelist:
                    logging.debug("Processing: " + bnk_filepath)
                    if (os.path.isfile(bnk_filepath)):                 
                        #if self.bnk_filename == '': 
                        self.bnk_filename = os.path.basename(bnk_filepath)
                        
                        self.mandir = os.path.dirname(bnk_filepath)

                        if (self.reverse.get() == 1): # reverse the seed.
                            self.seed = epsig2.getQCAS_Expected_output(self, self.combobox_SelectSeed.get())
                        else: 
                            self.seed = self.combobox_SelectSeed.get()

                        if (self.clubs_expected_output.get() == 1):
                            message = "\nQSIM reversed seed to use: " + self.getClubsQSIM_Expected_output(self.combobox_SelectSeed.get()) + "\n"
                            logging.debug(message)
                            self.text_BNKoutput.insert(END, message)

                        logging.debug("Seed is: " + self.seed)

                        # create process for hashing a file 

                        options_d = dict() 
                        options_d['cache_file_f'] = self.useCacheFile.get() == 1
                        options_d['uppercase'] = self.uppercase.get() == 1
                        options_d['eightchar'] = self.eightchar.get() == 1
                        options_d['reverse'] = self.reverse.get() == 1
                        options_d['usr_cache_file'] = self.CacheFileButtonText.get()

                        my_p = epsig2(self.seed, bnk_filepath, options_d, self.cache_dict) 
                        #threading.Thread(group=None, target=my_p.processfile(bnk_filepath, MAXIMUM_BLOCKSIZE_TO_READ)).start() 

                        # Create and launch a thread 
                        t = Thread(group=None, target=my_p.processfile, name=self.bnk_filename, args=(bnk_filepath, MAXIMUM_BLOCKSIZE_TO_READ, )) 
                        t.start()

                        # xor_result = self.processfile(bnk_filepath, MAXIMUM_BLOCKSIZE_TO_READ)
                    else: 
                        logging.warning(bnk_filepath + " does not exist")

                main_thread = threading.currentThread()
                for t in threading.enumerate(): 
                    if t is main_thread:
                        continue
                    logging.debug('joining %s', t.getName())
                    t.join()

                #for t in self.processes: 
                #    t.join() # wait for all threads to complete

                    # option to write to log selected.
                #    if self.writetolog.get() == 1:  
                #        my_p.writetoLogfile(EPSIG_LOGFILE, my_p.xor_result, bnk_filepath, self.logtimestamp.get() == 1)

                    # update gui
                #    for entry in my_p.output:
                #        self.text_BNKoutput.insert(END, entry+"\n")

                #   xor_result_output_str = '' 

                #    if self.reverse.get() == 1: 
                #        xor_result_output_str = "%-50s\tQCAS Expected Formatted Result\n" % (my_p.xor_result)
                #    else: 
                #        xor_result_output_str = "%-50s\tXOR Formatted Result\n" % (my_p.xor_result)
                    
                    # self.text_BNKoutput.insert(END, xor_result_output_str)
                #    logging.info("Processed: " + bnk_filepath + "\t" + xor_result_output_str)

            else:
                messagebox.showerror("BNK files not selected.", "Please select files first")
                logging.debug(str(len(self.bnk_filelist)))
        
        elif myButtonPress == '__clear_output__':
                self.text_BNKoutput.delete(1.0, END)
                
        elif myButtonPress == '__clear__':
                self.text_BNKoutput.delete(1.0, END)
                self.cb_reverse.deselect()
                self.bnk_filepath = ''
                self.bnk_filename = ''
                self.textfield_SelectedBNK.delete(0, END)
                self.reverse.set(0)
                self.mslcheck.set(0)
                self.cb_uppercase.deselect()
                self.cb_mslcheck.deselect()
                self.uppercase.set(0)
                self.eightchar.set(0)
                self.cb_eightchar.deselect()
                self.writetolog.set(0)
                self.logtimestamp.set(0)
                self.clubs_expected_output.set(0)
                self.label_SeedPath.configure(text="No SL1/MSL Seed file selected") 
                self.combobox_SelectSeed.set('0000000000000000000000000000000000000000')
                self.combobox_SelectSeed['values'] = ()
                self.bnk_filename_list = list()
                self.bnk_filelist = list()
                self.useCacheFile.set(0)
                self.CacheFileButtonText.set(DEFAULT_CACHE_FILE)
                self.user_cache_file = None
                self.processes = list()
                
        elif myButtonPress == '__clear_cache__':
                if self.user_cache_file:
                    cache_location = self.user_cache_file
                else: 
                    cache_location = DEFAULT_CACHE_FILE
                    
                logging.info("\nCleared local RAM cache only. \nFile cache not modified: " + cache_location)
                if self.useCacheFile.get() == 1: # Use Cache File
                    cache_file = CacheFile(self.user_cache_file) # read cache file
                    self.cache_dict = cache_file.cache_dict # Overwrite self.cache_dict with contents of file
                else:
                    self.cache_dict = {} # empty_cache_data # Clear cache_dict

                self.processes = list()


        elif myButtonPress == '__print_cache__':
                self.text_BNKoutput.insert(END, "\nCache Entries: ")
                if self.useCacheFile.get() == 1: # Use Cache File
                    cache_file = CacheFile(self.CacheFileButtonText.get())
                    self.cache_dict = cache_file.cache_dict # Overwrite self.cache_dict with contents of file

                message = json.dumps(self.cache_dict, sort_keys=True, indent=4, separators=(',',':'))                    
                self.text_BNKoutput.insert(END, message + "\n")


        elif myButtonPress == '__select_cache_file__':
                input_cachefile_dir = filedialog.askdirectory(initialdir='.', title='epsig2_cachefile.json')
                self.CacheFileButtonText.set(os.path.join(input_cachefile_dir,"epsig2_cachefile_v2.json"))
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
            sys.exit(1)                 

    def setupGUI(self):
        self.root.wm_title("epsig2 BNK file v" + VERSION)
        self.root.resizable(1,1)
        
        ## Top Frame
        frame_toparea = ttk.Frame(self.root)
        frame_toparea.pack(side = TOP, fill=X, expand=False)
        frame_toparea.config(relief = RIDGE, borderwidth = 0)
        
        label_Heading = ttk.Label(frame_toparea, justify=LEFT, text = 'GUI script to process BNK files (Supports only HMAC-SHA1)')
        label_Heading.grid(row=0, column=0, padx=3, pady=3, sticky='n')

        ## BNK Selection Frame
        frame_bnkSelectionFrame = ttk.Frame(frame_toparea)
        frame_bnkSelectionFrame.config(relief = RIDGE, borderwidth = 1)
        frame_bnkSelectionFrame.grid(row=1, column=0, padx=3, pady=3, sticky='w')

        # Button Selected BNK file
        button_SelectedBNKfile = ttk.Button(frame_bnkSelectionFrame, text = "Select BNK file...", width = 20,
                                                      command = lambda: self.handleButtonPress('__selected_bnk_file__'))                                             
        button_SelectedBNKfile.grid(row=1, column=0, padx=5, pady=5, sticky='w')
        
        # Text Entry Selected BNK file
        self.textfield_SelectedBNK = ttk.Entry(frame_bnkSelectionFrame, width = 72)
        self.textfield_SelectedBNK.grid(row=1, column=1, sticky='w', padx=5, pady=5)

        ## Seed Frame Area
        frame_SeedFrame = ttk.Frame(frame_toparea) 
        frame_SeedFrame.config(relief = RIDGE, borderwidth = 0)
        frame_SeedFrame.grid(row=2, column=0, padx=3, pady=3)

        frame_SelectSeed = ttk.Frame(frame_SeedFrame)
        frame_SelectSeed.config(relief= RIDGE, borderwidth = 1)
        frame_SelectSeed.grid(row=0, column=0, padx=3, pady=3) #(side=TOP, fill=BOTH, expand=False)

        # Button Selected Seed file (sl1)
        button_Selectedsl1file = ttk.Button(frame_SelectSeed, 
            text = "Seed or SL1/MSL file...", width = 20, 
            command = lambda: self.handleButtonPress('__selected_seed_file__'))                                             
        button_Selectedsl1file.grid(row=0, column=0, padx=5, pady=5, sticky='w')

        # Combo Box for Seeds, default to 0x00
        self.box_value = StringVar()
        self.combobox_SelectSeed = ttk.Combobox(frame_SelectSeed, 
            justify=LEFT, 
            textvariable=self.box_value, 
            width = 70)
        self.combobox_SelectSeed.grid(row=0, column=1, sticky='w', padx=5, pady=5)
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
        self.cb_mslcheck.grid(row=0, column=2, sticky='w',)
        
        # Text Label sl1 location
        self.label_SeedPath = ttk.Label(frame_SeedFrame, 
            text = 'No SL1/MSL Seed File Selected', width = 80)
        self.label_SeedPath.grid(row=3, column=0, padx=5, pady=5, sticky = 'w')

        ######################### MIDDLE FRAME
        frame_middleframe = ttk.Frame(self.root)
        frame_middleframe.pack(side = TOP, fill=BOTH, expand=True)

        # Need to use .pack() for scrollbar and text widget
        frame_textarea = ttk.Labelframe(frame_middleframe, text="Output Field")
        frame_textarea.pack(side = LEFT, fill=BOTH, expand=True)
        frame_textarea.config(relief = RIDGE, borderwidth = 2)

        # Text Area output of BNK file generation
        self.text_BNKoutput = Text(frame_textarea, height=30)
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
        self.eightchar.set(1)
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
        frame_bottombuttons.config(relief = RIDGE, borderwidth = 1)

        ################ Bottom Control FRAME ##############
        frame_controlbuttons = ttk.Frame(frame_bottombuttons)
        frame_controlbuttons.pack(side=TOP, fill=X, expand = True)
        frame_controlbuttons.config(relief = None, borderwidth = 1)
        
        # Clear Button
        self.button_clear = ttk.Button(
            frame_controlbuttons, 
            text = "Clear Form", 
            command = lambda: self.handleButtonPress('__clear__'), 
            width = 15)
        self.button_clear.grid(row=1, column = 1, padx=5, pady=5, sticky='w',)

        # Clear Output
        button_clear_output = ttk.Button(
            frame_controlbuttons, 
            text = "Clear Output Field",
            command = lambda: self.handleButtonPress('__clear_output__'),
            width = 16)
        button_clear_output.grid(row=1, column=2, sticky='w', padx=5, pady=5)

        # Start Button
        self.button_start = ttk.Button(
            frame_controlbuttons, 
            text = "Generate Hash...",
            command = lambda: self.handleButtonPress('__start__'), 
            width = 16)
        self.button_start.grid(row=1, column=3, sticky='w', padx=5, pady=5)

        ################ Bottom Cache FRAME ##############
        frame_cachebuttons = ttk.Frame(frame_bottombuttons)
        frame_cachebuttons.pack(side=BOTTOM, fill=X, expand = True)
        frame_cachebuttons.config(relief = None, borderwidth = 1)

        # Print Cache Button
        button_cache = ttk.Button(frame_cachebuttons, 
            text = "Print Cache",
            command = lambda: self.handleButtonPress('__print_cache__'),
            width = 15)
        button_cache.grid(row=1, column=3, sticky='w', padx=5, pady=5)
        
        # Clear Cache Button
        self.button_clear_cache = ttk.Button(
            frame_cachebuttons, 
            text = "Clear Local Cache",
            command = lambda: self.handleButtonPress('__clear_cache__'), 
            width = 18)
        self.button_clear_cache.grid(row=1, column=4, sticky='w', padx=5, pady=5)

        # Checkbutton Use Cache File
        self.useCacheFile = IntVar()
        self.useCacheFile.set(0)
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
        
        if self.useCacheFile.get() == 1: # Use Cache File
            self.button_clear_cache.state(["disabled"])
            self.button_clear_cache.config(state= DISABLED)
        else:
            self.button_clear_cache.state(["!disabled"])
            self.button_clear_cache.config(state=not DISABLED)

        self.root.mainloop()
        
def exit_handler():
    logging.getLogger().info("==== epsig2_gui STOPPED/INTERRUPTED: " + str(datetime.now()) + " by: " + getpass.getuser()  + " ====")
 
def main():
    app = None
    logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s- %(message)s')    
    atexit.register(exit_handler)
    
    try: 
        app = epsig2_gui()

    except KeyboardInterrupt:       
        logging.debug("Program Exiting.")
        app.root.quit()
        sys.exit(0)

if __name__ == "__main__": main()

