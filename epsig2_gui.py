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
#       - Now includes unit tests, to excercise the functions being utilised
#       - Output to Output Field, has been changed to the format: <SEED>/t<HASH>/t<FNAME> - 
#       - GUI has been standardised: button sizes, padding, relief, etc.
# v1.6  - utilise epsig.exe as a sanity check. 
#       - test for spaces in BNK file names
#       - test for other incorrect BNK file formats
#       - Updated GUI to add option to enable/disable epsig.exe file format checks.
# v2.0  - utilises epsig.exe to perform BNK file format checks and hashes
# v2.1  - addressed issue with output stripping starting '0'
#       - now can log back to files for BIN/BNK files, including separate log files. 
#       - added support to disable epsig.exe for BNK files (if needed)
#       - if separate log files are used, the script will sign the log file which can also be verified with a new function in the Options menu
#       - log files are now named in the format: MANUFACTURER-BIN/BNK FILENAME-TIMESTAMP.log
#       - epsig.exe is now verbose - refer logging.
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
import re
import subprocess

from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from tkinter import filedialog
from threading import Thread
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait, as_completed

from subprocess import PIPE, Popen
from queue import Queue, Empty

from epsig2 import epsig2, CacheFile, BNKEntry, Seed, DEFAULT_CACHE_FILE

VERSION = "2.1"

EPSIG_LOGFILE = "epsig2.log"
MAXIMUM_BLOCKSIZE_TO_READ = 65535

DEFAULT_STR_LBL_SEED_FILE = "Details of Seed File: <No SL1/MSL Seed File Selected>"

p_reset = "\x08"*8

EPSIGEXE_PATH = 'G:/OLGR-TECHSERV/BINIMAGE/epsig3_7.exe'

## epsig2_gui class
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
        self.sign_log_files = True # hard code this here

        Thread(self.setup_gui()).start()        

    def verify_signed_logfile(self): 
        fname = filedialog.askopenfilename(initialdir='epsig2-logs', defaultextension='.log')
        if not fname: return
        try:
            Thread(target=self.verifyfile(fname)).start()
        except Exception as e: 
            raise
            tk.messagebox("Error loading file", "Unable to open filename" + fname)

    def stripfile(self, fname, outfile="tmp.txt"):
        # delete existing file
        if os.path.isfile(outfile): 
            os.remove(outfile)

        with open(fname,'r') as oldfile, open(outfile, 'w+') as newfile:
            for line in oldfile:
                if line.startswith('#'):
                    continue # skip 
                newfile.write(line)
        return outfile

    def verifyfile(self, fname):
        h = epsig2.dohash_sha256(self, self.stripfile(fname))
        logging.info("Signed log file to be verified: " + fname)
        logging.info("SHA256 Hash Recalculated: " + str(h).upper())
        # We uppercase in Written SIGS file, make sure you uppercase before comparing
        if h.upper() in open(fname).read(): # HAX0Rs
            messagebox.showinfo("File Verified!", "Calculated Hash:" + h.upper() 
                + ",\nMatches with expected Hash.")
            logging.info("Signed log file: Verified")
        else: 
            messagebox.showinfo("File Unverifiable!", "Calculated SHA256 Hash:" 
                + h.upper() + ",\nDid not matches with expected Hash\n\nFAIL!")
            logging.error("Signed log file: Unverified")    
       
    def verify_file_exists(self, fname): 
        mandir = os.path.dirname(fname)
        rv = False
        if os.path.isfile(fname) and fname.endswith(".BNK"): 
            with open(fname, 'r', encoding='utf-8') as bnkfile: 
                f = csv.reader(bnkfile, delimiter=' ')
                try: 
                    for line in f: 
                        logging.info("BNKEntry: " + BNKEntry(line).toJSON()) # parse BNK for errors
                    rv = True
                except csv.Error as e: 
                    # sys.exit('fname %s, line %d: %s' % (fname, f.line_num, e))  
                    msg = "*** ERROR: " + fname + " cannot be read from disk"
                    logging.error(msg)                             
        elif os.path.isfile(fname): # BIN files and others
            rv = True
        else: 
            return False

        return rv

    def epsigexe_start(self, fname, seed): 
        if not os.path.isfile(EPSIGEXE_PATH):
            logging.error("epsig.exe cannot be found in: " + EPSIGEXE_PATH)
            return None

        if ' ' in os.path.basename(fname): 
            logging.error("no spaces allowed in filename: " + os.path.basename(fname))
            return None

        # the following will block
        proc = subprocess.run([EPSIGEXE_PATH, fname, seed], capture_output=True) #stdout=subprocess.PIPE

        err = proc.stderr.decode('utf-8')
        stdout = proc.stdout.decode('utf-8').split("\r\n")
        stdout = [i for i in stdout if i] # remove empty strings 
        
        result_l = list() 
        for row in stdout: 
            if row.startswith('Hash'): 
                result_l.append(row)

        # convert epsig.exe output to a dict
        rv = dict() 
        rv['err'] = err
        rv['stdout'] = stdout
        rv['results'] = result_l

        hash_results_l = list() 
        for item in rv['results']:
            results = item.split(' ')
            hash_results_l.append(results[2])

        rv['returncode'] = proc.returncode == 0

        if fname.upper().endswith('BNK') and rv['returncode'] == True: 
            rv['hash_result'] = hash_results_l[1]   # return result

        return rv

    def enqueue_output(self, out, queue):
        for line in iter(out.readline, b''):
            queue.put(line)
        out.close()

    def epsigexe_start2(self, fname, seed): 
        ON_POSIX = 'posix' in sys.builtin_module_names

        if not os.path.isfile(EPSIGEXE_PATH):
            logging.error("epsig.exe cannot be found in: " + EPSIGEXE_PATH)
            return None

        if ' ' in os.path.basename(fname): 
            logging.error("no spaces allowed in filename: " + os.path.basename(fname))
            return None

        # the following will block
        # proc = subprocess.run([EPSIGEXE_PATH, fname, seed], capture_output=True) #stdout=subprocess.PIPE

        proc = Popen([EPSIGEXE_PATH, fname, seed], stdout=PIPE, stderr=PIPE, bufsize=1, close_fds=ON_POSIX)
        q = Queue()
        t = Thread(target=epsig2_gui.enqueue_output, args=(self, proc.stdout, q))
        t.daemon = True # thread dies with the program
        t.start()

        output_l = list() 
        complete = False 
        epsig_exe_fail = False
        while not complete: 
            time.sleep(1)
            # read line without blocking
            try:  
                line = q.get_nowait() # or q.get(timeout=.1)
            except Empty:
                print('.', end='')
            else: # got line
                # decode & clean
                s = line.decode('utf-8').strip()
                logging.info("epsig.exe: " + s)
                output_l.append(s) 
                if s.endswith("(LSB First i.e. HMAC-SHA1)"): 
                    complete = True
                # handle all epsig.exe fails. 
                if 'Critical' in s: 
                    complete = True 
                    epsig_exe_fail = True
                    err = "epsig.exe: Critical! refer to logging for more info"
        
        result_l = list() 
        if not epsig_exe_fail: 
            for row in output_l: 
                if row.startswith('Hash'): 
                    result_l.append(row)

        # convert epsig.exe output to a dict
        rv = dict() 
        rv['err'] = err
        rv['stdout'] = output_l 
        rv['results'] = result_l

        hash_results_l = list() 
        for item in rv['results']:
            results = item.split(' ')
            hash_results_l.append(results[2])

        # dummy up returncode from epsig.exe
        if not epsig_exe_fail and len(hash_results_l[0]) > 0 and len(hash_results_l[1]) > 0: # i.e. two results
            rv['returncode'] = True 
        else:
            rv['returncode'] = False

        if fname.upper().endswith('BNK') and rv['returncode'] == True: 
             rv['hash_result'] = hash_results_l[1]   # return result

        return rv

    def write_to_logfile2(self, filename, epsig2exe_d, bnkfile, multi_logf):
        #timestamp = datetime.timestamp(datetime.now())
        timestamp_f = datetime.today().isoformat().replace(":","-")
        outputfile = ''
        outputdir = 'epsig2-logs'

        #if self.logtimestamp.get() == 1: # Multi log files not overwritten saved in different directory
        if multi_logf == True: 
            if not os.path.exists(outputdir):
                os.makedirs(outputdir)
            # generate outputfile filename
            head, bnk_filename = os.path.split(bnkfile)
            manufacturer = head.split('/')[3] 
            outputfile = outputdir + "/" + manufacturer + "-" + bnk_filename[:-4] + "-" + str(timestamp_f) + ".log"

        else: # Single log file that's appended to
            outputfile = filename

        with open(outputfile, 'a+') as outfile:
            outfile.writelines("---8<-----------GENERATED: " + 
                # str(datetime.fromtimestamp(timestamp)) + " --------------------------\n")
                timestamp_f +  " by: " + getpass.getuser()  +  " --------------------------\n")
            outfile.writelines("Processsed: " + bnkfile + "\n")
            # outfile.writelines("%40s \t %40s \t %60s\n" % ("SEED", "HASH", "FILENAME"))

            outfile.writelines("%-40s\t%-65s\t%-60s\n" % ("Seed", "Hash", "Filename"))
            outfile.writelines("%40s\t%65s\t%-60s\n" % (
                epsig2.format_output(self, self.seed.seed, self.gui_get_options()), 
                epsig2.format_output(self, epsig2exe_d['hash_result'], self.gui_get_options()), 
                os.path.basename(bnkfile)))

        if multi_logf == True and self.sign_log_files == True: 
            self.signfileoutput(outputfile, outputfile)

    def signfileoutput(self, infile, outfile):
        h = epsig2.dohash_sha256(self, infile)
        if h:
            self.appendfileoutput(h, outfile)

    def appendfileoutput(self, signature, outfile):   
        logging.info('Signed log file hash: ' + signature.upper())             
        with open (outfile, 'a') as f:
            f.write("#---8<---------------------------------START--------------------------------------------\n")
            f.write("# Remove this section to verify hash for: " + os.path.basename(outfile) + "\n")
            f.write("# SHA256 hash: " + signature.upper() + "\n")
            f.write("# IMPORTANT! To reconcile make sure there's an empty line at the bottom of this text file\n")
            f.write("# ---------------------------------------END------------------------------------->8------")

    def write_to_logfile(self, filename, epsig2_p, bnkfile, multi_logf):
        # timestamp = datetime.timestamp(datetime.now())
        timestamp_f = datetime.today().isoformat().replace(":","-")

        outputfile = ''
        outputdir = 'epsig2-logs'
        
        #if self.logtimestamp.get() == 1: # Multi log files not overwritten saved in different directory
        if multi_logf == True: 
            if not os.path.exists(outputdir):
                os.makedirs(outputdir)            
            head, bnk_filename = os.path.split(bnkfile)
            manufacturer = head.split('/')[3] 

            outputfile = outputdir + "/" + manufacturer + "-" + bnk_filename[:-4] + "-" + str(timestamp_f) + ".log"
        else: # Single log file that's overwritten
            outputfile = filename

        with open(outputfile, 'a+') as outfile:
            outfile.writelines("---8<-----------GENERATED: " + 
                #  str(datetime.fromtimestamp(timestamp)) + " --------------------------\n")
                timestamp_f +  " by: " + getpass.getuser()  +  " --------------------------\n")
            outfile.writelines("Processsed: " + bnkfile + "\n")
            # outfile.writelines("%40s \t %40s \t %60s\n" % ("SEED", "HASH", "FILENAME"))
            my_seed = ''
            outfile.writelines("%-40s\t%-65s\t%-60s\n" % ("Seed", "Hash", "Filename"))
            for item in epsig2_p.LogOutput:
                outfile.writelines("%40s\t%65s\t%-60s\n" % (epsig2.format_output(self, str(item['seed']), self.gui_get_options()), 
                    epsig2.format_output(self, str(item['hash']), self.gui_get_options()), item['filename']))
                my_seed = str(item['seed'])

            if epsig2_p.filepath.upper().endswith('.BNK'): 
                outfile.writelines("%40s\t%65s\tXOR\n" % (epsig2.format_output(self, my_seed, self.gui_get_options()), 
                    epsig2.format_output(self, epsig2_p.xor_result.replace(" ", ""), self.gui_get_options())))
            else: 
                outfile.writelines("%40s\t%65s\tFormatted Output\n" % (epsig2.format_output(self, my_seed, self.gui_get_options()), 
                    epsig2.format_output(self, epsig2_p.xor_result.replace(" ", ""), self.gui_get_options())))

        if multi_logf == True and self.sign_log_files == True: 
            self.signfileoutput(outputfile, outputfile)

    # Returns flipped bits of full length
    def getClubsQSIM_Expected_output(self, text): 
        return "".join(reversed([text[i:i+2] for i in range(0, len(text), 2)]))

    # Generates the Seed object everytime the "start" button is pressed. 
    def get_seed_text(self):
        tmp_seed = ''
        # reverse the seed.
        if (self.reverse.get() == 1): 
            tmp_seed = epsig2.getQCAS_Expected_output(self, self.combobox_SelectSeed.get())
        else: 
            tmp_seed = self.combobox_SelectSeed.get()

        self.seed = Seed(tmp_seed, self.selectedHashtype.get())

    def gui_get_options(self): 
        options_d = dict() 
        options_d['cache_file_f'] = self.useCacheFile.get() == 1
        options_d['uppercase'] = self.uppercase.get() == 1
        options_d['eightchar'] = self.eightchar.get() == 1
        options_d['reverse'] = self.reverse.get() == 1
        options_d['usr_cache_file'] = self.CacheFileButtonText.get()        
        options_d['selectedHashtype'] = self.selectedHashtype.get()
        options_d['use_epsigexe'] = self.use_epsigexe.get() == 1

        return options_d

    # refer: https://stackoverflow.com/questions/38987/how-do-i-merge-two-dictionaries-in-a-single-expression
    def merge_two_dicts(self, x, y):
        z = x.copy()   # start with x's keys and values
        z.update(y)    # modifies z with y's keys and values & returns None
        return z

    # returns Hashstring or None (if faiiled)
    def check_cache_filename(self, filename, seed_input): # alg_input 
        # For filename_seed, concatenate to form unique string. 
        if filename in self.cache_dict.keys(): # a hit?
            data = self.cache_dict.get(filename) # now a list
            for item in data:
                # Check if Seed and Algorithm matches. 
                if item['seed'] == seed_input: 
                    # verified_time = item['verify'] 
                    return(str(item['hash'])) # return Hash result
        
        return None    

    def start_epsig_gui(self, filepath): 
        #futures = list() 
        #pool = ThreadPoolExecutor(len(self.filelist)) # one thread per file     
        self.bnk_filename = os.path.basename(filepath)
        self.mandir = os.path.dirname(filepath)

        self.get_seed_text() 

        if (self.clubs_expected_output.get() == 1):
            message = "\nQSIM reversed seed to use: " + self.getClubsQSIM_Expected_output(self.seed.seed) + "\n"
            logging.info(message)
            self.text_BNKoutput.insert(END, message)

        if self.gui_get_options()['cache_file_f'] == True: # Use Cache File
            # Overwrite self.cache_dict with contents of file
            cache_file = CacheFile(self.user_cache_file) 
            self.cache_dict = cache_file.cache_dict


        cachedhit = self.check_cache_filename(filepath, self.seed.seed)        
        if cachedhit != None: 
            localhash = cachedhit
            epsigexe_output = {} 
            self.filepath = filepath

            # need to log if cache hit? 
        else: 
            new_cache_list = list()
            if filepath.upper().endswith('BNK'): 
                # BNK file
                if self.use_epsigexe.get() == 1: 
                    epsigexe_output = self.epsigexe_start2(filepath, self.seed.seed)
                    if epsigexe_output and epsigexe_output['returncode'] == True:
                        localhash = epsigexe_output['hash_result']

                        seed_info = { 
                            'seed': self.seed.seed, 
                            'hash': localhash 
                        }        

                        cache_entry_list = self.cache_dict.get(self.mandir + "/" + self.bnk_filename) # Should return a list. 
                        if cache_entry_list : 
                            # File Entry Exists, append to list
                            cache_entry_list.append(seed_info) # print this
                            self.cache_dict[self.mandir + "/" + self.bnk_filename] = cache_entry_list # keep unique
                        else:  
                            # No File Entry Exits generate new list entry in cache_dict
                            new_cache_list.append(seed_info)
                            self.cache_dict[self.mandir + "/" + self.bnk_filename] = new_cache_list # keep unique
                        
                        if self.gui_get_options()['cache_file_f'] == True:
                            cache_file.updateCacheFile(self.cache_dict) # Update file cache
                        else: 
                            self.cache_dict[self.mandir + "/" + self.bnk_filename] = new_cache_list # update local cache

                        for result in epsigexe_output['results']: # log epsig3_7.exe output to log file
                            logging.info("epsig.exe: " + result) 

                        logging.info("epsig.exe: " + filepath + " format is correct.")   
                        localhash = epsigexe_output['hash_result']
                        self.filepath = filepath
                    else: 
                        messagebox.showerror("epsig.exe returncode = error", "Please check contents of the BNK file: " + filepath)
                        localhash = '' # return empty string to force error. 
                        msg = "epsig.exe: " + os.path.basename(filepath) + " format error. The file is not formatted as expected. Check the file contents for errors\n\n"
                        self.text_BNKoutput.insert(END, "*** epsig.exe error: " + epsigexe_output['err'] + "\n" + msg)                                    
                        logging.error(msg)
                        # need to provide error dialogue here
                        self.filepath = None

                    # def write_to_logfile2(self, filename, epsig2exe_d, bnkfile, multi_logf):
                    if self.filepath and self.writetolog.get() == 1: 
                        self.write_to_logfile2(EPSIG_LOGFILE, epsigexe_output, self.filepath, self.logtimestamp.get() == 1)                

                else: 
                    # use epsig2.py to calculate BNK file hashes
                    my_p = epsig2(self.seed.seed, filepath, self.gui_get_options(), self.cache_dict, str(self.selectedHashtype.get()), False) 
                    my_p.processfile()
                    self.cache_dict = self.merge_two_dicts(self.cache_dict, my_p.cache_dict)

                    localhash = my_p.xor_result
                    self.filepath = filepath

                    if self.writetolog.get() == 1: 
                        self.write_to_logfile(EPSIG_LOGFILE, my_p, filepath, self.logtimestamp.get() == 1)      

            else: 
                # BIN file, use epsig2 (i.e. python shasums)
                my_p = epsig2(self.seed.seed, filepath, self.gui_get_options(), self.cache_dict, str(self.selectedHashtype.get())) 
                my_p.processfile()

                # update dict() 
                self.cache_dict = self.merge_two_dicts(self.cache_dict, my_p.cache_dict)

                localhash = my_p.xor_result
                self.filepath = filepath

                if self.writetolog.get() == 1: 
                    self.write_to_logfile(EPSIG_LOGFILE, my_p, filepath, self.logtimestamp.get() == 1)                

        if len(localhash) > 0 and self.filepath != None: 
            self.update_GUI_epsigexe(localhash)        
            if cachedhit:
                outputstr = "%-50s\t%-s\t%-10s" % (epsig2.format_output(self, str(localhash), 
                    self.gui_get_options()), os.path.basename(self.filepath), "(cached)")
            else:
                outputstr = "%-50s\t%-s\t" % (epsig2.format_output(self, str(localhash), self.gui_get_options()), 
                    os.path.basename(self.filepath))
            
            logging.debug(outputstr + "[" + str(threading.currentThread().getName()) + "]")

    def update_GUI_epsigexe(self, hash_result): 
        self.text_BNKoutput.insert(END, "\nProcessing: " + self.filepath + "\n")            
        # logging.info("Seed is: " + self.seed.seed + " length is: " + str(len(self.seed.seed)))
        if self.filepath.upper().endswith('.BNK'): 
            self.text_BNKoutput.insert(END, "XOR Result: " + "\n")
        else:
            self.text_BNKoutput.insert(END, "Formatted Result: " + "\n")           

        # Format seed and XOR/Formatted Result
        seed_output = epsig2.format_output(self, self.seed.seed, self.gui_get_options())
        str_output = epsig2.format_output(self, hash_result, self.gui_get_options())

        self.text_BNKoutput.insert(END, seed_output + "\t" + str_output + "\t" + os.path.basename(self.filepath + "\n"))
    
    def handle_button_press(self, myButtonPress):
        
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
                    
                    if not self.verify_file_exists(fname):
                        msg = "**** ERROR: " + fname + " cannot be read check contents"
                        self.text_BNKoutput.insert(END, msg)
                        logging.error(msg)
        
        elif myButtonPress == '__start__':
            if len(self.filelist) > 0: 
                for filepath in self.filelist:
                    logging.info("Processing: " + filepath)
                    if (os.path.isfile(filepath)):  
                        self.start_epsig_gui(filepath)                            
                    else: 
                        logging.warning(filepath + " does not exist")
                        messagebox.showerror(filepath + " does not exist", "Error in file selection")
            else:
                # try reading the text box if file exits: 
                tmp_fname = self.textfield_SelectedBNK.get() 
                if os.path.isfile(tmp_fname): 
                    self.start_epsig_gui(tmp_fname)
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
                self.writetolog.set(1)
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
                self.use_epsigexe.set(1) 

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
                    tmp = filedialog.askopenfile(initialdir='G:/OLGR-TECHSERV/MISC/BINIMAGE/qcas')
                else: 
                    tmp = filedialog.askopenfile(initialdir='S:/cogsp/docs/data_req/download/master') # put S:\ dir here. 
            elif (os.name == 'posix'): # Linux OS (my dev box)
                tmp = filedialog.askopenfile(initialdir='.')
            else: 
                tmp = filedialog.askopenfile(initialdir='.')
                
            if tmp: # Selected something
                self.seed_filepath = tmp.name
                self.get_combobox_values(self.seed_filepath)
                
                # Generate Year and Date based on numbers extracted
                sl1date = datetime.strptime(self.sl1_year + "/" + self.sl1_month, "%Y/%m")
                self.label_SeedPath.configure(text="Seed File: " + sl1date.strftime("(%b %Y)") + ": " + self.seed_filepath) 

    def process_SL1_file(self, fname): 
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

    def get_combobox_values(self, fname):
        if (os.path.isfile(fname)):
            self.combobox_SelectSeed['values'] = self.process_SL1_file(fname)
        else:
            messagebox.showerror("Expected SL1 or MSL file to Process", fname + " is not a valid seed file")
            # sys.exit(1)                 

    def about_window(self):
        about_script = "Version: v" + VERSION + " by aceretjr\n Python3 script for processing BNK and BIN files."
        messagebox.showinfo("About This Script", about_script)

    def select_hash_type(self, value): 
        self.selectedHashtype.set(value)

    def seed_selection(self):
        logging.info(self.box_value.get())

    def setup_gui(self):
        self.root.wm_title("epsig2 BNK/BIN file hashing tool v" + VERSION)
        self.root.resizable(1,1)

        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        optionmenu = tk.Menu(menubar, tearoff=0)
        helpmenu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=filemenu)
        menubar.add_cascade(label="Option", menu=optionmenu)
        menubar.add_cascade(label="Help", menu=helpmenu)
        filemenu.add_command(label="Exit", command=self.root.destroy)
        helpmenu.add_command(label="About...", command=self.about_window)
        #optionmenu.add_command(label="Preferences...", command=self.MenuBar_Config) # start this script now. 
        optionmenu.add_command(label="Verify signed log file...", command=self.verify_signed_logfile) # start this script now. 
        
        self.root.config(menu=menubar)
        
        ######## Top Frame
        frame_toparea = ttk.Frame(self.root)
        frame_toparea.pack(side = TOP, fill=X, expand=False)
        frame_toparea.config(relief = None, borderwidth = 2)

        frame_toparea2 = ttk.Frame(frame_toparea)
        frame_toparea2.pack(side = TOP, fill=X, expand=False)
        frame_toparea2.config(relief = None, borderwidth = 2)
        
        ttk.Label(frame_toparea2, justify=LEFT,
                                  text = 'GUI script to process BNK/BIN files (utilising epsig3_7.exe) - Please Select: ').pack(side=LEFT, padx=3, pady=3, fill=Y, expand=False, anchor='w')

        self.selectedHashtype = StringVar()
        optionMenuHashType = OptionMenu(frame_toparea2, self.selectedHashtype, 'HMAC-SHA1', 'HMAC-SHA256', command=self.select_hash_type).pack(side=LEFT, padx=3, pady=3, fill=X, expand=False, anchor='w')
        self.selectedHashtype.set("HMAC-SHA1")

        ######## BNK Selection Frame
        frame_bnkSelectionFrame = ttk.Frame(frame_toparea)
        frame_bnkSelectionFrame.config(relief = RIDGE, borderwidth = 2)
        frame_bnkSelectionFrame.pack(side = TOP, padx  = 3, pady = 3, expand = False, fill=X, anchor = 'w')       

        button_SelectedBNKfile = ttk.Button(frame_bnkSelectionFrame, text = "Select BNK/BIN file...", width=20, 
                                                      command = lambda: self.handle_button_press('__selected_bnk_file__'))                                             
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
            command = lambda: self.handle_button_press('__selected_seed_file__'))                                             
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

        # Text Label epsig.exe
        self.label_epsigexe = ttk.Label(frame_toparea, 
            text = EPSIGEXE_PATH + "\t:\t" + str(os.path.isfile(EPSIGEXE_PATH)), width = 80)
        self.label_epsigexe.pack(side=BOTTOM, fill=X, padx = 3, pady = 3, expand=True)
        
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
        frame_checkbuttons = ttk.Labelframe(frame_middleframe, text="Configurations")
        frame_checkbuttons.pack(side = RIGHT, fill=Y, expand = False)
        frame_checkbuttons.config(relief = RIDGE, borderwidth = 2)
        
        # Text Label sl1 location
        self.label_OutputOptions = ttk.Label(frame_checkbuttons, 
            text = "Display options: ")
        self.label_OutputOptions.grid(row=1, column=1, sticky='w',)

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
        self.cb_reverse.grid(row=2, column=1, sticky='w')

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
        self.cb_clubs_expected_output.grid(row=3, column=1, sticky='w')

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
        self.cb_uppercase.grid(row=4, column=1, sticky='w')

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
        self.cb_eightchar.grid(row=5, column=1, sticky='w',)

        ###################################################################
        # Other Settings

        # Text Label sl1 location
        self.label_Other = ttk.Label(frame_checkbuttons, 
            text = "Other Settings: ")
        self.label_Other.grid(row=6, column=1, sticky='w',)

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
        self.cb_writetolog.grid(row=7, column=1, sticky='w',)

        # Timestamp logs
        self.logtimestamp = IntVar()
        self.logtimestamp.set(0)
        self.cb_logtimestamp = Checkbutton(
            frame_checkbuttons, 
            text="Multiple Log Files: 'epsig2-logs/'", 
            justify=LEFT, 
            variable = self.logtimestamp, 
            onvalue=1, 
            offvalue=0)
        self.cb_logtimestamp.grid(row=8, column=1, sticky='e',)

        # epsig.exe BNK file validate
        self.use_epsigexe = IntVar() 
        self.use_epsigexe.set(1) 
        self.cb_epsigexe = Checkbutton(
            frame_checkbuttons, 
            text="epsig3_7.exe to verify BNK file formats", 
            justify=LEFT, 
            variable = self.use_epsigexe, 
            onvalue=1, 
            offvalue=0)
        self.cb_epsigexe.grid(row=9, column=1, sticky='w',)

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
            command = lambda: self.handle_button_press('__clear__'), 
            width = 20)
        self.button_clear.grid(row=1, column = 1, padx=5, pady=5, sticky='w',)

        # Clear Output
        button_clear_output = ttk.Button(
            frame_controlbuttons, 
            text = "Clear Output Field",
            command = lambda: self.handle_button_press('__clear_output__'),
            width = 20)
        button_clear_output.grid(row=1, column=2, sticky='w', padx=5, pady=5)

        # Start Button
        self.button_start = ttk.Button(
            frame_controlbuttons, 
            text = "Generate Hash...",
            command = lambda: self.handle_button_press('__start__'), 
            width = 20)
        self.button_start.grid(row=1, column=3, sticky='w', padx=5, pady=5)

        ################ Bottom Cache FRAME ##############
        frame_cachebuttons = ttk.Frame(frame_bottombuttons)
        frame_cachebuttons.pack(side=BOTTOM, fill=X, expand = True)
        frame_cachebuttons.config(relief = RIDGE, borderwidth = 2)

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
            command = lambda: self.handle_button_press('__select_cache_file__'))
        self.button_select_cache_button.grid(row=1, column=2, sticky='w', padx=3, pady=3)
        
        # Print Cache Button
        button_cache = ttk.Button(frame_cachebuttons, 
            text = "Print Cache",
            command = lambda: self.handle_button_press('__print_cache__'),
            width = 20)
        button_cache.grid(row=1, column=3, sticky='w', padx=5, pady=5)
        
        # Clear Cache Button
        self.button_clear_cache = ttk.Button(
            frame_cachebuttons, 
            text = "Clear Cache",
            command = lambda: self.handle_button_press('__clear_cache__'), 
            width = 20)
        self.button_clear_cache.grid(row=1, column=4, sticky='w', padx=5, pady=5)        

        self.root.mainloop()
        
def exit_handler():
    logging.getLogger().info("==== epsig2_gui STOPPED/INTERRUPTED: " + str(datetime.now()) + " by: " + getpass.getuser()  + " ====")
 
def main():
    app = None
    logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s- %(message)s')    
    atexit.register(exit_handler)
    
    try: 
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future = executor.submit(epsig2_gui())   

    except KeyboardInterrupt:       
        logging.debug("Program Exiting.")
        app.root.quit()
        sys.exit(0)

if __name__ == "__main__": main()
