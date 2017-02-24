# epsig2_gui.py 
# Ported from Rob Larkin's LUA script version to python. 
# 
##	from Rob's original epsig2.lua 
##  Usage:
##		lua epsig2.lua bnkfilename [seed [reverse] ]
##
##	examples: 	lua epsig2.lua ARI\10163088_F23B_6040_1.bnk
##				lua epsig2.lua ARI\10163088_F23B_6040_1.bnk 1234
##				lua epsig2.lua ARI\10163088_F23B_6040_1.bnk 00 reverse
##      If no seed supplied then a seed of 00 is used
##
##	Note wrt a Casino "reverse"'d result, the result wrt Casino datafiles is the last 8 chars of the result displayed. E.g.
##	Result: 3371cc5638d735cefde5fb8da904ac8d54c2050c the result is 54c2050c

# Version History
# v1.0 - Initial Release
# v1.1 - Add support to SL1 datafile seed files via combobox and file chooser widget, updated GUI
# v1.2 - Add support to use MSL (QCAS) files and automatically flip the SEED as expected for completing CHK01 (Yick's request)
# v1.3  - Add support for multiple selection of BNK files
#       - introduces Caching of Hashes
# v1.3.1 - Fixes Cache to also uniquely identify Seed
# v1.4 - Adds Cache File support to DEFAULT_CACHE_FILE
# v1.4.1 - cache is now a dict of a dicts, i.e. { "fname": { "seed": "hash_result", "filename": "C:\blah\blah\cache.json" } } - for readability.
#       - fixed cache file location to "\\\Justice.qld.gov.au\\Data\\OLGR-TECHSERV\\TSS Applications Source\\James\\epsig2_cachefile.json"
#           - supports multiple seeds for each file
#       - adds user specifiable Cache File (when you want to control your own cache)
#       - adds automatic validation of Cache File, the file is signed and verified prior to loading automatically, via SHA1 hash and a .sigs file
# v1.4.2 - add option to write to log file (request by Yick)

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

from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from tkinter import filedialog
from threading import Thread
from datetime import datetime

MAXIMUM_BLOCKSIZE_TO_READ = 65535
VERIFY_THRESHOLD = 5 # Number of Hashes Generated before it can be trusted
DEFAULT_CACHE_FILE = "\\\Justice.qld.gov.au\\Data\\OLGR-TECHSERV\\TSS Applications Source\\James\\epsig2_cachefile_v2.json"
#DEFAULT_CACHE_FILE = "epsig2_cachefile_v2.json"
VERSION = "1.4.2 (Log File Option)"
p_reset = "\x08"*8

class epsig2:

    # input: file to be CRC32 
    def dohash_crc32(self, fname):
        buf = open(fname,'rb').read()
        buf = (binascii.crc32(buf) & 0xFFFFFFFF)

        return "%08X" % buf

    # input: file to be hashed using sha1()
    # output: hexdigest of input file    
    def dohash_sha1(self, fname, chunksize=8192): 
        m = hashlib.sha1()         

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
        key = bytes.fromhex(self.seed)
        m = hmac.new(key, digestmod = hashlib.sha1) # change this if you want other hashing types for HMAC, e.g. hashlib.md5
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

    def checkCacheFilename(self, filename, seed_input, alg_input): # alg_input
        # For filename_seed, concatenate to form unique string. 
        if filename in self.cache_dict.keys(): # a hit?
            #print("Cache Hit!\t" + os.path.basename(filename) + ":\t" + self.cache_dict[filename+"_"+seed])
            data = self.cache_dict.get(filename) # now a list
            for item in data:
                if item['seed'] == seed_input and item['alg'] == alg_input: # Check if Seed and Algorithm matches. 
                    verified_time = item['verify'] 
                    #print("Cache item is: " + item['hash'])
                    return(item['hash']) # return Hash result
        else:
            return 0

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
                print("\n**** WARNING **** File Cache integrity issue: Cannot Verify")
                print("**** Generating new File Cache\n")
                cache_data = {} # return null
        else:
            print(cache_location + " cannot be found. Generating default file...")
            with open(cache_location, 'w') as json_cachefile:
                # write empty json file
                json.dump({}, json_cachefile, sort_keys=True, indent=4, separators=(',', ': '))
        
        return(cache_data)

    def verifyCacheIntegrity(self, cache_location_sigs): 
        if os.path.isfile(cache_location_sigs): # Sigs file exist?
            with open(cache_location_sigs, 'r') as sigs_file: 
                cache_sigs_data = json.load(sigs_file)
                hash = cache_sigs_data['cachefile_hash']
                fname = cache_sigs_data['filename']
                
                generated_hash = self.dohash_sha1(fname)
                if hash == generated_hash: 
                    return True
                else: 
                    return False     
        else: 
            print("\n**** WARNING **** Generating new Cache Sigs file\n") # advise user
            if self.user_cache_file: # Handle User selectable Cache File
                cache_location = self.user_cache_file
            else: 
                cache_location = DEFAULT_CACHE_FILE
            
            self.signCacheFile(cache_location) # Generate Cache
        
    def signCacheFile(self, cache_location):
        sigsCacheFile = cache_location[:-4] + "sigs" # .json file renaming to .sigs file
        
        with open(sigsCacheFile,'w') as sigs_file: 
            h = self.dohash_sha1(cache_location) # requires file name as input
            
            timestamp = datetime.now()
            sigs_dict = { 'cachefile_hash' : h, 'filename': cache_location, 'last_generated_by_user' : getpass.getuser(), 'date': str(timestamp.strftime("%Y-%m-%d %H:%M")) }
            
            json.dump(sigs_dict, sigs_file, sort_keys=True, indent=4, separators=(',', ': '))
        
    def updateCacheFile(self, cache_dict):
        if self.user_cache_file:
            cache_location = self.user_cache_file
        else: 
            cache_location = DEFAULT_CACHE_FILE
            
        if os.path.isfile(cache_location):
            with open(cache_location, 'w') as json_cachefile:
                json.dump(cache_dict, json_cachefile, sort_keys=True, indent=4, separators=(',', ': '))
            
            self.signCacheFile(cache_location) # Sign Cache
        
        
    def dobnk(self, fname, blocksize):
        if self.useCacheFile.get() == 1: # Use Cache File
            self.cache_dict = self.importCacheFile() # Overwrite self.cache_dict with contents of file

        oh = "0000000000000000000000000000000000000000"
        # Verify Seed is a number String format, and atleast 2 digits long 
        if (len(self.seed) < 2 or not self.checkhexchars(self.seed)):
            messagebox.showerror("Error in Seed Input", "Expected atleast two Hexadecimal characters as the Seed input" +
                                 ".\n\nCheck your Seed string again: " + self.seed)
            return -1
        else:
            try:
                self.text_BNKoutput.insert(END, "Processing: " + fname + "\n")
                # infile = open(self.mandir + "/" + self.bnk_filename, 'r')
                infile = open(fname, 'r')
                fdname = ['fname', 'type', 'blah']
                reader = csv.DictReader(infile, delimiter=' ', fieldnames = fdname)

                self.text_BNKoutput.insert(END, "Seed: " + self.seed + "\n")
            
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
                                localhash = self.dohash_hmacsha1(self.mandir + "/" + str(row['fname']), blocksize)

                                seed_info = { 'seed': self.seed, 'alg': row['type'].upper(), 'verify':'0', 'hash': localhash }        
                                cache_entry_list = self.cache_dict.get(self.mandir + "/" + str(row['fname'])) # Should return a list. 
                                
                                if cache_entry_list : # File Entry Exists, append to list
                                    cache_entry_list.append(seed_info) # print this
                                    self.cache_dict[self.mandir + "/" + str(row['fname'])] = cache_entry_list # keep unique
                                else:  # No File Entry Exits generate new list entry in cache_dict
                                    new_cache_list.append(seed_info)
                                    self.cache_dict[self.mandir + "/" + str(row['fname'])] = new_cache_list # keep unique
                                
                                if self.useCacheFile.get() == 1:
                                    self.updateCacheFile(self.cache_dict) # Update file cache
                                else: 
                                    self.cache_dict[self.mandir + "/" + str(row['fname'])] = new_cache_list # update local cache
                                    #self.cache_dict[self.mandir + "/" + str(row['fname'])+"_"+self.seed] = localhash # only local hash
                                    

                            self.resulthash = localhash
                            # handle incorrect seed length
                            if localhash == 0:
                                break # exit out cleanly
                        
                            # include a space for every eight chars
                            if (self.eightchar.get() == 1):
                                eightchar_displaytext = self.insert_spaces(str(localhash), 8)
                            else:
                                eightchar_displaytext = str(localhash)

                            if self.uppercase.get() == 0:
                                self.text_BNKoutput.insert(END, eightchar_displaytext + " " + str(row['fname']) + "\n")
                            else:
                                self.text_BNKoutput.insert(END, eightchar_displaytext.upper() + " " + str(row['fname']) + "\n")

                            # XOR strings, by first converting to numbers using int(), and providing expected base (16 for hex numbers)
                            # Then two conversions, to perform the XOR operator "^" then convert back to hex
                            
                            oh = hex(int(oh,16) ^ int(str(localhash), 16)) # XOR'ed result
                            
                            if cachedhit:
                                print (str(localhash) + "\t" + str(row['fname']) + " (cached)") # Hash and Filename
                            else:
                                print (str(localhash) + "\t" + str(row['fname']))
                        else: 
                            self.text_BNKoutput.insert(END, "could not read file: " + str(row['fname']) + "\n")
                    else: 
                        messagebox.showerror("Not Yet Implemented!", "Unsupported hash algorithm: " + row['type'].upper() + ".\n\nExiting. Sorry!")
                        sys.exit('Unsupported hash algorithm: ' + row['type'])
                        # Need to implement CR16, CR32, PS32, PS16, OA4F and OA4R, and SHA256 if need be. 

            except csv.Error() as e:
                messagebox.showerror("CSV Parsing Error", "Malformed BNK entry, check the file manually" + row['type'].upper() + ".\n\nExiting.")
                sys.exit('file %s, line %d: %s' % (filename, reader.line_num, e))
            
        return oh
    
    # Inserts spaces on [text] for every [s_range]
    def insert_spaces(self, text, s_range):
        return " ".join(text[i:i+s_range] for i in range(0, len(text), s_range))

    def processfile(self, fname, chunks):
        h = self.dobnk(fname, chunks)
        
        style = ttk.Style()
        if h == -1: 
            return # handle error in seed input
        else:
            #outputstart = len(self.text_BNKoutput.get(0, END))
            
            self.text_BNKoutput.insert(END, "RAW output: " + str(h).zfill(40) + "\n")

            #strip 0x first
            tmpStr = str(h).lstrip('0X').zfill(40) # forces 40 characters with starting 0 characters. 
            tmpStr = str(h).lstrip('0x').zfill(40)

            # include a space for every eight chars
            if (self.eightchar.get() == 1):
                eightchar_displaytext = self.insert_spaces(tmpStr, 8)
            else: 
                eightchar_displaytext = tmpStr

            style.configure("self.text_BNKoutput", foreground="red") # RED text
            
            # Do QCAS expected result       
            if (self.reverse.get() == 1):
                if self.uppercase.get() == 1:
                    displaystr = self.getQCAS_Expected_output(eightchar_displaytext)
                    self.text_BNKoutput.insert(END, "QCAS Expected Result: " + displaystr.upper())
                else:
                    displaystr = self.getQCAS_Expected_output(eightchar_displaytext)
                    self.text_BNKoutput.insert(END, "QCAS Expected Result: " + displaystr) # Slice characters from the 8th-last position to the end
                    
            # Normal XOR result
            elif (self.reverse.get() == 0): 
                if self.uppercase.get() == 1:
                    self.text_BNKoutput.insert(END, "XOR: " + eightchar_displaytext.upper())
                else:
                    self.text_BNKoutput.insert(END, "XOR: " + eightchar_displaytext)
            else:
                messagebox.showerror("Checkbox Error", "Unknown state")

            style.configure("self.text_BNKoutput", foreground="black")       
            self.text_BNKoutput.insert(END, "\n\n")

           
            

    def writetofile(self, filename, text):
        timestamp = datetime.timestamp(datetime.now())
        outputfile = ''
        
        if self.logtimestamp.get() == 1: # Multi log files not overwritten saved in different directory
            outputfile = "epsig2-logs/" + filename[:-4] + "-" + str(timestamp) + ".log"
        else: # Single log file that's overwritten
            outputfile = filename

        with open(outputfile, 'w+') as outfile:
            outfile.write("#--8<-----------GENERATED: " + str(datetime.fromtimestamp(timestamp)) + " --------------------------\n")
            outfile.write(text)
            

    def getQCAS_Expected_output(self, text):
        tmpstr = text[:8] # Returns from the beginning to position 8 of uppercase text
        return "".join(reversed([tmpstr[i:i+2] for i in range(0, len(tmpstr), 2)]))
    
    def processdirectory(self):
        print("Arg 1 is a path")

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
                    print("\nProcessing: " + bnk_filepath)
                    if (os.path.isfile(bnk_filepath)):                 
                        if self.bnk_filename == '': 
                            self.bnk_filename = os.path.basename(bnk_filepath)
                        
                        self.mandir = os.path.dirname(bnk_filepath)

                        if (self.reverse.get() == 1): # reverse the seed.
                            self.seed = self.getQCAS_Expected_output(self.combobox_SelectSeed.get())
                        else: 
                            self.seed = self.combobox_SelectSeed.get()

                        print("Seed is: " + self.seed)
                        
                        self.processfile(bnk_filepath, MAXIMUM_BLOCKSIZE_TO_READ)

                # option to write to log selected.
                if self.writetolog.get() == 1:  
                    #self.writetofile("epsig2.log", self.text_BNKoutput.get("1.0", "end-3c"))
                    self.writetofile("epsig2.log", self.text_BNKoutput.get("1.0", "end-3c"))
            else:
                messagebox.showerror("Files not Chosen!", "Please select files first")

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
                self.label_SeedPath.configure(text="No SL1/MSL Seed file selected") 
                self.combobox_SelectSeed.set('0000000000000000000000000000000000000000')
                self.combobox_SelectSeed['values'] = ()
                self.bnk_filename_list = list()
                self.bnk_filelist = list()
                self.useCacheFile.set(0)
                self.CacheFileButtonText.set(DEFAULT_CACHE_FILE)
                self.user_cache_file = None
                
        elif myButtonPress == '__clear_cache__':
                if self.user_cache_file:
                    cache_location = self.user_cache_file
                else: 
                    cache_location = DEFAULT_CACHE_FILE
                    
                print("\nCleared local RAM cache only. \nFile cache not modified: " + cache_location)
                if self.useCacheFile.get() == 1: # Use Cache File
                    self.importCacheFile() # Overwrite self.cache_dict with contents of file
                else:
                    #seed_info = [{ 'seed': '0x0000', 'alg':'hmac-sha1', 'verify':'0', 'hash': '0x1111' }]
                    #empty_cache_data = { 'fname': seed_info }
                    self.cache_dict = {} # empty_cache_data # Clear cache_dict

        elif myButtonPress == '__print_cache__':
                print("\nCache Entries: ")
                if self.useCacheFile.get() == 1: # Use Cache File
                    self.cache_dict = self.importCacheFile() # Overwrite self.cache_dict with contents of file
                    print(json.dumps(self.cache_dict, sort_keys=True, indent=4, separators=(',',':')))
                else:
                    print(json.dumps(self.cache_dict, sort_keys=True, indent=4, separators=(',',':')))
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
        
        frame_toparea = ttk.Frame(self.root)
        frame_toparea.pack(side = "top", fill=X, expand=False)
        frame_toparea.config(relief = RIDGE, borderwidth = 0)
        
        ttk.Label(frame_toparea, justify=LEFT,
                  text = 'GUI script to process BNK files. Note: Supports only HMAC-SHA1').grid(row = 0, columnspan=4, padx=3, pady=3)

        # Button Selected BNK file
        button_SelectedBNKfile = ttk.Button(frame_toparea, text = "Select BNK file...", width = 20,
                                                      command = lambda: self.handleButtonPress('__selected_bnk_file__'))                                             
        button_SelectedBNKfile.grid(row=1, column=0, padx=5, pady=5, sticky='e')
        
        # Text Entry Selected BNK file
        self.textfield_SelectedBNK = ttk.Entry(frame_toparea, width = 72)
        self.textfield_SelectedBNK.grid(row=1, column=1, sticky='w', padx=5, pady=5)

        # Button Selected Seed file (sl1)
        button_Selectedsl1file = ttk.Button(frame_toparea, text = "Seed or SL1/MSL file...", width = 20, 
                                                      command = lambda: self.handleButtonPress('__selected_seed_file__'))                                             
        button_Selectedsl1file.grid(row=2, column=0, padx=5, pady=5, sticky='e')

        # Combo Box for Seeds, default to 0x00
        self.box_value = StringVar()
        self.combobox_SelectSeed = ttk.Combobox(frame_toparea, justify=LEFT, textvariable=self.box_value, width = 70)
        self.combobox_SelectSeed.grid(row=2, column=1, sticky='w', padx=5, pady=5)
        self.combobox_SelectSeed.set('0000000000000000000000000000000000000000')

        # Checkbutton MSL file (casinos)
        self.mslcheck = IntVar()
        self.mslcheck.set(0)
        self.cb_mslcheck = Checkbutton(frame_toparea, text="MSL (Use Casino MSL File)", justify=LEFT, variable = self.mslcheck, onvalue=1, offvalue=0)
        self.cb_mslcheck.grid(row=2, column=2, sticky='e',)
        
        # Text Label sl1 location
        self.label_SeedPath = ttk.Label(frame_toparea, text = 'No SL1/MSL Seed File Selected', width = 80)
        self.label_SeedPath.grid(row=3, columnspan=4, padx=5, pady=5, sticky = 'w')

        ######################### MIDDLE FRAME
        frame_middleframe = ttk.Frame(self.root)
        frame_middleframe.pack(side = TOP, fill=BOTH, expand=True)
        
        # Need to use .pack() for scrollbar and text widget
        frame_textarea = ttk.Labelframe(frame_middleframe, text="Output")
        frame_textarea.pack(side = LEFT, fill=BOTH, expand=True)
        frame_textarea.config(relief = RIDGE, borderwidth = 0)

        # Text Area output of BNK file generation
        self.text_BNKoutput = Text(frame_textarea, height=30)
        S = Scrollbar(frame_textarea, command=self.text_BNKoutput.yview)
        S.pack(side=RIGHT, fill=Y)
        self.text_BNKoutput.configure(yscrollcommand=S.set)
        self.text_BNKoutput.pack(side=LEFT, fill=BOTH, expand=True)
        
        #Frame for Checkbuttons
        frame_checkbuttons = ttk.Labelframe(frame_middleframe, text="Output Options")
        frame_checkbuttons.pack(side = RIGHT, fill=Y, expand = False)
        frame_checkbuttons.config(relief = RIDGE, borderwidth = 0)
        
        # Checkbutton Reverse
        self.reverse = IntVar()
        self.reverse.set(0)
        self.cb_reverse = Checkbutton(frame_checkbuttons, text="QCAS expected output", justify=LEFT, variable = self.reverse, onvalue=1, offvalue=0)
        self.cb_reverse.grid(row=1, column=1, sticky='w')

        # Checkbutton Uppercase
        self.uppercase = IntVar()
        self.uppercase.set(1)
        self.cb_uppercase = Checkbutton(frame_checkbuttons, text="Uppercase", justify=LEFT, variable = self.uppercase, onvalue=1, offvalue=0)
        self.cb_uppercase.grid(row=2, column=1, sticky='w')

        # Checkbutton 8 Char
        self.eightchar = IntVar()
        self.eightchar.set(1)
        self.cb_eightchar = Checkbutton(frame_checkbuttons, text="8 character spacing", justify=LEFT, variable = self.eightchar, onvalue=1, offvalue=0)
        self.cb_eightchar.grid(row=3, column=1, sticky='w',)

        # Checkbutton Write to Log
        self.writetolog = IntVar()
        self.writetolog.set(1)
        self.cb_writetolog = Checkbutton(frame_checkbuttons, text="Write to Log File\noutput: epsig2.log", justify=LEFT, variable = self.writetolog, onvalue=1, offvalue=0)
        self.cb_writetolog.grid(row=4, column=1, sticky='w',)

        # Timestamp logs
        self.logtimestamp = IntVar()
        self.logtimestamp.set(0)
        self.cb_logtimestamp = Checkbutton(frame_checkbuttons, text="Timestamp Log File\noutput: epsig2-logs/epsig2-{timestamp}.log", justify=LEFT, variable = self.logtimestamp, onvalue=1, offvalue=0)
        self.cb_logtimestamp.grid(row=5, column=1, sticky='w',)

        ################ Bottom FRAME ##############
        frame_bottombuttons = ttk.Frame(self.root)
        frame_bottombuttons.pack(side=BOTTOM, fill=X, expand = False)
        frame_bottombuttons.config(relief = RIDGE, borderwidth = 0)
        
        # Clear Button
        self.button_clear = ttk.Button(frame_bottombuttons, text = "Clear Form", command = lambda: self.handleButtonPress('__clear__'), width = 15)
        self.button_clear.grid(row=1, column = 1, padx=5, pady=5, sticky='w',)
        
        # Start Button
        button_start = ttk.Button(frame_bottombuttons, text = "Generate Hash...",
                                  command = lambda: self.handleButtonPress('__start__'), width = 16)
        button_start.grid(row=1, column=2, sticky='w', padx=5, pady=5)

        # Print Cache Button
        button_cache = ttk.Button(frame_bottombuttons, text = "Print Cache",
                                  command = lambda: self.handleButtonPress('__print_cache__'), width = 15)
        button_cache.grid(row=1, column=3, sticky='w', padx=5, pady=5)
        
        # Clear Cache Button
        self.button_clear_cache = ttk.Button(frame_bottombuttons, text = "Clear Local Cache",
                                  command = lambda: self.handleButtonPress('__clear_cache__'), width = 18)
        self.button_clear_cache.grid(row=1, column=4, sticky='w', padx=5, pady=5)

        # Checkbutton Use Cache File
        self.useCacheFile = IntVar()
        self.useCacheFile.set(0)
        self.cb_useCacheFile = Checkbutton(frame_bottombuttons, text="Use File Cache:", justify=LEFT, variable = self.useCacheFile, onvalue=1, offvalue=0)
        self.cb_useCacheFile.grid(row=2, column=1, sticky='w', padx=3, pady=3)
        
        # Select Cache file button
        self.CacheFileButtonText = StringVar()
        self.CacheFileButtonText.set(DEFAULT_CACHE_FILE)
        self.button_select_cache_button = ttk.Button(frame_bottombuttons, textvariable = self.CacheFileButtonText,
                                  command = lambda: self.handleButtonPress('__select_cache_file__'))
        self.button_select_cache_button.grid(row=2, column=2, sticky='w', padx=3, pady=3)
        
        if self.useCacheFile.get() == 1: # Use Cache File
            self.button_clear_cache.state(["disabled"])
            self.button_clear_cache.config(state= DISABLED)
        else:
            self.button_clear_cache.state(["!disabled"])
            self.button_clear_cache.config(state=not DISABLED)
        
        self.root.mainloop()

        
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
        
        self.setupGUI()

def main():
    app = epsig2()

if __name__ == "__main__": main()
