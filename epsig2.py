import concurrent.futures
import csv
import hashlib
import hmac
import json
import logging
import os
import string
import sys
import threading
import getpass

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait, as_completed

p_reset = "\x08"*8

TEST=True   # This must be changed once released

if TEST: 
    DEFAULT_CACHE_FILE="epsig2_cachefile_v3.json"
else: 
    DEFAULT_CACHE_FILE = "\\\Justice.qld.gov.au\\Data\\OLGR-TECHSERV\\TSS Applications Source\\James\\epsig2_cachefile_v3.json"


## Seed class
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


## BNKEntry class
class BNKEntry:
    # helper class for sanitizing BNK file entries

    def __init__(self, line): 
        self.fields = [i for i in line if i] # remove empty strings

        fields = self.fields
        assert(len(fields) == 3), "Maximum 3 fields"

        # filenameX The filename+ext of a binary image (max 250 chars and must not contain spaces)
        assert(len(fields[0]) < 250), "filename max 250 chars"
        assert(" " not in fields[0]), "filename must not contain spaces"
        self.fname = fields[0] 

        #algX       The hash algorithm designation type to be used for the image.
        #           Refer to previous list of supported algorithm types & designations.
        #           Cannot be “BLNK” (i.e. no recursion)            
        assert(fields[1] in ACCEPTABLE_HASH_ALGORITHMS), "unknown hash algorithm"
        self.hash_type = fields[1] 

        assert(fields[2] == 'p'), "must be a 'p'"
        self.hash_type = fields[1] 

    def toJSON(self): 
        return (json.dumps(self, default=lambda o: o.__dict__, sort_keys = True, indent=4))


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

    def __init__(self, seed, filepath, options_d, cache_dict, hash_type_str, epsigexe=True):
        logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s- %(message)s')
        self.verify_with_epsigexe = epsigexe # default this will use epsig.exe to verify BNK files. 
        self.seed = seed 
        self.filepath = filepath
        self.options_d = options_d
        self.mandir = os.path.dirname(self.filepath)
        self.cache_dict = dict()
        self.xor_result = ''
        self.LogOutput = list() 
        self.user_cache_file = options_d['usr_cache_file']
        self.selectedHashtype = hash_type_str

        # this will delay each file to be checked. 
        if filepath.upper().endswith('BNK') and self.verify_with_epsigexe: 
            # use Rob's epsig3_7.exe to verify BNK file format
            epsigexe_output = epsig2.bnkfile_validate_epsigexe(self, filepath, self.seed) # will block

            if epsigexe_output and epsigexe_output['returncode'] == True: 
                for result in epsigexe_output['results']: # log epsig3_7.exe output to log file
                    logging.info("epsig.exe: " + result) 
                logging.info("epsig.exe: " + filepath + " format is correct.")   
            else: 
                logging.error("epsig.exe: " + os.path.basename(filepath) + " format Error. The file is not formatted as expected. Check the file contents for errors")
                # need to provide error dialogue here
                self.filepath = None

        else: 
            if not self.verifyFileExists(self.filepath):
                msg = "**** ERROR: " + self.filepath + " had errors while reading file contents"
                logging.error(msg)
            else:
                logging.info("epsig2_gui: " + filepath + " format is correct.")   


        # self.processfile(self.filepath, chunks=8192) 

    def bnkfile_validate_epsigexe(self, fname, seed): 
        epsig_path = 'G:/OLGR-TECHSERV/BINIMAGE/epsig3_7.exe'
        if not os.path.isfile(epsig_path):
            logging.error("epsig.exe cannot be found in: " + epsig_path)
            return None

        if ' ' in os.path.basename(fname): 
            logging.error("no spaces allowed in filename: " + os.path.basename(fname))
            return None

        # the following will block
        proc = subprocess.run([epsig_path, fname, seed], capture_output=True) #stdout=subprocess.PIPE
        
        err = proc.stderr.decode('utf-8')
        stdout = proc.stdout.decode('utf-8').split("\r\n")
        stdout = [i for i in stdout if i] # remove empty strings 
        
        result_l = list() 
        for row in stdout: 
            if row.startswith('Hash'): 
                result_l.append(row)

        rv = dict() 
        rv['err'] = err
        rv['stdout'] = stdout
        rv['results'] = result_l
        rv['returncode'] = proc.returncode == 0

        return rv

    def verifyFileExists(self, fname): 
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
        
    # def verifyFileExists(self, fname): 
    #     mandir = os.path.dirname(fname)
    #     rv = True
    #     with open(fname, 'r') as infile: 
    #         fdname = ['fname', 'type', 'blah']
    #         reader = csv.DictReader(infile, delimiter=' ', fieldnames = fdname)

    #         for row in reader:
    #             fp = os.path.join(mandir, str(row['fname']))
                
    #             if str(row['type']).upper() == 'SHA1' or str(row['type']).upper() == 'SHA256':
    #                 # check if the file exists
    #                 if not (os.path.isfile(fp)):
    #                     msg = "**** ERROR: " + fp + " cannot be read from disk"
    #                     logging.error(msg)                         
    #                     rv = False
    #             else:
    #                 msg = fp + " is not an expected hash type"
    #                 logging.error(msg)                                             
    #                 rv = False
    #     return rv
    
    # def verifyFileExists(self, f):
        # rv = True
        # if f.endswith(".BNK"): 
            # with open(f, 'r') as infile: 
                # fdname = ['fname', 'type', 'blah']
                # reader = csv.DictReader(infile, delimiter=' ', fieldnames = fdname)
                # for row in reader: 
                    # path = os.path.dirname(f)
                    # fp = os.path.join(path, str(row['fname'])) # can't use: os.path.join(self.mandir, str(row['fname'])), as the Cache expects "/"
                    # if not os.path.isfile(fp): 
                        # msg = "**** ERROR: " + fp + " cannot be read from disk"
                        # logging.error(msg)                        
                        # rv = False   
        # else: 
            # if not os.path.isfile(f): 
                # rv= False
        # return rv

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

    # def checkCacheFilename_BNK(self, filename, seed_input, alg_input): # alg_input 
    #     # For filename_seed, concatenate to form unique string. 
    #     if filename in self.cache_dict.keys(): # a hit?
    #         data = self.cache_dict.get(filename) # now a list
    #         # print(json.dumps(data, indent=4, sort_keys=True))
    #         for item in data:
    #             # Check if Seed and Algorithm matches. 
    #             if item['seed'] == seed_input and item['alg'] == alg_input: 
    #                 # verified_time = item['verify'] 
    #                 return(str(item['hash'])) # return Hash result
        
    #     return None  

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
                                cachedhit = epsig2.checkCacheFilename(self, fp, self.seed, str(row['type']).upper())
                                
                                if cachedhit != None:
                                    # logging.debug("Cached hit!: " + cachedhit)
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
                                # self.outxput.append(outputstr)
                                
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

            except FileNotFoundError: 
                logging.error("Could not read file: " + fname)

            
        return oh # { 'oh': oh } , 'cache_dict' : self.cache_dict, 'rv': self.LogOutput ,'filename' : fname} 
    
    # Inserts spaces on [text] for every [s_range]
    # def insert_spaces(self, text, s_range):
    #     return " ".join(text[i:i+s_range] for i in range(0, len(text), s_range))

    # Formats inputstr based on options_d dictionary
    # Note this can be used outside this script. 
    def format_output(self, inputstr, options_d):
        outputstr = ''

        if options_d['selectedHashtype'] == 'HMAC-SHA1': 
            outputstr = inputstr.lstrip('0X').lstrip('0x').zfill(40) #strip 0x first
        elif options_d['selectedHashtype'] == 'HMAC-SHA256': 
            outputstr = inputstr.lstrip('0X').lstrip('0x').zfill(64) #strip 0x first

        # include a space for every eight chars
        if (options_d['eightchar'] == True):
            s_range = 8
            outputstr = " ".join(outputstr[i:i+s_range] for i in range(0, len(outputstr), s_range))
        
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

    def processfile(self,chunks=8192):
        # time.sleep(1) 
        fname=self.filepath
        h = None
        do_output = None
        
        if fname: 
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