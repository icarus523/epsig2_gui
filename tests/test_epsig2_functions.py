import unittest
import os
import csv

from epsig2GUI_TestClient import epsig2GUI_TestClient
from epsig2_gui import epsig2

class test_epsig2_functions(epsig2GUI_TestClient):      

    def test_dobnk_SHA1(self): 
        self.bnkfile = '/Users/james/Documents/dev/bnkfiles/5D81F_W4QLQ05M.BNK'
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        expected_result = '94C5809DEA787F1584A5CA6CFDF4210A9E831018'

        h = epsig2.dobnk(self, self.bnkfile, blocksize=8192)
        formatted_h = epsig2.format_output(self, str(h), self.options_d) 

        self.assertEqual(formatted_h, expected_result)


    def test_dobnk_SHA256(self): 
        self.bnkfile = '/Users/james/Documents/dev/bnkfiles/5D81F_W4QLQ05M.BNK'
        self.seed = '0000000000000000000000000000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA256'    
        expected_result = '00000000000000000000000094C5809DEA787F1584A5CA6CFDF4210A9E831018'

        h = epsig2.dobnk(self, self.bnkfile, blocksize=8192)
        formatted_h = epsig2.format_output(self, str(h), self.options_d) 

        self.assertEqual(formatted_h, expected_result)


    def test_format_output(self): 
        inputstr = '0x94C5809DEA787F1584A5CA6CFDF4210A9E831018'

        self.options_d['cache_file_f'] = False
        self.options_d['uppercase'] = True
        self.options_d['eightchar'] = False
        self.options_d['reverse'] = False
        self.options_d['usr_cache_file'] = False
        self.selectedHashtype = 'HMAC-SHA1'

        output_str = epsig2.format_output(self, inputstr, self.options_d)
        self.assertEqual(output_str, '94C5809DEA787F1584A5CA6CFDF4210A9E831018')

    def test_format_output_uppercase(self): 
        inputstr = '92971beb3f6d486bdb86402e8e9e2c726d1173d7999f3f7188f3884663181ff0'

        self.options_d['cache_file_f'] = False
        self.options_d['uppercase'] = True
        self.options_d['eightchar'] = False
        self.options_d['reverse'] = False
        self.options_d['usr_cache_file'] = False
        self.selectedHashtype = 'HMAC-SHA256'

        output_str = epsig2.format_output(self, inputstr, self.options_d)
        self.assertEqual(output_str, '92971BEB3F6D486BDB86402E8E9E2C726D1173D7999F3F7188F3884663181FF0')

    def test_format_output_eight_char_spacing(self): 
        inputstr = '92971beb3f6d486bdb86402e8e9e2c726d1173d7999f3f7188f3884663181ff0'

        self.options_d['cache_file_f'] = False
        self.options_d['uppercase'] = True
        self.options_d['eightchar'] = True
        self.options_d['reverse'] = False
        self.options_d['usr_cache_file'] = False
        self.selectedHashtype = 'HMAC-SHA256'

        output_str = epsig2.format_output(self, inputstr, self.options_d)
        self.assertEqual(output_str, '92971BEB 3F6D486B DB86402E 8E9E2C72 6D1173D7 999F3F71 88F38846 63181FF0')

    def test_format_output_reverse(self): 
        inputstr = '92971beb3f6d486bdb86402e8e9e2c726d1173d7999f3f7188f3884663181ff0'

        self.options_d['cache_file_f'] = False
        self.options_d['uppercase'] = False
        self.options_d['eightchar'] = False
        self.options_d['reverse'] = True
        self.options_d['usr_cache_file'] = False
        self.selectedHashtype = 'HMAC-SHA256'

        output_str = epsig2.format_output(self, inputstr, self.options_d)
        self.assertEqual(output_str, 'eb1b9792')


    def test_dohash_hmacsha1(self): 
        self.seed = '0000000000000000000000000000000000000000000000000000000000000000'
        expected_result = '0e2dad2de1d15eb13cd8553e0a2bba7127af4796'
        h = epsig2.dohash_hmacsha(self, self.binfile, chunksize=8192, hash_type='HMAC-SHA1')

        self.assertEqual(h, expected_result)

    def test_dohash_hmacsha256(self): 
        self.seed = '0000000000000000000000000000000000000000000000000000000000000000'
        expected_result = '92971beb3f6d486bdb86402e8e9e2c726d1173d7999f3f7188f3884663181ff0'
        h = epsig2.dohash_hmacsha(self, self.binfile, chunksize=8192, hash_type='HMAC-SHA256')

        self.assertEqual(h, expected_result)

    def test_insert_spaces(self): 
        input_str = '1234567890abcdefghijklmnopqrstuvwxyz1234'

        output_str = epsig2.insert_spaces(self, input_str, s_range=8)

        self.assertEqual(output_str, '12345678 90abcdef ghijklmn opqrstuv wxyz1234')

    def test_checkCacheFilenameSeedAlg_BNK(self): 
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)

        self.cache_dict = {
            "/Users/james/Documents/dev/bnkfiles/5D81F.sigs":[
                {
                    "alg":"SHA1",
                    "hash":"387a1d858b2f32d7f8074f2b33b673b8f5f42339",
                    "seed":"0000000000000000000000000000000000000000"
                },
                {
                    "alg":"HMAC-SHA1",
                    "hash":"2519afc9fcb7ebb4647c8bcd6a142ded2ea9bab96a7f0e567ce6fbc82c3aab5a",
                    "seed":"0000000000000000000000000000000000000000000000000000000000000000"
                }                    
            ],
            "/Users/james/Documents/dev/bnkfiles/SBGEN024.img":[
                {
                    "alg":"SHA1",
                    "hash":"c6967f4f9240f15ea742f8d57b347b3142427e51",
                    "seed":"0000000000000000000000000000000000000000"
                }, 
                {
                    "alg":"HMAC-SHA1",
                    "hash":"1ed8dfe521c0eea1ce80428a40e78cea6508b042f0b1e471c15392c6da2be21d",
                    "seed":"0000000000000000000000000000000000000000000000000000000000000000"
                }                    
            ],
            "/Users/james/Documents/dev/bnkfiles/W4QLQ05M.sigs":[
                {
                    "alg":"SHA1",
                    "hash":"6a29e257f317bc9cdbe07d92b576298329354d70",
                    "seed":"0000000000000000000000000000000000000000"
                }, 
                {
                    "alg":"HMAC-SHA1",
                    "hash":"46048e12ba000ae2f6b38547d49769fa82fa626610d9603dd06745c8a9dc4e67",
                    "seed":"0000000000000000000000000000000000000000000000000000000000000000"
                }                    
            ]
        }

        with open(self.bnkfile, 'r') as infile: 
            fdname = ['fname', 'type', 'blah']
            reader = csv.DictReader(infile, delimiter=' ', fieldnames = fdname)
            for row in reader: 
                fp = self.mandir + "/" + str(row['fname'])
                hash_value = epsig2.checkCacheFilename_BNK(self, fp, self.seed, row['type'].upper())

                if fp == "/Users/james/Documents/dev/bnkfiles/5D81F.sigs": 
                    self.assertEqual(hash_value, '387a1d858b2f32d7f8074f2b33b673b8f5f42339')
                elif fp == "/Users/james/Documents/dev/bnkfiles/SBGEN024.img": 
                    self.assertEqual(hash_value, 'c6967f4f9240f15ea742f8d57b347b3142427e51')
                elif fp == "/Users/james/Documents/dev/bnkfiles/W4QLQ05M.sigs": 
                    self.assertEqual(hash_value, '6a29e257f317bc9cdbe07d92b576298329354d70')
