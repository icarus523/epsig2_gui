import unittest
import os
import csv
import epsig2_gui

from epsig2GUI_TestClient import epsig2GUI_TestClient
from epsig2_gui import epsig2, Seed

class test_epsig2_functions(epsig2GUI_TestClient):      

# CompletedProcess(args=['G:/OLGR-TECHSERV/BINIMAGE/epsig3_7.exe', 'G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK', '0000000000000000000000000000000000000000000000000000000000000000'], 
# returncode=0, 
# stdout=b'0000000.000 \r\n\r\nEPSIG.EXE Version 3.7 Copyright The State of Queensland 1999-2015\r\n0000000.000 Started at   Fri Oct 01 15:15:24 2021\r\n G:\\OLGR-TECHSERV\\BINIMAGE\\epsig3_7.exe G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK 0000000000000000000000000000000000000000000000000000000000000000 \r\n0000000.000  Allocating buffer 262144 bytes\r\n\r\n0000000.000 BNK File Test Mode\r\nInput BNK File: G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK\r\nSeed (32 bytes hex, LSB First) : 0000000000000000000000000000000000000000000000000000000000000000 \r\n0000000.000 BNKFILE: 1645GDXX_393_004.BNK\r\n0000000.094 bnkLine: M165MLT030GA00.mod SHA1 S\r\n0000000.094 Hashing: 1 "M165MLT030GA00.mod" alg: "SHA1"\r\n0000010.719 HashFin: 1 "M165MLT030GA00.mod" bytes: 188,738,048 secs: 10.5 (r9.111)\r\n0000010.719 bnkLine: M166MLT030GA00.mod SHA1 p\r\n0000010.719 Hashing: 2 "M166MLT030GA00.mod" alg: "SHA1"\r\n0000022.781 HashFin: 2 "M166MLT030GA00.mod" bytes: 170,754,560 secs: 11.7 (r10.502)\r\n0000022.781 bnkLine: M167MLT030GA00.mod SHA1 p\r\n0000022.781 Hashing: 3 "M167MLT030GA00.mod" alg: "SHA1"\r\n0000039.234 HashFin: 3 "M167MLT030GA00.mod" bytes: 259,789,312 secs: 16.1 (r14.345)\r\n0000039.234 bnkLine: KGI_M164SPB010GA00.mod SHA1 p\r\n0000039.234 Hashing: 4 "KGI_M164SPB010GA00.mod" alg: "SHA1"\r\n0000054.125 HashFin: 4 "KGI_M164SPB010GA00.mod" bytes: 207,159,808 secs: 14.5 (r12.876)\r\n0000054.125 bnkLine: KGI_MWPGCMC133GA00.mod SHA1 p\r\n0000054.125 Hashing: 5 "KGI_MWPGCMC133GA00.mod" alg: "SHA1"\r\n0000072.422 HashFin: 5 "KGI_MWPGCMC133GA00.mod" bytes: 252,955,136 secs: 17.9 (r15.887)\r\n0000072.422 bnkLine: LLPSYSC100XX_QD393XXX.mod SHA1 p\r\n0000072.422 Hashing: 6 "LLPSYSC100XX_QD393XXX.mod" alg: "SHA1"\r\n0000082.922 HashFin: 6 "LLPSYSC100XX_QD393XXX.mod" bytes: 119,013,888 secs: 10.1 (r9.203)\r\n0000082.922 bnkLine: LRAMCLC011QD.bin SHA1 p\r\n0000082.937 Hashing: 7 "LRAMCLC011QD.bin" alg: "SHA1"\r\n0000083.031 HashFin: 7 "LRAMCLC011QD.bin" bytes: 20 secs: 0.0 (r0.000)\r\n0000083.031 bnkLine: KGI_MW4KP3C020XX.mod SHA1 p\r\n0000083.031 Hashing: 8 "KGI_MW4KP3C020XX.mod" alg: "SHA1"\r\n0000083.140 HashFin: 8 "KGI_MW4KP3C020XX.mod" bytes: 32,256 secs: 0.0 (r0.015)\r\n0000083.140 bnkLine: KGI_LWEKP3C001XX.mod SHA1 p\r\n0000083.140 Hashing: 9 "KGI_LWEKP3C001XX.mod" alg: "SHA1"\r\n0000083.265 HashFin: 9 "KGI_LWEKP3C001XX.mod" bytes: 32,256 secs: 0.0 (r0.031)\r\n0000083.265 bnkLine: KGI_MWPSYSC060GA.mod SHA1 p\r\n0000083.265 Hashing: 10 "KGI_MWPSYSC060GA.mod" alg: "SHA1"\r\n0000248.094 HashFin: 10 "KGI_MWPSYSC060GA.mod" bytes: 3,177,248,256 secs: 164.7 (r138.734)\r\n0000248.094 bnkLine: MWBIOSC001XX.mod SHA1 p\r\n0000248.094 Hashing: 11 "MWBIOSC001XX.mod" alg: "SHA1"\r\n0000248.750 HashFin: 11 "MWBIOSC001XX.mod" bytes: 2,882,058 secs: 0.3 (r0.219)\r\n0000248.765 bnkLine: KGI_LLWRTVC010XX.mod SHA1 p\r\n0000248.765 Hashing: 12 "KGI_LLWRTVC010XX.mod" alg: "SHA1"\r\n0000248.906 HashFin: 12 "KGI_LLWRTVC010XX.mod" bytes: 524,288 secs: 0.1 (r0.062)\r\n0000248.906 bnkLine: LLBIOSC004XX.mod SHA1 p\r\n0000248.906 Hashing: 13 "LLBIOSC004XX.mod" alg: "SHA1"\r\n0000249.390 HashFin: 13 "LLBIOSC004XX.mod" bytes: 4,162,058 secs: 0.4 (r0.360)\r\n\r\nG:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK Results:\r\nHash (hex): 0000000000000000000000005D0A05A3B52FEE0564013F5FB49404C6CC98D07C (MSB First i.e. PSA32)\r\nHash (hex): 7CD098CCC60494B45F3F016405EE2FB5A3050A5D000000000000000000000000 (LSB First i.e. HMAC-SHA1)\r\n', 
# stderr=b'')
# [Finished in 250.6s]

    def test_epsigexe_functions(self): 
        self.bnkfile = 'bnkfiles/5D81F_W4QLQ05M.BNK'
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2.bnkfile_validate_epsigexe(self, self.bnkfile, self.seed)
        self.assertTrue(epsigexe_output['returncode'])

        for item in epsigexe_output['results']: 
            print(item)

    def test_verifyFileExists(self): 
        print(self.bnkfile)
        self.assertTrue(epsig2.verifyFileExists(None, self.bnkfile))

    def test_verifyFileExists2(self): 
        self.bnkfile = 'G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK'
        print(self.bnkfile)
        self.seed = '0000000000000000000000000000000000000000'
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2.bnkfile_validate_epsigexe(self, self.bnkfile, self.seed)
        self.assertTrue(epsigexe_output['returncode'])

    def test_dobnk_SHA1(self): 
        self.bnkfile = 'bnkfiles/5D81F_W4QLQ05M.BNK'
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype        

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        expected_result = 'FC1FE2617F2B5EF0C0652FB8D1345738782E6468'

        h = epsig2.dobnk(self, self.bnkfile, blocksize=8192)
        formatted_h = epsig2.format_output(self, str(h), self.options_d) 

        self.assertEqual(formatted_h, expected_result)


    def test_dobnk_SHA256(self): 
        self.bnkfile = 'bnkfiles/5D81F_W4QLQ05M.BNK'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = False 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA256'    
        self.options_d['selectedHashtype'] = self.selectedHashtype        
        self.seed = Seed('0000000000000000000000000000000000000000000000000000000000000000', self.selectedHashtype).seed

        expected_result = '000000000000000000000000FC1FE2617F2B5EF0C0652FB8D1345738782E6468'

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
        self.options_d['selectedHashtype'] = self.selectedHashtype        
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
        self.options_d['selectedHashtype'] = self.selectedHashtype        
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
        self.options_d['selectedHashtype'] = self.selectedHashtype        
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
        self.options_d['selectedHashtype'] = self.selectedHashtype        
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
            "bnkfiles/5D81F.sigs":[
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
            "bnkfiles/SBGEN024.img":[
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
            "bnkfiles/W4QLQ05M.sigs":[
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

                if fp == "bnkfiles/5D81F.sigs": 
                    self.assertEqual(hash_value, '387a1d858b2f32d7f8074f2b33b673b8f5f42339')
                elif fp == "bnkfiles/SBGEN024.img": 
                    self.assertEqual(hash_value, 'c6967f4f9240f15ea742f8d57b347b3142427e51')
                elif fp == "bnkfiles/W4QLQ05M.sigs": 
                    self.assertEqual(hash_value, '6a29e257f317bc9cdbe07d92b576298329354d70')
