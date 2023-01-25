import unittest
import os
import csv
import epsig2_gui

from epsig2GUI_TestClient import epsig2GUI_TestClient
from epsig2_gui import Seed, epsig2_gui
from epsig2 import epsig2


BNK_FILE_REMOTE = 'G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK'
BNK_FILE_REMOTE2 = 'G:/OLGR-TECHSERV/BINIMAGE/Wymac/G0351_004_301103.BNK'
BNK_FILE_LOCAL = 'bnkfiles/5D81F_W4QLQ05M.BNK'
BIN_FILE_LOCAL = 'bnkfiles/A35E4_35I_CSC_Q0A_QB.BIN'
BNK_FILE_LOCAL_BAD = 'bnkfiles/5D81F_W4QLQ05M_2.BNK' # missing 'p'
BNK_FILE_LOCAL_BAD2 = 'bnkfiles/5D81F_W4QLQ05M_3.BNK' # two file suffixes
class test_epsig2gui_functions(epsig2GUI_TestClient):   

# CompletedProcess(args=['G:/OLGR-TECHSERV/BINIMAGE/epsig3_7.exe', 'G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK', '0000000000000000000000000000000000000000000000000000000000000000'], 
# returncode=0, 
# stdout=b'0000000.000 \r\n\r\nEPSIG.EXE Version 3.7 Copyright The State of Queensland 1999-2015\r\n0000000.000 Started at   Fri Oct 01 15:15:24 2021\r\n G:\\OLGR-TECHSERV\\BINIMAGE\\epsig3_7.exe G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK 0000000000000000000000000000000000000000000000000000000000000000 \r\n0000000.000  Allocating buffer 262144 bytes\r\n\r\n0000000.000 BNK File Test Mode\r\nInput BNK File: G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK\r\nSeed (32 bytes hex, LSB First) : 0000000000000000000000000000000000000000000000000000000000000000 \r\n0000000.000 BNKFILE: 1645GDXX_393_004.BNK\r\n0000000.094 bnkLine: M165MLT030GA00.mod SHA1 S\r\n0000000.094 Hashing: 1 "M165MLT030GA00.mod" alg: "SHA1"\r\n0000010.719 HashFin: 1 "M165MLT030GA00.mod" bytes: 188,738,048 secs: 10.5 (r9.111)\r\n0000010.719 bnkLine: M166MLT030GA00.mod SHA1 p\r\n0000010.719 Hashing: 2 "M166MLT030GA00.mod" alg: "SHA1"\r\n0000022.781 HashFin: 2 "M166MLT030GA00.mod" bytes: 170,754,560 secs: 11.7 (r10.502)\r\n0000022.781 bnkLine: M167MLT030GA00.mod SHA1 p\r\n0000022.781 Hashing: 3 "M167MLT030GA00.mod" alg: "SHA1"\r\n0000039.234 HashFin: 3 "M167MLT030GA00.mod" bytes: 259,789,312 secs: 16.1 (r14.345)\r\n0000039.234 bnkLine: KGI_M164SPB010GA00.mod SHA1 p\r\n0000039.234 Hashing: 4 "KGI_M164SPB010GA00.mod" alg: "SHA1"\r\n0000054.125 HashFin: 4 "KGI_M164SPB010GA00.mod" bytes: 207,159,808 secs: 14.5 (r12.876)\r\n0000054.125 bnkLine: KGI_MWPGCMC133GA00.mod SHA1 p\r\n0000054.125 Hashing: 5 "KGI_MWPGCMC133GA00.mod" alg: "SHA1"\r\n0000072.422 HashFin: 5 "KGI_MWPGCMC133GA00.mod" bytes: 252,955,136 secs: 17.9 (r15.887)\r\n0000072.422 bnkLine: LLPSYSC100XX_QD393XXX.mod SHA1 p\r\n0000072.422 Hashing: 6 "LLPSYSC100XX_QD393XXX.mod" alg: "SHA1"\r\n0000082.922 HashFin: 6 "LLPSYSC100XX_QD393XXX.mod" bytes: 119,013,888 secs: 10.1 (r9.203)\r\n0000082.922 bnkLine: LRAMCLC011QD.bin SHA1 p\r\n0000082.937 Hashing: 7 "LRAMCLC011QD.bin" alg: "SHA1"\r\n0000083.031 HashFin: 7 "LRAMCLC011QD.bin" bytes: 20 secs: 0.0 (r0.000)\r\n0000083.031 bnkLine: KGI_MW4KP3C020XX.mod SHA1 p\r\n0000083.031 Hashing: 8 "KGI_MW4KP3C020XX.mod" alg: "SHA1"\r\n0000083.140 HashFin: 8 "KGI_MW4KP3C020XX.mod" bytes: 32,256 secs: 0.0 (r0.015)\r\n0000083.140 bnkLine: KGI_LWEKP3C001XX.mod SHA1 p\r\n0000083.140 Hashing: 9 "KGI_LWEKP3C001XX.mod" alg: "SHA1"\r\n0000083.265 HashFin: 9 "KGI_LWEKP3C001XX.mod" bytes: 32,256 secs: 0.0 (r0.031)\r\n0000083.265 bnkLine: KGI_MWPSYSC060GA.mod SHA1 p\r\n0000083.265 Hashing: 10 "KGI_MWPSYSC060GA.mod" alg: "SHA1"\r\n0000248.094 HashFin: 10 "KGI_MWPSYSC060GA.mod" bytes: 3,177,248,256 secs: 164.7 (r138.734)\r\n0000248.094 bnkLine: MWBIOSC001XX.mod SHA1 p\r\n0000248.094 Hashing: 11 "MWBIOSC001XX.mod" alg: "SHA1"\r\n0000248.750 HashFin: 11 "MWBIOSC001XX.mod" bytes: 2,882,058 secs: 0.3 (r0.219)\r\n0000248.765 bnkLine: KGI_LLWRTVC010XX.mod SHA1 p\r\n0000248.765 Hashing: 12 "KGI_LLWRTVC010XX.mod" alg: "SHA1"\r\n0000248.906 HashFin: 12 "KGI_LLWRTVC010XX.mod" bytes: 524,288 secs: 0.1 (r0.062)\r\n0000248.906 bnkLine: LLBIOSC004XX.mod SHA1 p\r\n0000248.906 Hashing: 13 "LLBIOSC004XX.mod" alg: "SHA1"\r\n0000249.390 HashFin: 13 "LLBIOSC004XX.mod" bytes: 4,162,058 secs: 0.4 (r0.360)\r\n\r\nG:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK Results:\r\nHash (hex): 0000000000000000000000005D0A05A3B52FEE0564013F5FB49404C6CC98D07C (MSB First i.e. PSA32)\r\nHash (hex): 7CD098CCC60494B45F3F016405EE2FB5A3050A5D000000000000000000000000 (LSB First i.e. HMAC-SHA1)\r\n', 
# stderr=b'')
# [Finished in 250.6s]

    @unittest.skipIf(os.path.isfile(BNK_FILE_LOCAL) == False, "file not found")
    def test_epsigexe_start_BNK(self): 
        self.bnkfile = BNK_FILE_LOCAL # bnkfiles/5D81F_W4QLQ05M.BNK
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, self.bnkfile, self.seed)
        
        self.assertTrue(epsigexe_output['returncode'], epsigexe_output['returncode'])
        self.assertEqual(epsigexe_output['hash_result'], 'FC1FE2617F2B5EF0C0652FB8D1345738782E6468000000000000000000000000' )

    @unittest.skipIf(os.path.isfile(BNK_FILE_REMOTE) == False, "file not found")
    def test_epsigexe_start_BNK_REMOTE(self): 
        self.bnkfile = BNK_FILE_REMOTE # 'G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK'
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   
        self.options_d['use_epsigexe'] = True

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, self.bnkfile, self.seed)
        
        self.assertTrue(epsigexe_output['returncode'], epsigexe_output['returncode'])
        self.assertEqual(epsigexe_output['hash_result'], '7CD098CCC60494B45F3F016405EE2FB5A3050A5D000000000000000000000000' )

    # Note this doesn't work, as epsig.exe doesn't support BIN files. 
    # @unittest.skipIf(os.path.isfile(BIN_FILE_LOCAL) == False, "file not found")
    # def test_epsigexe_start_BIN(self): 
    #     self.bnkfile = BIN_FILE_LOCAL # 'bnkfiles/A35E4_35I_CSC_Q0A_QB.BIN'
    #     self.seed = '0000000000000000000000000000000000000000'
    #     self.mandir = os.path.dirname(self.bnkfile)
    #     self.options_d['cache_file_f'] = True 
    #     self.LogOutput = list() 
    #     self.selectedHashtype = 'HMAC-SHA1'    
    #     self.options_d['selectedHashtype'] = self.selectedHashtype   
    #     self.options_d['use_epsigexe'] = True

    #     self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

    #     epsigexe_output = epsig2_gui.epsigexe_start2(self, self.bnkfile, self.seed)
                
    #     print(epsigexe_output)
    #     # print(epsigexe_output['hash_result'], self.bnkfile)
        
    #     self.assertTrue(epsigexe_output['returncode'], epsigexe_output['returncode'])
    #     self.assertEqual(epsigexe_output['hash_result'], '0XE2DAD2DE1D15EB13CD8553E0A2BBA7127AF4796' )

    @unittest.skipIf(os.path.isfile(BNK_FILE_LOCAL) == False, "file not found")
    def test_epsig2gui_display_options_uppercase(self): 
        self.bnkfile = BNK_FILE_LOCAL # 'bnkfiles/5D81F_W4QLQ05M.BNK'
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        
        self.options_d['selectedHashtype'] = self.selectedHashtype   
        self.options_d['uppercase'] = True

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, self.bnkfile, self.seed)
        self.assertTrue(epsigexe_output['returncode'])    
        formatted_h = epsig2.format_output(self, epsigexe_output['hash_result'], self.options_d)            
        self.assertEqual(formatted_h, 'FC1FE2617F2B5EF0C0652FB8D1345738782E6468000000000000000000000000')


    @unittest.skipIf(os.path.isfile(BNK_FILE_LOCAL) == False, "file not found")
    def test_epsig2gui_display_options_lowercase(self): 
        self.bnkfile = BNK_FILE_LOCAL # 'bnkfiles/5D81F_W4QLQ05M.BNK'
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        
        self.options_d['selectedHashtype'] = self.selectedHashtype   
        self.options_d['uppercase'] = False

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, self.bnkfile, self.seed)
        self.assertTrue(epsigexe_output['returncode'])    
        formatted_h = epsig2.format_output(self, epsigexe_output['hash_result'], self.options_d)
        self.assertEqual(formatted_h, 'fc1fe2617f2b5ef0c0652fb8d1345738782e6468000000000000000000000000')


    @unittest.skipIf(os.path.isfile(BNK_FILE_LOCAL) == False, "file not found")
    def test_epsig2gui_display_options_eightcharspace_lowercase(self): 
        self.bnkfile = BNK_FILE_LOCAL # 'bnkfiles/5D81F_W4QLQ05M.BNK'
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        
        self.options_d['selectedHashtype'] = self.selectedHashtype   
        self.options_d['eightchar'] = True
        self.options_d['uppercase'] = False

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, self.bnkfile, self.seed)
        self.assertTrue(epsigexe_output['returncode'])    
        formatted_h = epsig2.format_output(self, epsigexe_output['hash_result'], self.options_d)
        self.assertEqual(formatted_h, 'fc1fe261 7f2b5ef0 c0652fb8 d1345738 782e6468 00000000 00000000 00000000')        

    @unittest.skipIf(os.path.isfile(BNK_FILE_LOCAL) == False, "file not found")
    def test_epsig2gui_start2(self): 
        self.bnkfile = BNK_FILE_LOCAL # 'bnkfiles/5D81F_W4QLQ05M.BNK'
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = False 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        
        self.options_d['selectedHashtype'] = self.selectedHashtype   
        self.options_d['uppercase'] = False

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, self.bnkfile, self.seed)
        self.assertTrue(epsigexe_output['returncode'], epsigexe_output['returncode'])    
        formatted_h = epsig2.format_output(self, epsigexe_output['hash_result'], self.options_d)
        self.assertEqual(formatted_h, 'fc1fe2617f2b5ef0c0652fb8d1345738782e6468000000000000000000000000')             

    @unittest.skipIf(os.path.isfile(BNK_FILE_LOCAL) == False, "file not found")
    def test_epsig2gui_start2_bad_bnkfile_format(self): 
        self.bnkfile = BNK_FILE_LOCAL_BAD # W4QLQ05M.sigs SHA1 
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = False 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        
        self.options_d['selectedHashtype'] = self.selectedHashtype   
        self.options_d['uppercase'] = False

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, self.bnkfile, self.seed)
        self.assertFalse(epsigexe_output['returncode'], epsigexe_output['returncode'])    

    @unittest.skipIf(os.path.isfile(BNK_FILE_LOCAL_BAD2) == False, "file not found")
    def test_two_file_suffixes_in_bnkfile(self): 
        self.bnkfile = BNK_FILE_LOCAL_BAD2 # W4QLQ05M.sigs.sha1
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = False 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        
        self.options_d['selectedHashtype'] = self.selectedHashtype   
        self.options_d['uppercase'] = False

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, self.bnkfile, self.seed)
        self.assertFalse(epsigexe_output['returncode'], epsigexe_output['returncode'])        

    @unittest.skipIf(os.path.isfile(BNK_FILE_REMOTE2) == False, "file not found")
    def test_epsigexe_start_BNK_Starting_Zero_result(self): 
        self.bnkfile = BNK_FILE_REMOTE2 # G0351_004_301103
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   
        self.options_d['use_epsigexe'] = True

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, self.bnkfile, self.seed)
        
        self.assertTrue(epsigexe_output['returncode'], epsigexe_output['returncode'])
        self.assertEqual(epsigexe_output['hash_result'], '0B7C877F2F6D71D52143E440C4F1AD11B7279DE8000000000000000000000000' )
