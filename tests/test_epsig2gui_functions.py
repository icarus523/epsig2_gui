import unittest
import os
import csv
import epsig2_gui

from epsig2GUI_TestClient import epsig2GUI_TestClient
from epsig2_gui import Seed, epsig2_gui
from epsig2 import epsig2

from epsig2GUI_TestClient import BNK_FILE_REMOTE, BNK_FILE_REMOTE2, \
    BNK_FILE_REMOTE3, BIN_FILE_REMOTE, BNK_FILE_LOCAL, BNK_FILE_LOCAL_BAD, BNK_FILE_LOCAL_BAD2

class test_epsig2gui_functions(epsig2GUI_TestClient):   

    # 'G:/OLGR-TECHSERV/BINIMAGE/VID/A51D4_05I_CSD_50D_5B.bin'
    @unittest.skipIf(os.path.isfile(BIN_FILE_REMOTE) == False, "file not found")
    def test_epsig2_start_BIN_zero_seed_reverse(self): 
        self.bnkfile = BIN_FILE_REMOTE # G:/OLGR-TECHSERV/BINIMAGE/VID/A51D4_05I_CSD_50D_5B.bin
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   
        self.options_d['use_epsigexe'] = True

        self.seed = epsig2.getQCAS_Expected_output(self, Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed)

        # epsig.exe can't do bin files, by default the script will revert to python3 epsig2:
        my_p = epsig2(self.seed, self.bnkfile, self.options_d, self.cache_dict, self.selectedHashtype, False) 
        my_p.processfile()

        localhash = my_p.xor_result

        self.assertEqual(localhash, '0xa0d0cbdf41b5ddc89c0cd5a0f5c17115a1f863c1', localhash)
        formatted_h = epsig2.format_output(self, localhash, self.options_d)
        self.assertEqual(formatted_h, 'A0D0CBDF41B5DDC89C0CD5A0F5C17115A1F863C1')             

    # 'G:/OLGR-TECHSERV/BINIMAGE/IGT/SD_00264_X10F6_1_001.bnk'
    @unittest.skipIf(os.path.isfile(BNK_FILE_REMOTE3) == False, "file not found")
    def test_epsig2_start_BNK_with_seed_5A366C53_reverse(self): 
        self.bnkfile = BNK_FILE_REMOTE3
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   
        self.options_d['use_epsigexe'] = True
        self.options_d['reverse'] = True # qcas format

        self.seed = epsig2.getQCAS_Expected_output(self, Seed('5A366C5300000000000000000000000000000000', self.selectedHashtype).seed)
                        
        # epsig.exe can't do bin files, by default the script will revert to python3 epsig2:
        my_p = epsig2(self.seed, self.bnkfile, self.options_d, self.cache_dict, self.selectedHashtype, False) 
        my_p.processfile()

        localhash = my_p.xor_result

        self.assertEqual(localhash, '0x5c23f142726cee426c83fd5fc7bf5b54cfd862e', localhash)
        formatted_h = epsig2.format_output(self, localhash, self.options_d)
        self.assertEqual(formatted_h, '143FC205', formatted_h)          