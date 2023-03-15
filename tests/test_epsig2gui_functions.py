import unittest
import os
import csv
import epsig2_gui

from epsig2GUI_TestClient import epsig2GUI_TestClient
from epsig2_gui import Seed, epsig2_gui
from epsig2 import epsig2

from epsig2GUI_TestClient import BNK_FILE_REMOTE, BNK_FILE_REMOTE2, \
    BNK_FILE_REMOTE3, BIN_FILE_REMOTE, BNK_FILE_LOCAL, BNK_FILE_LOCAL_BAD, BNK_FILE_LOCAL_BAD2, BNK_FILE_REMOTE4

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
    # SSAN: 168124

    # MSL Entry for April 2023
    # 2023,04,33395973,77333236,61486D76,46644E50,33475972,6F4D4248,616C4C32,627A726C,5A366C53,36413348,3571594D,65375268,6844526B,756B4948,72425839,76754166,58503037,39616674,76474472,5239366E,48667763,44623652,68776F45,72613442,56624357,4953684C,4B396169,54547A7A,51316434,69435050,46396D73

    # PSL Entry for April 2023
    # FORTUNE GONG DRAGON DYNASTY DU,01,2023,04,0000168124,BF70AC54,09F2934F,F93CEFF6,FA17B4B0,31BA0A85,A72559A8,7524B7FB,5DF7C575,143FC205,66720832,E374B6C7,496BEEAB,527B844A,B0F667BB,2AB6E177,2C89E4C7,4D013DDF,D9350771,4ED7D4C5,57104F10,BE73421B,50A3E155,0BF3E4DD,723F5541,647064CC,139038B7,51D3BE75,D43474DF,B7F3B0D0,113D524B,F16ADF7E    @unittest.skipIf(os.path.isfile(BNK_FILE_REMOTE3) == False, "file not found")

    # Seed: 5A366C53 (day 9 seed)
    # Expected Results: 143FC205 (expected day 9 result)
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

    # BNK_FILE_REMOTE4 = 'G:/OLGR-TECHSERV/BINIMAGE/IGT/00611_X127E_0_004.bnk'
    # SSAN: 239717

    # MSL Entry for March:
    # 2023 2023,03,6E527A46,4D6F4452,324B4935,4A61614A,666F6648,6C717739,4633706E,4C766672,42736C62,614F526E,6D447371,32794F39,764F6834,4467454C,725A6A53,4247696E,6D716D32,33697846,33506B54,76386174,4F614146,64324D78,5935327A,4D61626C,43647970,616E4734,64616954,38637170,4C565467,4B4B4952,53436246

    # PSL Entry for March 2023:
    # LUCKY GONG LINK EMPERORS LIONS,01,2023,03,0000239717,881597AD,2AB23B18,06F649DF,C6508C29,EE7AA517,B5EE0EF8,4DD5A6EB,335C425C,648A5AE3,77C0F494,2CC7F0AB,13DDC894,B5041B5E,BA859BF5,19B272D9,2F4522D3,C7817B62,25CE4BB2,516F2275,BBC78C73,938EDE44,5EFC8B12,12DF59DB,DE2E4D89,722BA021,9B317FE8,3B7E5641,DDB549E3,1422CE3E,A3F055C1,C10F03CB

    # Seed 42736C62
    # Expected Results: 648A5AE3 (9 day result)
    @unittest.skipIf(os.path.isfile(BNK_FILE_REMOTE4) == False, "file not found")
    def test_epsig2_start_BNK_with_seed_648A5AE3_reverse2(self): 
        self.bnkfile = BNK_FILE_REMOTE4
        self.mandir = os.path.dirname(self.bnkfile)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   
        self.options_d['use_epsigexe'] = True
        self.options_d['reverse'] = True # qcas format

        self.seed = epsig2.getQCAS_Expected_output(self, Seed('42736C6200000000000000000000000000000000', self.selectedHashtype).seed)
                        
        # epsig.exe can't do bin files, by default the script will revert to python3 epsig2:
        my_p = epsig2(self.seed, self.bnkfile, self.options_d, self.cache_dict, self.selectedHashtype, False) 
        my_p.processfile()

        localhash = my_p.xor_result

        self.assertEqual(localhash, '0xe35a8a64a725b52b6caadfa1926f0e90bd36f678', localhash)
        formatted_h = epsig2.format_output(self, localhash, self.options_d)
        self.assertEqual(formatted_h, '648A5AE3', formatted_h) 