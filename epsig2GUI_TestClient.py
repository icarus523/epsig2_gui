import unittest
import os 

BNK_FILE_REMOTE = 'G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK'
BNK_FILE_REMOTE2 = 'G:/OLGR-TECHSERV/BINIMAGE/Wymac/G0351_004_301103.BNK'
BNK_FILE_REMOTE3 = 'G:/OLGR-TECHSERV/BINIMAGE/IGT/SD_00264_X10F6_1_001.bnk'

BIN_FILE_REMOTE = 'G:/OLGR-TECHSERV/BINIMAGE/VID/A51D4_05I_CSD_50D_5B.bin'

BIN_FILE_LOCAL = 'bnkfiles/A35E4_35I_CSC_Q0A_QB.BIN'

BNK_FILE_LOCAL = 'bnkfiles/5D81F_W4QLQ05M.BNK'

BNK_FILE_LOCAL_BAD = 'bnkfiles/5D81F_W4QLQ05M_2.BNK' # missing 'p'
BNK_FILE_LOCAL_BAD2 = 'bnkfiles/5D81F_W4QLQ05M_3.BNK' # two file suffixes

USE_NETWORK_DRIVES = False
class epsig2GUI_TestClient(unittest.TestCase): 

    def setUp(self): 
        self.bnkfile = ''
        self.binfile = ''        

        if (os.name == 'nt' and USE_NETWORK_DRIVES): # Windows OS
            self.bnkfile = """G:\OLGR-TECHSERV\BINIMAGE\AGT\GDQL163A_1I6A_003.bnk"""
            self.binfile = """G:\OLGR-TECHSERV\BINIMAGE\VID\A35E4_35I_CSC_Q0A_QB.bin"""

        elif (os.name == 'nt' and USE_NETWORK_DRIVES == False):
            self.bnkfile = 'bnkfiles/5D81F_W4QLQ05M.BNK'
            self.bnkfile2 = 'bnkfiles/Test_Game.BNK'
            self.binfile = 'bnkfiles/A35E4_35I_CSC_Q0A_QB.bin'

        elif (os.name == 'posix'): # Linux OS
            self.bnkfile = 'bnkfiles/5D81F_W4QLQ05M.BNK'
            self.bnkfile2 = 'bnkfiles/Test_Game.BNK'
            self.bnkfile_list = [ self.bnkfile , self.bnkfile2 ]

            self.binfile = 'bnkfiles/A35E4_35I_CSC_Q0A_QB.bin'

        self.options_d = dict() 
        self.options_d['cache_file_f'] = False
        self.options_d['uppercase'] = True
        self.options_d['eightchar'] = False
        self.options_d['reverse'] = False
        self.options_d['usr_cache_file'] = False
        self.options_d['selectedHashtype'] = 'HMAC-SHA1'
        self.options_d['use_epsigexe'] = True
        
        self.cache_dict = {}
        self.user_cache_file = 'epsig2_cachefile_v3.json'
        
    def tearDown(self): 
        self.cache_dict = {}

if __name__ == '__main__':
    unittest.main()