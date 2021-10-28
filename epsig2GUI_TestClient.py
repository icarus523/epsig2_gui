import unittest
import os 

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
            self.binfile = 'tests/A35E4_35I_CSC_Q0A_QB.bin'

        elif (os.name == 'posix'): # Linux OS
            self.bnkfile = 'bnkfiles/5D81F_W4QLQ05M.BNK'
            self.bnkfile2 = 'bnkfiles/Test_Game.BNK'
            self.bnkfile_list = [ self.bnkfile , self.bnkfile2 ]

            self.binfile = 'tests/A35E4_35I_CSC_Q0A_QB.bin'

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