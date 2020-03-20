import unittest

class epsig2GUI_TestClient(unittest.TestCase): 

	def setUp(self): 
		self.bnkfile = """G:\OLGR-TECHSERV\BINIMAGE\AGT\GDQL163A_1I6A_003.bnk"""
		self.binfile = """G:\OLGR-TECHSERV\BINIMAGE\VID\A35E4_35I_CSC_Q0A_QB.bin"""


        self.options_d = dict() 
        self.options_d['cache_file_f'] = self.useCacheFile.get() == 1
        self.options_d['uppercase'] = self.uppercase.get() == 1
        self.options_d['eightchar'] = self.eightchar.get() == 1
        self.options_d['reverse'] = self.reverse.get() == 1
        self.options_d['usr_cache_file'] = self.CacheFileButtonText.get()
