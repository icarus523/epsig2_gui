import unittest
import os
import csv
import epsig2_gui

from epsig2GUI_TestClient import epsig2GUI_TestClient
from epsig2_gui import Seed, epsig2_gui

class test_epsig2gui_manufacturers_BNK_test(epsig2GUI_TestClient):   

    def test_ARI(self): 
        ARI_BNK = 'G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1645GDXX_393_004.BNK'

        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(ARI_BNK)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, ARI_BNK, self.seed)
        
        self.assertTrue(epsigexe_output['returncode'], epsigexe_output['returncode'])
        self.assertEqual(epsigexe_output['hash_result'], '7CD098CCC60494B45F3F016405EE2FB5A3050A5D000000000000000000000000', epsigexe_output['hash_result'])

    def test_AGT(self): 
        AGT_BNK = 'G:/OLGR-TECHSERV/BINIMAGE/AGT/GDQL332F_J06F_003.bnk'
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(AGT_BNK)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, AGT_BNK, self.seed)
        
        self.assertTrue(epsigexe_output['returncode'], epsigexe_output['returncode'])
        self.assertEqual(epsigexe_output['hash_result'], '187BFAE7AA142A1B103C813DB8524A3241A3B901000000000000000000000000')

    def test_SGGaming(self): 
        SGGaming_BNK = 'G:/OLGR-TECHSERV/BINIMAGE/VID/DBCCQL1B_06B_2401.bnk'
        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(SGGaming_BNK)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, SGGaming_BNK, self.seed)
        
        self.assertTrue(epsigexe_output['returncode'], epsigexe_output['returncode'])
        self.assertEqual(epsigexe_output['hash_result'], '631401C7FA45C20EDAD7DEFCAC82A1E672B69DC3000000000000000000000000')

    def test_Konami(self): 
        # Note - this results in string that starts with 0
        Konami_BNK = 'G:/OLGR-TECHSERV/BINIMAGE/KONAMI/1815QDXX_395_004.BNK'

        self.seed = '0000000000000000000000000000000000000000'
        self.mandir = os.path.dirname(Konami_BNK)
        self.options_d['cache_file_f'] = True 
        self.LogOutput = list() 
        self.selectedHashtype = 'HMAC-SHA1'    
        self.options_d['selectedHashtype'] = self.selectedHashtype   

        self.seed = Seed('0000000000000000000000000000000000000000', self.selectedHashtype).seed

        epsigexe_output = epsig2_gui.epsigexe_start2(self, Konami_BNK, self.seed)
        
        self.assertTrue(epsigexe_output['returncode'], epsigexe_output['returncode'])
        self.assertEqual(epsigexe_output['hash_result'], '0C37609A43B590C5F8625B9047F24F30F51EBB8A000000000000000000000000')