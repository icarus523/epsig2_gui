import unittest

from epsig2GUI_TestClient import epsig2GUI_TestClient
from epsig2_gui import epsig2

class test_HashingFiles_file(epsig2GUI_TestClient):      

    def test_dobnk_SHA1(self): 
        expected_result = '94C5809DEA787F1584A5CA6CFDF4210A9E831018'
        seed = "0000000000000000000000000000000000000000000000000000000000000000"
        hash_type = "HMAC-SHA1"
        myp = epsig2(seed, self.bnkfile, self.options_d, self.cache_dict, hash_type)
        self.assertEqual(myp.xor_result,expected_result)

    def test_dobnk_HMAC_SHA256(self): 
        seed = "0000000000000000000000000000000000000000000000000000000000000000"
        hash_type = "HMAC-SHA256"
        myp = epsig2(seed, self.bnkfile, self.options_d, self.cache_dict, hash_type)
        expected_result = '7DC5FE3E67770FF75C4F4C00FE64C8FDC95B689D8A178A1A6DD22CC65FCD0720'
        self.assertEqual(myp.xor_result,expected_result)


    def test_dobin_SHA1(self): 
        expected_result = '0E2DAD2DE1D15EB13CD8553E0A2BBA7127AF4796'
        seed = "0000000000000000000000000000000000000000000000000000000000000000"
        hash_type = "HMAC-SHA1"
        myp = epsig2(seed, self.binfile, self.options_d, self.cache_dict, hash_type)
        self.assertEqual(myp.xor_result,expected_result)

    def test_dobin_HMAC_SHA256(self): 
        seed = "0000000000000000000000000000000000000000000000000000000000000000"
        hash_type = "HMAC-SHA256"
        myp = epsig2(seed, self.binfile, self.options_d, self.cache_dict, hash_type)
        expected_result = '92971BEB3F6D486BDB86402E8E9E2C726D1173D7999F3F7188F3884663181FF0'
        self.assertEqual(myp.xor_result,expected_result)

