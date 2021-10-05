import unittest

from epsig2GUI_TestClient import epsig2GUI_TestClient
from epsig2_gui import epsig2, Seed

class test_Seed(epsig2GUI_TestClient): 

    def test_Seed_SHA1_truncation(self): 
        seed = "00000000000000000000000094C5809DEA787F1584A5CA6CFDF4210A9E831018"
        hash_type = "HMAC-SHA1"
        my_seed = Seed(seed, hash_type)
        
        self.assertEqual('00000000000000000000000094C5809DEA787F15', my_seed.seed)

    def test_Seed_SHA256_appending(self): 
        seed = "94C5809DEA787F1584A5CA6CFDF4210A9E831018"
        hash_type = "HMAC-SHA256"
        my_seed = Seed(seed, hash_type)
        
        self.assertEqual('94C5809DEA787F1584A5CA6CFDF4210A9E831018000000000000000000000000', my_seed.seed)

    def test_Seed_SHA256_no_truncation(self): 
        seed = "00000000000000000000000094C5809DEA787F1584A5CA6CFDF4210A9E831018"
        hash_type = "HMAC-SHA256"
        my_seed = Seed(seed, hash_type)
        
        self.assertEqual('00000000000000000000000094C5809DEA787F1584A5CA6CFDF4210A9E831018', my_seed.seed)

