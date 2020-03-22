import unittest

from epsig2GUI_TestClient import epsig2GUI_TestClient
from epsig2_gui import epsig2

class test_epsig2_functions(epsig2GUI_TestClient):      

    def test_format_output(self): 
        inputstr = '0x94C5809DEA787F1584A5CA6CFDF4210A9E831018'

        self.options_d['cache_file_f'] = False
        self.options_d['uppercase'] = True
        self.options_d['eightchar'] = False
        self.options_d['reverse'] = False
        self.options_d['usr_cache_file'] = False
        self.selectedHashtype = 'HMAC-SHA1'

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

