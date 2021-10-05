import unittest

from epsig2GUI_TestClient import epsig2GUI_TestClient
from epsig2_gui import epsig2, CacheFile

class test_cache_functions_file(epsig2GUI_TestClient):      

	def test_init(self): 
		fname = "epsig2_cachefile_test_empty.json"

		test_cache_file = CacheFile(fname)

		self.assertEqual(test_cache_file.cache_dict, {})

	def test_expected_import_cache(self): 
		fname = "epsig2_cachefile_test "