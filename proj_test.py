import unittest
import enc_dec
import bech32m

# Presently testing 3 pairs of valid bech32m addressess

class Testenc_dec(unittest.TestCase):

    def test_encode_scriptPubkey(self):
    	
        encoded_string = enc_dec.encode_scriptPubkey("bc","5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6")
        self.assertEqual(encoded_string, "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y")


    def test_encode_str(self):
        """Test whether address encoding takes place correctly on user input"""
        encoded_str = enc_dec.encode_str("7468697369736D7974657374737472696E67")
        self.assertEqual(encoded_str, "bc1pusk379h4yx6jus99caetl4x70944gm2sp8v7jz")
    
    def test_decode_bech32(self):
        """Test whether a valid Bech32 address is decoded to correct value"""
        decoded_str = enc_dec.decode_bech32("bc", "BC1SW50QGDZ25J")
        self.assertEqual(decoded_str, "751e")



if __name__ == "__main__":
    unittest.main()

