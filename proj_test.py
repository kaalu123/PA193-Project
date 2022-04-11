import unittest
import enc_dec


INVALID_HRP = ["",
               "bsadbhabdshabdsabsnmdsadmsabjfvasdmfmndsbfnmasdcdsnbcnmbcsdbcndsbnnbsnbdsnbnsbcnsdsn",
               "   abcdefdhdhdh",
               ]

VALID_HRP = ["test",
             "122333",
             "?",
             "\/",
             "/!@#$%^?/><~"
             ]


class Testenc_dec(unittest.TestCase):

    def test_encode_pure_bech32m(self):
        self.assertEqual(enc_dec.encode_pure_bech32m("test", "dmVjdG9y", "b64", "bech32m"), "test1wejkxar0wg64ekuu")
        self.assertEqual(enc_dec.encode_pure_bech32m("test", "dmVjdG9y", "b64", "hex"),
                         "746573743177656a6b7861723077673634656b7575")
        self.assertEqual(enc_dec.encode_pure_bech32m("test", "dmVjdG9y", "b64", "b64"), "dGVzdDF3ZWpreGFyMHdnNjRla3V1")
        self.assertEqual(enc_dec.encode_pure_bech32m("test", "dmVjdG9y", "b64", "bin"), b'test1wejkxar0wg64ekuu')

        self.assertEqual(enc_dec.encode_pure_bech32m("test", "766563746f72", "hex", "bech32m"), "test1wejkxar0wg64ekuu")
        self.assertEqual(enc_dec.encode_pure_bech32m("test", "766563746f72", "hex", "hex"),
                         "746573743177656a6b7861723077673634656b7575")
        self.assertEqual(enc_dec.encode_pure_bech32m("test", "766563746f72", "hex", "b64"),
                         "dGVzdDF3ZWpreGFyMHdnNjRla3V1")
        self.assertEqual(enc_dec.encode_pure_bech32m("test", "766563746f72", "hex", "bin"), b'test1wejkxar0wg64ekuu')

        self.assertEqual(enc_dec.encode_pure_bech32m("test", b'\x76\x65\x63\x74\x6f\x72', "bin", "bech32m"),
                         "test1wejkxar0wg64ekuu")
        self.assertEqual(enc_dec.encode_pure_bech32m("test", b'\x76\x65\x63\x74\x6f\x72', "bin", "hex"),
                         "746573743177656a6b7861723077673634656b7575")
        self.assertEqual(enc_dec.encode_pure_bech32m("test", b'\x76\x65\x63\x74\x6f\x72', "bin", "b64"),
                         "dGVzdDF3ZWpreGFyMHdnNjRla3V1")
        self.assertEqual(enc_dec.encode_pure_bech32m("test", b'\x76\x65\x63\x74\x6f\x72', "bin", "bin"),
                         b'test1wejkxar0wg64ekuu')

        self.assertEqual(enc_dec.encode_pure_bech32m("abcdef", "q83v", "b64", "bech32m"), "abcdef140x77khk82w")
        self.assertEqual(enc_dec.encode_pure_bech32m("abcdef", "q83v", "b64", "hex"),
                         "6162636465663134307837376b686b383277")
        self.assertEqual(enc_dec.encode_pure_bech32m("abcdef", "q83v", "b64", "b64"), "YWJjZGVmMTQweDc3a2hrODJ3")
        self.assertEqual(enc_dec.encode_pure_bech32m("abcdef", "q83v", "b64", "bin"), b'abcdef140x77khk82w')

        self.assertEqual(enc_dec.encode_pure_bech32m("abcdef", "abcdef", "hex", "bech32m"), "abcdef140x77khk82w")

        self.assertEqual(enc_dec.encode_pure_bech32m("a", "", "hex", "bech32m"), "a1lqfn3a")
        self.assertEqual(enc_dec.encode_pure_bech32m("a", "", "b64", "bech32m"), "a1lqfn3a")
        self.assertEqual(enc_dec.encode_pure_bech32m("a", b'', "bin", "bech32m"), "a1lqfn3a")

        self.assertEqual(enc_dec.encode_pure_bech32m(
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber1", "",
            "hex", "bech32m"),
                         "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6")
        self.assertEqual(enc_dec.encode_pure_bech32m(
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber1", "",
            "b64", "bech32m"),
                         "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6")
        self.assertEqual(enc_dec.encode_pure_bech32m(
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber1", b'',
            "bin", "bech32m"),
                         "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6")

        self.assertEqual(
            enc_dec.encode_pure_bech32m("abcdef", "ffbbcdeb38bdab49ca307b9ac5a928398a418820", "hex", "bech32m"),
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx")
        self.assertEqual(enc_dec.encode_pure_bech32m("abcdef", "/7vN6zi9q0nKMHuaxakoOYpBiCA=", "b64", "bech32m"),
                         "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx")

        self.assertEqual(enc_dec.encode_pure_bech32m("?", "", "hex", "bech32m"), "?1v759aa")
        self.assertEqual(enc_dec.encode_pure_bech32m("?", "", "b64", "bech32m"), "?1v759aa")
        self.assertEqual(enc_dec.encode_pure_bech32m("?", b'', "bin", "bech32m"), "?1v759aa")

        self.assertEqual(
            enc_dec.encode_pure_bech32m("split", "c5f38b70305f519bf66d85fb6cf03058f3dde463ecd7918f2dc743918f2d", "hex",
                                        "bech32m"), "split1checkupstagehandshakeupstreamerranterredcaperredlc445v")
        self.assertEqual(
            enc_dec.encode_pure_bech32m("split", "xfOLcDBfUZv2bYX7bPAwWPPd5GPs15GPLcdDkY8t", "b64", "bech32m"),
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v")

        self.assertEqual(enc_dec.encode_pure_bech32m("A", "", "hex", "bech32m"), "A1lqfn3a")
        self.assertEqual(enc_dec.encode_pure_bech32m("A", "", "b64", "bech32m"), "A1lqfn3a")
        self.assertEqual(enc_dec.encode_pure_bech32m("A", b'', "bin", "bech32m"), "A1lqfn3a")

        self.assertEqual(enc_dec.encode_pure_bech32m("?", "6162637A7A7A7A7A7A", "hex", "bech32m"),
                         "?1v93xx7n60fa857sqycgct")
        self.assertEqual(enc_dec.encode_pure_bech32m("?", "YWJjenp6enp6", "b64", "bech32m"), "?1v93xx7n60fa857sqycgct")
        self.assertEqual(enc_dec.encode_pure_bech32m("?", b'\x61\x62\x63\x7A\x7A\x7A\x7A\x7A\x7A', "bin", "bech32m"),
                         "?1v93xx7n60fa857sqycgct")

        self.assertEqual(enc_dec.encode_pure_bech32m("test", b'vector', "bin", "bech32m"), "test1wejkxar0wg64ekuu")
        self.assertEqual(enc_dec.encode_pure_bech32m("test", "dmVjdG9y", "b64", "bech32m"), "test1wejkxar0wg64ekuu")


    def test_invalid_hrp(self):
        """Test whether given hrp in invalid"""
        for hrp in INVALID_HRP:
            res = enc_dec.validate_hrp(hrp)
            self.assertEqual(res, False)


    def test_valid_hrp(self):
        for hrp in VALID_HRP:
            """Test whether given hrp in valid"""
            res = enc_dec.validate_hrp(hrp)
            self.assertEqual(res, True)


if __name__ == "__main__":
    unittest.main()

