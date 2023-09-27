import unittest
from os import urandom

from zokrates_pycrypto.curves import BabyJubJub, JubJub
from zokrates_pycrypto.eddsa import PublicKey, PrivateKey


class TestEdDSA(unittest.TestCase):
    def test_signverify_babyjubjub(self):
        # Hardcoded for now till we have automatic test generation for ZoKrates test framework
        key = 1997011358982923168928344992199991480689546837621580239342656433234255379025

        sk = PrivateKey(key, curve=BabyJubJub)
        msg = urandom(32)
        sig = sk.sign(msg)

        pk = PublicKey.from_private(sk)
        self.assertTrue(pk.verify(sig, msg))

    def test_signverify_jubjub(self):
        # Hardcoded for now till we have automatic test generation for ZoKrates test framework
        key = 1997011358982923168928344992199991480689546837621580239342656433234255379025

        sk = PrivateKey(key, curve=JubJub)
        msg = urandom(32)
        sig = sk.sign(msg)

        pk = PublicKey.from_private(sk)
        self.assertTrue(pk.verify(sig, msg))

    def test_random_signverify_babyjubjub(self):
        # Hardcoded for now till we have automatic test generation for ZoKrates test framework
        key = 1997011358982923168928344992199991480689546837621580239342656433234255379025

        sk = PrivateKey.from_rand(curve=BabyJubJub)
        msg = urandom(32)
        sig = sk.sign(msg)

        pk = PublicKey.from_private(sk)
        self.assertTrue(pk.verify(sig, msg))

    def test_random_signverify_jubjub(self):
        # Hardcoded for now till we have automatic test generation for ZoKrates test framework
        key = 1997011358982923168928344992199991480689546837621580239342656433234255379025

        sk = PrivateKey.from_rand(curve=JubJub)
        msg = urandom(32)
        sig = sk.sign(msg)

        pk = PublicKey.from_private(sk)
        self.assertTrue(pk.verify(sig, msg))


if __name__ == "__main__":
    unittest.main()
