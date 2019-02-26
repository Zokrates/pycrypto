import unittest

from os import urandom

from field import FQ
from babyjubjub import Point
from babyjubjub import JUBJUB_E
from eddsa import Signature, PrivateKey, PublicKey

class TestEddsa(unittest.TestCase):

	def _point_a(self):
		x = 0x274dbce8d15179969bc0d49fa725bddf9de555e0ba6a693c6adb52fc9ee7a82c
		y = 0x5ce98c61b05f47fe2eae9a542bd99f6b2e78246231640b54595febfd51eb853
		return Point(FQ(x), FQ(y))

	def _point_a_double(self):
		x = 6890855772600357754907169075114257697580319025794532037257385534741338397365
		y = 4338620300185947561074059802482547481416142213883829469920100239455078257889
		return Point(FQ(x), FQ(y))

	def test_double_via_add(self):
		a = self._point_a()
		a_dbl = a.add(a)
		self.assertEqual(a_dbl, self._point_a_double())

	def test_cyclic(self):
		G = self._point_a()
		self.assertEqual(G * (JUBJUB_E+1), G)

	def test_mult_2(self):
		p = self._point_a()
		q = p.mult(2)
		self.assertEqual(q, self._point_a_double())
if __name__ == "__main__":
	unittest.main()