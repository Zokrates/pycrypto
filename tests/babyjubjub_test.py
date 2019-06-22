import unittest

from os import urandom

from zokrates_pycrypto.field import FQ
from zokrates_pycrypto.babyjubjub import Point
from zokrates_pycrypto.babyjubjub import JUBJUB_E, JUBJUB_C, JUBJUB_L


class TestJubjub(unittest.TestCase):
    def _point_g(self):
        return Point.generator()

    def _point_g_dbl(self):
        x = 17324563846726889236817837922625232543153115346355010501047597319863650987830
        y = 20022170825455209233733649024450576091402881793145646502279487074566492066831
        return Point(FQ(x), FQ(y))

    # Hardcoded for now till we have automatic test generation for ZoKrates test framework
    def _fe_rnd(self):
        return [FQ(1234), FQ(5678), FQ(7890)]

    def test_double_via_add(self):
        G = self._point_g()
        G_dbl = G.add(G)
        self.assertEqual(G_dbl, self._point_g_dbl())

    def test_cyclic(self):
        G = self._point_g()
        self.assertEqual(G.mult(JUBJUB_E + 1), G)

    def test_mult_2(self):
        G = self._point_g()
        G_mult2 = G.mult(2)
        self.assertEqual(G_mult2, self._point_g_dbl())

    def test_lower_order_p(self):
        lp = Point(
            FQ(
                4342719913949491028786768530115087822524712248835451589697801404893164183326
            ),
            FQ(
                4826523245007015323400664741523384119579596407052839571721035538011798951543
            ),
        )
        lp_c = lp.mult(JUBJUB_C)
        self.assertEqual(lp_c, Point.infinity())
        lp_l = lp.mult(JUBJUB_L)
        self.assertEqual(lp_l, lp)

    def test_multiplicative(self):
        G = self._point_g()
        a, b, _ = self._fe_rnd()
        A = G.mult(a)
        B = G.mult(b)

        ab = (a.n * b.n) % JUBJUB_E  # 7006652
        AB = G.mult(ab)
        self.assertEqual(A.mult(b), AB)
        self.assertEqual(B.mult(a), AB)

    def test_associativity(self):
        G = self._point_g()

        a, b, c = self._fe_rnd()

        res1 = G.mult(a).mult(b).mult(c)
        res2 = G.mult(b).mult(c).mult(a)
        res3 = G.mult(c).mult(a).mult(b)

        self.assertEqual(res1, res2)
        self.assertEqual(res2, res3)
        self.assertEqual(res1, res3)

    def test_identities(self):
        G = self._point_g()
        self.assertEqual(G + Point.infinity(), G)
        self.assertEqual(G + G.neg(), Point.infinity())


if __name__ == "__main__":
    unittest.main()
