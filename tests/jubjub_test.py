import unittest

from os import urandom

from znakes.fields import BLS12_381Field as FQ
from znakes.curves import JubJub


JUBJUB_C = JubJub.JUBJUB_C
JUBJUB_E = JubJub.JUBJUB_E


class TestJubjub(unittest.TestCase):
    def _point_g(self):
        return JubJub.generator()

    # Hardcoded for now till we have automatic test generation for ZoKrates test framework
    def _fe_rnd(self):
        return [FQ(1234), FQ(5678), FQ(7890)]

    def test_double(self):
        G = self._point_g()
        G_times_2 = G.mult(2)
        G_dbl = G.add(G)
        self.assertEqual(G_times_2, G_dbl)

    # test taken form: https://github.com/gtank/jubjub/blob/main/jubjub_test.go#L47
    def test_cyclic(self):
        G = self._point_g()
        scalar = 6554484396890773809930967563523245729705921265872317281365359162392183254199
        self.assertEqual(G.mult(JUBJUB_C).mult(scalar), JubJub.infinity())

    # TODO: find values for JubJub
    # def test_lower_order_p(self):
    #     lp = JubJub(
    #         FQ(
    #             4342719913949491028786768530115087822524712248835451589697801404893164183326
    #         ),
    #         FQ(
    #             4826523245007015323400664741523384119579596407052839571721035538011798951543
    #         ),
    #     )
    #     lp_c = lp.mult(JUBJUB_C)
    #     self.assertEqual(lp_c, JubJub.infinity())
    #     lp_l = lp.mult(JUBJUB_L)
    #     self.assertEqual(lp_l, lp)

    def test_multiplicative(self):
        G = self._point_g()
        a, b, _ = self._fe_rnd()
        A = G.mult(a)
        B = G.mult(b)

        ab = (a.n * b.n) % JUBJUB_E  # 7006652
        AB = G.mult(FQ(ab))
        self.assertEqual(A.mult(b), AB)
        self.assertEqual(B.mult(a), AB)

    def test_multiplicative_associativity(self):
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
        self.assertEqual(G + JubJub.infinity(), G)
        self.assertEqual(G + G.neg(), JubJub.infinity())


if __name__ == "__main__":
    unittest.main()
