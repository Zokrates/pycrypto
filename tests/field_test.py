import unittest

from znakes.fields import FQ, BN128Field, BLS12_381Field


class TestField(unittest.TestCase):

    class F11(FQ):
        FIELD = 11

    def setUp(self):
        self.zero = self.F11(0)
        self.one = self.F11(1)
        self.two = self.F11(2)
        self.three = self.F11(3)
        self.five = self.F11(5)
        self.eight = self.F11(8)

    def test_zero(self):
        zero = self.F11(11)
        self.assertEqual(zero, self.zero)

    def test_one(self):
        one = self.F11(12)
        self.assertEqual(one, self.one)

    def test_equality(self):
        self.assertEqual(self.one, self.F11(1))
        self.assertNotEqual(self.two, self.three)
        self.assertNotEqual(BN128Field(1), BLS12_381Field(1))

    def test_cyclic(self):
        self.assertEqual(self.F11(12), self.one)
        self.assertEqual(self.F11(23), self.one)

    def test_neg(self):
        self.assertEqual(self.F11(-0), self.zero)
        self.assertEqual(self.F11(-1), self.F11(10))
        self.assertEqual(-self.one, self.F11(10))
        self.assertEqual(-self.three, self.eight)

    def test_sum(self):
        self.assertEqual(self.zero + self.one, self.one)
        self.assertEqual(self.three + self.zero, self.three)

        self.assertEqual(self.three + self.five, self.eight)
        self.assertEqual(self.five + self.three, self.eight)

        self.assertEqual(self.five + self.eight, self.two)
        self.assertEqual(self.F11(12) + self.F11(23), self.two)

    def test_sub(self):
        self.assertEqual(self.one - self.zero, self.one)
        self.assertEqual(self.three - self.zero, self.three)

        self.assertEqual(self.three - self.five, self.F11(9))
        self.assertEqual(self.five - self.three, self.two)

        self.assertEqual(self.F11(12) - self.F11(23), self.zero)

    def test_mult(self):
        self.assertEqual(self.zero * self.one, self.zero)
        self.assertEqual(self.eight * self.one, self.eight)
        self.assertEqual(self.three * self.three, self.F11(9))
        self.assertEqual(self.three * self.five, self.F11(4))

    def test_div(self):
        self.assertEqual(self.zero / self.three, self.zero)
        self.assertEqual(self.eight / self.one, self.eight)
        self.assertEqual(self.F11(9) / self.three, self.three)

    def test_inv(self):
        self.assertEqual(self.zero.inv(), self.zero)
        self.assertEqual(self.one.inv(), self.one)
        self.assertEqual(self.eight.inv() * self.eight, self.one)

    def test_power(self):
        self.assertEqual(self.zero ** 10, self.zero)
        self.assertEqual(self.one ** 10, self.one)
        self.assertEqual(self.three ** 0, self.one)
        self.assertEqual(self.three ** 1, self.three)
        self.assertEqual(self.three ** 3, self.five)

    def test_associativity(self):
        res1 = (self.three + self.five) + self.eight
        res2 = self.three + (self.five + self.eight)
        self.assertEqual(res1, res2)

        res1 = (self.three * self.five) * self.eight
        res2 = self.three * (self.five * self.eight)
        self.assertEqual(res1, res2)

    def test_distributivity(self):
        res1 = (self.three + self.five) * self.eight
        res2 = (self.three * self.eight) +  (self.five * self.eight)
        self.assertEqual(res1, res2)

if __name__ == "__main__":
    unittest.main()
