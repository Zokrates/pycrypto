"""
This module implements the extended twisted edwards and extended affine coordinates
described in the paper "Twisted Edwards Curves Revisited":
 - https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
   Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, and Ed Dawson

based on: https://github.com/HarryR/ethsnarks
"""

from collections import namedtuple
from .field import FQ, field_modulus

# order of the field
JUBJUB_Q = field_modulus
# order of the curve
JUBJUB_E = 21888242871839275222246405745257275088614511777268538073601725287587578984328
JUBJUB_C = 8  # Cofactor
JUBJUB_L = JUBJUB_E // JUBJUB_C  # C*L == E
JUBJUB_A = 168700  # Coefficient A
JUBJUB_D = 168696  # Coefficient D


class Point(namedtuple("_Point", ("x", "y"))):
    def valid(self):
        """
        Satisfies the relationship
            ax^2 + y^2 = 1 + d x^2 y^2
        """
        xsq = self.x * self.x
        ysq = self.y * self.y
        return (JUBJUB_A * xsq) + ysq == (1 + JUBJUB_D * xsq * ysq)

    def add(self, other):
        assert isinstance(other, Point)
        if self.x == 0 and self.y == 0:
            return other
        (u1, v1) = (self.x, self.y)
        (u2, v2) = (other.x, other.y)
        u3 = (u1 * v2 + v1 * u2) / (FQ.one() + JUBJUB_D * u1 * u2 * v1 * v2)
        v3 = (v1 * v2 - JUBJUB_A * u1 * u2) / (FQ.one() - JUBJUB_D * u1 * u2 * v1 * v2)
        return Point(u3, v3)

    def mult(self, scalar):
        if isinstance(scalar, FQ):
            scalar = scalar.n
        p = self
        a = self.infinity()
        i = 0
        while scalar != 0:
            if (scalar & 1) != 0:
                a = a.add(p)
            p = p.double()
            scalar = scalar // 2
            i += 1
        return a

    def neg(self):
        """
        Twisted Edwards Curves, BBJLP-2008, section 2 pg 2
        """
        return Point(-self.x, self.y)

    @classmethod
    def generator(cls):
        x = 16540640123574156134436876038791482806971768689494387082833631921987005038935
        y = 20819045374670962167435360035096875258406992893633759881276124905556507972311
        return Point(FQ(x), FQ(y))

    @staticmethod
    def infinity():
        return Point(FQ(0), FQ(1))

    def __str__(self):
        return "x: {}, y:{}".format(*self)

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __neg__(self):
        return self.neg()

    def __add__(self, other):
        return self.add(other)

    def __sub__(self, other):
        return self.add(other.neg())

    def __mul__(self, n):
        return self.mult(n)

    def double(self):
        return self.add(self)
