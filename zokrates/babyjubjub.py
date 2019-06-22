"""
This module implements the extended twisted edwards and extended affine coordinates
described in the paper "Twisted Edwards Curves Revisited":
 - https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
   Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, and Ed Dawson

based on: https://github.com/HarryR/ethsnarks
"""

from collections import namedtuple
from .field import FQ, inv, field_modulus
from .numbertheory import square_root_mod_prime, SquareRootError

# order of the field
JUBJUB_Q = field_modulus
# order of the curve
JUBJUB_E = 21888242871839275222246405745257275088614511777268538073601725287587578984328
JUBJUB_C = 8  # Cofactor
JUBJUB_L = JUBJUB_E // JUBJUB_C  # C*L == E
JUBJUB_A = 168700  # Coefficient A
JUBJUB_D = 168696  # Coefficient D


def is_negative(v):
    assert isinstance(v, FQ)
    return v.n < (-v).n


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

    @classmethod
    def from_x(cls, x):
        """
        y^2 = ((a * x^2) / (d * x^2 - 1)) - (1 / (d * x^2 - 1))
        For every x coordinate, there are two possible points: (x, y) and (x, -y)
        """
        assert isinstance(x, FQ)
        xsq = x * x
        ax2 = JUBJUB_A * xsq
        dxsqm1 = inv(JUBJUB_D * xsq - 1, JUBJUB_Q)
        ysq = dxsqm1 * (ax2 - 1)
        y = FQ(square_root_mod_prime(int(ysq), JUBJUB_Q))
        return cls(x, y)

    @classmethod
    def from_y(cls, y, sign=None):
        """
        x^2 = (y^2 - 1) / (d * y^2 - a)
        """
        assert isinstance(y, FQ)
        ysq = y * y
        lhs = ysq - 1
        rhs = JUBJUB_D * ysq - JUBJUB_A
        xsq = lhs / rhs
        x = FQ(square_root_mod_prime(int(xsq), JUBJUB_Q))
        if sign is not None:
            # Used for compress & decompress
            if (x.n & 1) != sign:
                x = -x
        else:
            if is_negative(x):
                x = -x
        return cls(x, y)

    @classmethod
    def from_hash(cls, entropy):
        """
        HashToPoint (or Point.from_hash)

        Parameters:
            entropy (bytes): input entropy provided as byte array

        Hashes the input entropy and interprets the result as the Y coordinate
        then recovers the X coordinate, if no valid point can be recovered
        Y is incremented until a matching X coordinate is found.
        The point is guaranteed to be prime order and not the identity.
        From: https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1
        Page 6:
           o  HashToBase(x, i).  This method is parametrized by p and H, where p
              is the prime order of the base field Fp, and H is a cryptographic
              hash function which outputs at least floor(log2(p)) + 2 bits.  The
              function first hashes x, converts the result to an integer, and
              reduces modulo p to give an element of Fp.
        """
        from hashlib import sha256

        assert isinstance(entropy, bytes)
        entropy = sha256(entropy).digest()
        entropy_as_int = int.from_bytes(entropy, "big")
        y = FQ(entropy_as_int)
        while True:
            try:
                p = cls.from_y(y)
            except SquareRootError:
                y += 1
                continue

            # Multiply point by cofactor, ensures it's on the prime-order subgroup
            p = p * JUBJUB_C

            # Verify point is on prime-ordered sub-group
            if (p * JUBJUB_L) != Point.infinity():
                raise RuntimeError("Point not on prime-ordered subgroup")

            return p

    def compress(self):
        x = self.x.n
        y = self.y.n
        # return int.to_bytes(y | ((x & 1) << 255), 32, "little")
        return int.to_bytes(y | ((x & 1) << 255), 32, "big")

    @classmethod
    def decompress(cls, point):
        """
        From: https://ed25519.cr.yp.to/eddsa-20150704.pdf

        The encoding of F_q is used to define "negative" elements of F_q:
        specifically, x is negative if the (b-1)-bit encoding of x is
        lexiographically larger than the (b-1)-bit encoding of -x. In particular,
        if q is prime and the (b-1)-bit encoding of F_q is the little-endian
        encoding of {0, 1, ..., q-1}, then {1,3,5,...,q-2} are the negative element of F_q.

        This encoding is also used to define a b-bit encoding of each element `(x,y) ∈ E`
        as a b-bit string (x,y), namely the (b-1)-bit encoding of y followed by the sign bit.
        the sign bit is 1 if and only if x is negative.

        A parser recovers `(x,y)` from a b-bit string, while also verifying that `(x,y) ∈ E`,
        as follows: parse the first b-1 bits as y, compute `xx = (y^2 - 1) / (dy^2 - a)`;
        compute `x = [+ or -] sqrt(xx)` where the `[+ or -]` is chosen so that the sign of
        `x` matches the `b`th bit of the string. if `xx` is not a square then parsing fails.
        """
        if len(point) != 32:
            raise ValueError("Invalid input length for decompression")
        # y = int.from_bytes(point, "little")
        y = int.from_bytes(point, "big")
        sign = y >> 255
        y &= (1 << 255) - 1
        return cls.from_y(FQ(y), sign)
