"""
This module implements the extended twisted edwards and extended affine coordinates
described in the paper "Twisted Edwards Curves Revisited":
 - https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
   Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, and Ed Dawson

based on: https://github.com/HarryR/ethsnarks
"""

from abc import ABC, abstractmethod
from .fields import FQ, BN128Field, BLS12_381Field
from .numbertheory import square_root_mod_prime, SquareRootError


def is_negative(v):
    assert isinstance(v, FQ), f"given type: {type(v)}"
    return v.n < (-v).n


class EdwardsCurve(ABC):
    FIELD_TYPE: type
    JUBJUB_Q: int
    JUBJUB_E: int
    JUBJUB_C: FQ
    JUBJUB_L: FQ
    JUBJUB_A: FQ
    JUBJUB_D: FQ

    def __init__(self, x: FQ, y: FQ):
        assert type(x) == type(y) and type(x) == self.FIELD_TYPE
        self.x = x
        self.y = y

    @classmethod
    @property
    @abstractmethod
    def FIELD_TYPE(cls):
        raise NotImplementedError

    @classmethod
    @property
    @abstractmethod
    def JUBJUB_Q(cls):
        raise NotImplementedError

    @classmethod
    @property
    @abstractmethod
    def JUBJUB_E(cls):
        raise NotImplementedError

    @classmethod
    @property
    @abstractmethod
    def JUBJUB_C(cls):
        raise NotImplementedError

    @classmethod
    @property
    @abstractmethod
    def JUBJUB_L(cls):
        raise NotImplementedError

    @classmethod
    @property
    @abstractmethod
    def JUBJUB_A(cls):
        raise NotImplementedError

    @classmethod
    @property
    @abstractmethod
    def JUBJUB_D(cls):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def generator(cls):
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def infinity():
        raise NotImplementedError

    def valid(self):
        """
        Satisfies the relationship
            ax^2 + y^2 = 1 + d x^2 y^2
        """
        xsq = self.x * self.x
        ysq = self.y * self.y
        return (self.JUBJUB_A * xsq) + ysq == (self.FIELD_TYPE(1) + self.JUBJUB_D * xsq * ysq)

    def add(self, other):
        assert isinstance(other, type(self))
        if self.x == 0 and self.y == 0:
            return other
        (u1, v1) = (self.x, self.y)
        (u2, v2) = (other.x, other.y)
        u3 = (u1 * v2 + v1 * u2) / (self.FIELD_TYPE(1) + self.JUBJUB_D * u1 * u2 * v1 * v2)
        v3 = (v1 * v2 - self.JUBJUB_A * u1 * u2) / (self.FIELD_TYPE(1) - self.JUBJUB_D * u1 * u2 * v1 * v2)
        return type(self)(u3, v3)

    def mult(self, scalar):
        if isinstance(scalar, FQ):
            scalar = scalar.n
        p = self
        a = type(self).infinity()
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
        return type(self)(-self.x, self.y)

    def __str__(self):
        return "x: {}, y:{}".format(self.x, self.y)

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
        assert isinstance(x, cls.FIELD_TYPE)
        xsq = x * x
        ax2 = cls.JUBJUB_A * xsq
        dxsqm1 = (cls.JUBJUB_D * xsq - cls.FIELD_TYPE(1)).inv()
        ysq = dxsqm1 * (ax2 - cls.FIELD_TYPE(1))
        y = square_root_mod_prime(int(ysq), cls.JUBJUB_Q)
        return cls(x, y)

    @classmethod
    def from_y(cls, y, sign=None):
        """
        x^2 = (y^2 - 1) / (d * y^2 - a)
        """
        assert isinstance(y, cls.FIELD_TYPE)
        ysq = y * y
        lhs = ysq - cls.FIELD_TYPE(1)
        rhs = cls.JUBJUB_D * ysq - cls.JUBJUB_A
        xsq = lhs / rhs
        x = cls.FIELD_TYPE(square_root_mod_prime(int(xsq), cls.JUBJUB_Q))
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
        HashToEdwardsCurve (or EdwardsCurve.from_hash)

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
        y = cls.FIELD_TYPE(entropy_as_int)
        while True:
            try:
                p = cls.from_y(y)
            except SquareRootError:
                y += cls.FIELD_TYPE(1)
                continue

            # Multiply point by cofactor, ensures it's on the prime-order subgroup
            p = p * cls.JUBJUB_C

            # Verify point is on prime-ordered sub-group
            if (p * cls.JUBJUB_L) != type(p).infinity():
                raise RuntimeError("EdwardsCurve not on prime-ordered subgroup")

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
        return cls.from_y(cls.FIELD_TYPE(y), sign)


# values taken from: https://github.com/barryWhiteHat/baby_jubjub
class BabyJubJub(EdwardsCurve):
    FIELD_TYPE = BN128Field
    # order of the field
    JUBJUB_Q = BN128Field.FIELD
    # order of the curve
    JUBJUB_E = 21888242871839275222246405745257275088614511777268538073601725287587578984328
    JUBJUB_C = BN128Field(8)  # Cofactor
    JUBJUB_L = BN128Field(JUBJUB_E) / JUBJUB_C  # C*L == E
    JUBJUB_A = BN128Field(168700)  # Coefficient A
    JUBJUB_D = BN128Field(168696)  # Coefficient D

    def __init__(self, x: BN128Field, y: BN128Field):
        super().__init__(x, y)

    @classmethod
    def generator(cls):
        x = 16540640123574156134436876038791482806971768689494387082833631921987005038935
        y = 20819045374670962167435360035096875258406992893633759881276124905556507972311
        return cls(BN128Field(x), BN128Field(y))

    @staticmethod
    def infinity():
        return BabyJubJub(BN128Field(0), BN128Field(1))


# values taken from: https://github.com/daira/jubjub
class JubJub(EdwardsCurve):
    FIELD_TYPE = BLS12_381Field
    # order of the field
    JUBJUB_Q = BLS12_381Field.FIELD
    # order of the curve
    JUBJUB_E = 52435875175126190479447740508185965837647370126978538250922873299137466033592  # C*L == E
    JUBJUB_C = BLS12_381Field(8)  # Cofactor
    JUBJUB_L = BLS12_381Field(6554484396890773809930967563523245729705921265872317281365359162392183254199)
    JUBJUB_A = BLS12_381Field(-1)  # Coefficient A
    JUBJUB_D = BLS12_381Field(19257038036680949359750312669786877991949435402254120286184196891950884077233)  # Coefficient D

    def __init__(self, x: BLS12_381Field, y: BLS12_381Field):
        super().__init__(x, y)

    @classmethod
    def generator(cls):
        x = 11076627216317271660298050606127911965867021807910416450833192264015104452986
        y = 44412834903739585386157632289020980010620626017712148233229312325549216099227
        return cls(BLS12_381Field(x), BLS12_381Field(y))

    @staticmethod
    def infinity():
        return JubJub(BLS12_381Field(0), BLS12_381Field(1))
