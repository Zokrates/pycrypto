"""
This code is copied from https://github.com/ethereum/py_ecc/blob/master/py_ecc/bn128/bn128_curve.py
Author is Vitalik Buterin.
Unfortunately the field modulus is not generic in this implementation, hence we had to copy the file.
All changes from our side are denoted with #CHANGE.
"""

from __future__ import absolute_import

from typing import cast, List, Tuple, Sequence, Union


# The prime modulus of the field
# field_modulus = 21888242871839275222246405745257275088696311157297823662689037894645226208583
field_modulus = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
# CHANGE: Changing the modulus to the embedded curve

# See, it's prime!
assert pow(2, field_modulus, field_modulus) == 2

# The modulus of the polynomial in this representation of FQ12
# FQ12_MODULUS_COEFFS = (82, 0, 0, 0, 0, 0, -18, 0, 0, 0, 0, 0)  # Implied + [1]
# FQ2_MODULUS_COEFFS = (1, 0)
# CHANGE: No need for extended  in this case

# Extended euclidean algorithm to find modular inverses for
# integers
def inv(a: int, n: int) -> int:
    if a == 0:
        return 0
    lm, hm = 1, 0
    num = a if isinstance(a, int) else a.n
    low, high = num % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


IntOrFQ = Union[int, "FQ"]


# A class for field elements in FQ. Wrap a number in this class,
# and it becomes a field element.
class FQ(object):
    n = None  # type: int

    def __init__(self, val: IntOrFQ) -> None:
        if isinstance(val, FQ):
            self.n = val.n
        else:
            self.n = val % field_modulus
        assert isinstance(self.n, int)

    def __add__(self, other: IntOrFQ) -> "FQ":
        on = other.n if isinstance(other, FQ) else other
        return FQ((self.n + on) % field_modulus)

    def __mul__(self, other: IntOrFQ) -> "FQ":
        on = other.n if isinstance(other, FQ) else other
        return FQ((self.n * on) % field_modulus)

    def __rmul__(self, other: IntOrFQ) -> "FQ":
        return self * other

    def __radd__(self, other: IntOrFQ) -> "FQ":
        return self + other

    def __rsub__(self, other: IntOrFQ) -> "FQ":
        on = other.n if isinstance(other, FQ) else other
        return FQ((on - self.n) % field_modulus)

    def __sub__(self, other: IntOrFQ) -> "FQ":
        on = other.n if isinstance(other, FQ) else other
        return FQ((self.n - on) % field_modulus)

    def __div__(self, other: IntOrFQ) -> "FQ":
        on = other.n if isinstance(other, FQ) else other
        assert isinstance(on, int)
        return FQ(self.n * inv(on, field_modulus) % field_modulus)

    def __truediv__(self, other: IntOrFQ) -> "FQ":
        return self.__div__(other)

    def __rdiv__(self, other: IntOrFQ) -> "FQ":
        on = other.n if isinstance(other, FQ) else other
        assert isinstance(on, int), on
        return FQ(inv(self.n, field_modulus) * on % field_modulus)

    def __rtruediv__(self, other: IntOrFQ) -> "FQ":
        return self.__rdiv__(other)

    def __pow__(self, other: int) -> "FQ":
        if other == 0:
            return FQ(1)
        elif other == 1:
            return FQ(self.n)
        elif other % 2 == 0:
            return (self * self) ** (other // 2)
        else:
            return ((self * self) ** int(other // 2)) * self

    def __eq__(
        self, other: IntOrFQ
    ) -> bool:  # type:ignore # https://github.com/python/mypy/issues/2783 # noqa: E501
        if isinstance(other, FQ):
            return self.n == other.n
        else:
            return self.n == other

    def __ne__(
        self, other: IntOrFQ
    ) -> bool:  # type:ignore # https://github.com/python/mypy/issues/2783 # noqa: E501
        return not self == other

    def __neg__(self) -> "FQ":
        return FQ(-self.n)

    def __repr__(self) -> str:
        return repr(self.n)

    def __int__(self) -> int:
        return self.n

    @classmethod
    def one(cls) -> "FQ":
        return cls(1)

    @classmethod
    def zero(cls) -> "FQ":
        return cls(0)
