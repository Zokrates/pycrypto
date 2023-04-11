"""
This code is copied from https://github.com/ethereum/py_ecc/blob/master/py_ecc/bn128/bn128_curve.py
Author is Vitalik Buterin.
Unfortunately the FIELD modulus is not generic in this implementation, hence we had to copy the file.
All changes from our side are denoted with #CHANGE.
"""

from __future__ import absolute_import

from abc import ABC, abstractmethod


# A class for FIELD elements in FQ. Wrap a number in this class,
# and it becomes a FIELD element.
class FQ(ABC):
    FIELD = int
    n: int

    @classmethod
    @property
    @abstractmethod
    def FIELD(cls):
        raise NotImplementedError

    def __init__(self, val: int) -> None:
        assert isinstance(val, int)
        self.n = val % self.FIELD

    def __assert_field(self, other: "FQ"):
        assert isinstance(other, FQ)
        assert self.FIELD == other.FIELD

    def __int__(self):
        return self.n

    def __add__(self, other: "FQ") -> "FQ":
        self.__assert_field(other)
        return type(self)(self.n + other.n)

    def __mul__(self, other: "FQ") -> "FQ":
        self.__assert_field(other)
        return type(self)(self.n * other.n)

    def __sub__(self, other: "FQ") -> "FQ":
        self.__assert_field(other)
        return type(self)(self.n - other.n)

    def __truediv__(self, other: "FQ") -> "FQ":
        self.__assert_field(other)
        return self * other.inv()

    def __pow__(self, other: int) -> "FQ":
        if other == 0:
            return type(self)(1)
        elif other == 1:
            return self
        elif other % 2 == 0:
            return (self * self) ** (other // 2)
        else:
            return ((self * self) ** int(other // 2)) * self

    def __eq__(
        self, other: "FQ"
    ) -> bool:  # type:ignore # https://github.com/python/mypy/issues/2783 # noqa: E501
        if isinstance(other, FQ):
            return self.n == other.n and self.FIELD == other.FIELD
        else:
            return False

    def __ne__(
        self, other: "FQ"
    ) -> bool:  # type:ignore # https://github.com/python/mypy/issues/2783 # noqa: E501
        return not self == other

    def __neg__(self) -> "FQ":
        return type(self)(-self.n)

    def __repr__(self) -> str:
        return repr(self.n)

    def inv(self) -> "FQ":
        if self.n == 0:
            return type(self)(0)
        lm, hm = 1, 0
        low, high = self.n % self.FIELD, self.FIELD
        while low > 1:
            r = high // low
            nm, new = hm - lm * r, high - low * r
            lm, low, hm, high = nm, new, lm, low
        return type(self)(lm)


class BN128Field(FQ):
    FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617


class BLS12_381Field(FQ):
    FIELD = 52435875175126190479447740508185965837690552500527637822603658699938581184513
