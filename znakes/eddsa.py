"""
This module implements EdDSA (https://en.wikipedia.org/wiki/EdDSA) signing and verification

1) the signer has two secret values:

    * k = Secret key
    * r = Per-(message,key) nonce

2) the signer provides the verifier with their public key:

    * A = k*B

3) the signer provides a signature consisting of two values:

    * R = Point, image of `r*B`
    * s = Image of `r + (k*t)`

The value `t` denotes the common reference string used by both parties:
    * t = H(R, A, M)
where H() denotes a cryptographic hash function, SHA256 in this implementation.

The nonce `r` is  a random secret, and protects the value `s` from revealing the
signers secret key.

4) the verifier can check the following statement:
    `S*B = R + t*A`

For further information see: https://eprint.iacr.org/2015/677.pdf
based on: https://github.com/HarryR/ethsnarks
"""

import hashlib
from collections import namedtuple
from math import ceil, log2
from os import urandom
from abc import ABCMeta

from .curves import EdwardsCurve, BabyJubJub, JubJub
from .fields import FQ, BN128Field, BLS12_381Field
from .utils import to_bytes


class PrivateKey:
    """
    Wraps field element
    """
    def __init__(self, sk: int, curve: ABCMeta):
        if curve == BabyJubJub:
            field = BN128Field
        elif curve == JubJub:
            field = BLS12_381Field
        else:
            raise ValueError('Edwardscurve not supported')
        self.curve = curve
        self.fe = field(sk)

    @classmethod
    def from_rand(cls, curve: ABCMeta):
        mod = curve.JUBJUB_L.n
        # nbytes = ceil(ceil(log2(mod)) / 8) + 1
        nbytes = ceil(ceil(log2(mod)) / 8)
        rand_n = int.from_bytes(urandom(nbytes), "little")
        return cls(rand_n, curve)

    def sign(self, msg, B: EdwardsCurve = None):
        "Returns the signature (R,S) for a given private key and message."
        B = B or self.curve.generator()

        A = PublicKey.from_private(self)  # A = kB

        M = msg
        r = A.hash_to_scalar(self.fe, M)  # r = H(k,M) mod L
        R = B.mult(r)  # R = rB

        # Bind the message to the nonce, public key and message
        hRAM = A.hash_to_scalar(R, A.point, M)
        key_field = self.fe.n
        S = (r + (key_field * hRAM)) % self.curve.JUBJUB_E # r + (H(R,A,M) * k)

        return (R, S)

class PublicKey:
    """
    Wraps edwards point
    """
    def __init__(self, point: EdwardsCurve):
        assert issubclass(type(point), EdwardsCurve)
        self.point = point
        self.curve = type(point)

    @classmethod
    def from_private(cls, sk: PrivateKey, B=None):
        "Returns public key for a private key. B denotes the group generator"
        assert isinstance(sk, PrivateKey) and issubclass(type(sk.fe), FQ)
        curve = sk.curve
        if B:
            assert type(B) == type(curve)
        B = B or curve.generator()
        A = B.mult(sk.fe)
        return cls(A)

    def verify(self, sig, msg, B=None):
        B = B or self.curve.generator()

        R, S = sig
        M = msg
        A = self.point

        lhs = B.mult(S)

        hRAM = self.hash_to_scalar(R, A, M)
        rhs = R + (A.mult(hRAM))

        return lhs == rhs


    def hash_to_scalar(self, *args):
        """
        Hash the key and message to create `r`, the blinding factor for this signature.
        If the same `r` value is used more than once, the key for the signature is revealed.

        Note that we take the entire 256bit hash digest as input for the scalar multiplication.
        As the group is only of size JUBJUB_E (<256bit) we allow wrapping around the group modulo.
        """
        p = b"".join(to_bytes(_) for _ in args)
        digest = hashlib.sha256(p).digest()
        return int(digest.hex(), 16) % self.curve.JUBJUB_E # mod JUBJUB_E here for optimized implementation
