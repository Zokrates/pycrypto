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

from .babyjubjub import JUBJUB_E, JUBJUB_L, JUBJUB_Q, Point
from .field import FQ
from .utils import to_bytes


class PrivateKey(namedtuple("_PrivateKey", ("fe"))):
    """
    Wraps field element
    """

    @classmethod
    # FIXME: ethsnarks creates keys > 32bytes. Create issue.
    def from_rand(cls):
        mod = JUBJUB_L
        # nbytes = ceil(ceil(log2(mod)) / 8) + 1
        nbytes = ceil(ceil(log2(mod)) / 8)
        rand_n = int.from_bytes(urandom(nbytes), "little")
        return cls(FQ(rand_n))

    def sign(self, msg, B=None):
        "Returns the signature (R,S) for a given private key and message."
        B = B or Point.generator()

        A = PublicKey.from_private(self)  # A = kB

        M = msg
        r = hash_to_scalar(self.fe, M)  # r = H(k,M) mod L
        R = B.mult(r)  # R = rB

        # Bind the message to the nonce, public key and message
        hRAM = hash_to_scalar(R, A, M)
        key_field = self.fe.n
        S = (r + (key_field * hRAM)) % JUBJUB_E  # r + (H(R,A,M) * k)

        return (R, S)


class PublicKey(namedtuple("_PublicKey", ("p"))):
    """
    Wraps edwards point
    """

    @classmethod
    def from_private(cls, sk, B=None):
        "Returns public key for a private key. B denotes the group generator"
        B = B or Point.generator()
        if not isinstance(sk, PrivateKey):
            sk = PrivateKey(sk)
        A = B.mult(sk.fe)
        return cls(A)

    def verify(self, sig, msg, B=None):
        B = B or Point.generator()

        R, S = sig
        M = msg
        A = self.p

        lhs = B.mult(S)

        hRAM = hash_to_scalar(R, A, M)
        rhs = R + (A.mult(hRAM))

        return lhs == rhs


def hash_to_scalar(*args):
    """
    Hash the key and message to create `r`, the blinding factor for this signature.
    If the same `r` value is used more than once, the key for the signature is revealed.

    Note that we take the entire 256bit hash digest as input for the scalar multiplication.
    As the group is only of size JUBJUB_E (<256bit) we allow wrapping around the group modulo.
    """
    p = b"".join(to_bytes(_) for _ in args)
    digest = hashlib.sha256(p).digest()
    return int(digest.hex(), 16)  # mod JUBJUB_E here for optimized implementation
