from bitstring import BitArray

from .curves import EdwardsCurve
from .fields import FQ
import hashlib


def to_bytes(*args):
    "Returns byte representation for objects used in this module."
    result = b""
    for M in args:
        if isinstance(M, EdwardsCurve):
            result += to_bytes(M.x)
            # result += to_bytes(M.y)
        elif isinstance(M, FQ):
            result += to_bytes(M.n)
        elif isinstance(M, int):
            result += M.to_bytes(32, "big")
        elif isinstance(M, BitArray):
            result += M.tobytes()
        elif isinstance(M, bytes):
            result += M
        elif isinstance(M, (list, tuple)):
            result += b"".join(to_bytes(_) for _ in M)
        else:
            raise TypeError("Bad type for M: " + str(type(M)))
    return result


def write_signature_for_zokrates_cli(pk, sig, msg, path):
    "Writes the input arguments for verifyEddsa in the ZoKrates stdlib to file."
    sig_R, sig_S = sig
    args = [sig_R.x, sig_R.y, sig_S, pk.point.x.n, pk.point.y.n]
    args = " ".join(map(str, args))

    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
    args = args + " " + " ".join(b0 + b1)

    with open(path, "w+") as file:
        for l in args:
            file.write(l)


def pprint_hex_as_256bit(n, h):
    "Takes a variable name and a hex encoded number and returns Zokrates assignment statement."
    b = BitArray(int(h, 16).to_bytes(32, "big")).bin
    s = "[" + ", ".join(b) + "]"
    return "field[256] {} = {} \n".format(n, s)


def pprint_point(n, p):
    "Takes a variable name and curve point and returns Zokrates assignment statement."
    x, y = p.x, p.y
    return "field[2] {} = [{}, {}] \n".format(n, x, y)


def pprint_fe(n, fe):
    "Takes a variable name and field element and returns Zokrates assignment statement."
    return "field {} = {} \n".format(n, fe)


def pprint_for_zokrates(pk, sig, msg):

    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]

    code = []
    sig_R, sig_S = sig
    for n, h in zip(["M0", "M1"], [M0, M1]):
        code.append(pprint_hex_as_256bit(n, h))

    code.append(pprint_point("A", pk.p))
    code.append(pprint_point("R", sig_R))
    code.append(pprint_fe("S", sig_S))

    print("\n".join(code))
