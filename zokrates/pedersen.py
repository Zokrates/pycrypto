# TODO: add doc
# based on: https://github.com/HarryR/ethsnarks

import math
import bitstring
from math import floor, log2
from struct import pack

from .babyjubjub import Point, JUBJUB_L, JUBJUB_C
from .field import FQ

# TODO: use parameterise and show source
CHUNK_SIZE_BITS = 3
LOOKUP_SIZE_BITS = 2
CHUNKS_PER_BASE_POINT = 62

# TODO: make it a class


def pedersen_hash_basepoint(name, i):
    """
    Create a base point for use with the windowed pedersen
    hash function.
    The name and sequence numbers are used a unique identifier.
    Then HashToPoint is run on the name+seq to get the base point.
    """
    if not isinstance(name, bytes):
        if isinstance(name, str):
            name = name.encode("ascii")
        else:
            raise TypeError("Name not bytes")
    if i < 0 or i > 0xFFFF:
        raise ValueError("Sequence number invalid")
    if len(name) > 28:
        raise ValueError("Name too long")
    data = b"%-28s%04X" % (name, i)
    return Point.from_hash(data)


def pedersen_hash_windows(name, windows):
    # TODO: define `62`,
    # 248/62 == 4... ? CHUNKS_PER_BASE_POINT
    #  TODO: describe -binary => complementary
    result = Point.infinity()
    for j, window in enumerate(windows):
        if j % 62 == 0:
            current = pedersen_hash_basepoint(name, j // 62)  # add to list
        j = j % 62
        if j != 0:
            current = current.double().double().double().double()
        segment = current * ((window & 0b11) + 1)
        if window > 0b11:
            segment = segment.neg()
        result += segment
    return result


WINDOW_SIZE_BITS = 2


def pedersen_hash_gen_table(name, segments=62):
    table = []
    for j in range(0, segments):
        if j % 62 == 0:
            p = pedersen_hash_basepoint(name, j // 62)  # add to list
        j = j % 62
        if j != 0:
            p = p.double().double().double().double()
        # scalar = (window & 0b11) + 1
        row = [p.mult(i + 1) for i in range(0, WINDOW_SIZE_BITS ** 2)]
        table.append(row)

    print(pprint_pedersen_windowed_table(table))
    return table


def pedersen_hash_windowed_table(name, windows):

    segments = len(windows)
    table = pedersen_hash_gen_table(name, segments)

    a = Point.infinity()
    for j, window in enumerate(windows):
        row = table[j]
        scalar = window & 0b11
        c = row[scalar]
        if window > 0b11:
            c = c.neg()
        a += c
    return a


def pedersen_hash_bits_table(name, bits):
    # Split into 3 bit windows
    if isinstance(bits, bitstring.BitArray):
        bits = bits.bin
    windows = [int(bits[i : i + 3][::-1], 2) for i in range(0, len(bits), 3)]
    assert len(windows) > 0

    # Hash resulting windows
    return pedersen_hash_windowed_table(name, windows)


def pprint_pedersen_windowed_table(table):

    # TODO: add imports
    dsl = []

    segments = len(table)
    for i in range(0, segments):
        r = table[i]
        dsl.append("//Round {}".format(i))
        dsl.append(
            "cx = sel3s([e[{}], e[{}], e[{}]], [{} , {}, {}, {}])".format(
                3 * i, 3 * i + 1, 3 * i + 2, r[0].x, r[1].x, r[2].x, r[3].x
            )
        )
        # TODO: y coordinate does not need to be inverted
        dsl.append(
            "cy = sel2([e[{}], e[{}]], [{} , {}, {}, {}])".format(
                3 * i, 3 * i + 1, r[0].y, r[1].y, r[2].y, r[3].y
            )
        )
        dsl.append("a = add(a, [cx, cy], context)")

    return "\n".join(dsl)


def pedersen_hash_bits(name, bits):
    # Split into 3 bit windows
    if isinstance(bits, bitstring.BitArray):
        bits = bits.bin
    windows = [int(bits[i : i + 3][::-1], 2) for i in range(0, len(bits), 3)]
    assert len(windows) > 0
    # Hash resulting windows
    return pedersen_hash_windows(name, windows)


def pedersen_hash_bytes(name, data):
    """
    Hashes a sequence of bits (the message) into a point.

    The message is split into 3-bit windows after padding (via append)
    to `len(data.bits) = 0 mod 3`
    """
    assert isinstance(data, bytes)
    assert len(data) > 0

    # Decode bytes to octets of binary bits
    bits = "".join([bin(_)[2:].rjust(8, "0") for _ in data])

    return pedersen_hash_bits(name, bits)


def pedersen_hash_scalars(name, *scalars):
    """
    Calculates a pedersen hash of scalars in the same way that zCash
    is doing it according to: ... of their spec.
    It is looking up 3bit chunks in a 2bit table (3rd bit denotes sign).

    E.g:

        (b2, b1, b0) = (1,0,1) would look up first element and negate it.

    Row i of the lookup table contains:

        [2**4i * base, 2 * 2**4i * base, 3 * 2**4i * base, 3 * 2**4i * base]

    E.g:

        row_0 = [base, 2*base, 3*base, 4*base]
        row_1 = [16*base, 32*base, 48*base, 64*base]
        row_2 = [256*base, 512*base, 768*base, 1024*base]

    Following Theorem 5.4.1 of the zCash Sapling specification, for baby jub_jub
    we need a new base point every 62 windows. We will therefore have multiple
    tables with 62 rows each.
    """
    windows = []
    for _, s in enumerate(scalars):
        windows += list((s >> i) & 0b111 for i in range(0, s.bit_length(), 3))
    return pedersen_hash_windows(name, windows)
