import math
import bitstring
from math import floor, log2
from struct import pack

from ..curves import BabyJubJub
from ..fields import BN128Field as FQ

WINDOW_SIZE_BITS = 2  # Size of the pre-computed look-up table


def pedersen_hash_basepoint(name, i):
    """
    Create a base point for use with the windowed Pedersen
    hash function.
    The name and sequence numbers are used as a unique identifier.
    Then HashToEdwardsCurve is run on the name+seq to get the base point.
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
    return BabyJubJub.from_hash(data)


def windows_to_dsl_array(windows):
    bit_windows = (bitstring.BitArray(bin(i)).bin[::-1] for i in windows)
    bit_windows_padded = ("{:0<3}".format(w) for w in bit_windows)
    bitstr = "".join(bit_windows_padded)
    return list(bitstr)


class PedersenHasher(object):
    def __init__(self, name, segments=False):
        self.name = name
        if segments:
            self.segments = segments
            self.is_sized = True
        else:
            self.is_sized = False

    def __gen_table(self):
        assert (
            self.is_sized == True
        ), "Hasher size must be defined first, before lookup table can be created"
        generators = self.generators
        table = []
        for p in generators:
            row = [p.mult(i + 1) for i in range(0, WINDOW_SIZE_BITS ** 2)]
            table.append(row)
        return table

    def __gen_generators(self):

        name = self.name
        segments = self.segments
        generators = []
        for j in range(0, segments):
            # TODO: define `62`,
            if j % 62 == 0:
                current = pedersen_hash_basepoint(name, j // 62)
            j = j % 62
            if j != 0:
                current = current.double().double().double().double()
            generators.append(current)
        return generators

    def __hash_windows(self, windows, witness):

        if self.is_sized == False:
            self.segments = len(windows)
            self.is_sized = True
            self.generators = self.__gen_generators()

        segments = self.segments
        assert (
            len(windows) <= segments
        ), "Number of windows exceeds pedersenHasher config. {} vs {}".format(
            len(windows), segments
        )
        padding = (segments - len(windows)) * [0]  # pad to match number of segments
        windows.extend(padding)
        assert (
            len(windows) == segments
        ), "Number of windows does not match pedersenHasher config. {} vs {}".format(
            len(windows), segments
        )

        # in witness mode return padded windows
        if witness:
            return windows_to_dsl_array(windows)

        result = BabyJubJub.infinity()
        for (g, window) in zip(self.generators, windows):
            segment = g * ((window & 0b11) + 1)
            if window > 0b11:
                segment = segment.neg()
            result += segment
        return result

    def hash_bits(self, bits, witness=False):
        # Split into 3 bit windows
        if isinstance(bits, bitstring.BitArray):
            bits = bits.bin
        windows = [int(bits[i : i + 3][::-1], 2) for i in range(0, len(bits), 3)]
        assert len(windows) > 0

        return self.__hash_windows(windows, witness)

    def hash_bytes(self, data, witness=False):
        """
        Hashes a sequence of bits (the message) into a point.

        The message is split into 3-bit windows after padding (via append)
        to `len(data.bits) = 0 mod 3`
        """

        assert isinstance(data, bytes)
        assert len(data) > 0

        # Decode bytes to octets of binary bits
        bits = "".join([bin(_)[2:].rjust(8, "0") for _ in data])

        return self.hash_bits(bits, witness)

    def hash_scalars(self, *scalars, witness=False):
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

        return self.__hash_windows(windows, witness)

    def gen_dsl_witness_bits(self, bits):
        return self.hash_bits(bits, witness=True)

    def gen_dsl_witness_bytes(self, data):
        return self.hash_bytes(data, witness=True)

    def gen_dsl_witness_scalars(self, *scalars):
        return self.hash_scalars(*scalars, witness=True)

    def __gen_dsl_code(self):

        table = self.__gen_table()

        imports = """
import "utils/multiplexer/lookup3bitSigned.code" as sel3s
import "utils/multiplexer/lookup2bit.code" as sel2
import "ecc/babyjubjubParams.code" as context
import "ecc/edwardsAdd.code" as add"""

        program = []
        program.append("\ndef main({}) -> (field[2]):".format(self.gen_dsl_args()))
        program.append("\tcontext = context()")
        program.append("\tfield[2] a = [context[2], context[3]] //Infinity")

        segments = len(table)
        for i in range(0, segments):
            r = table[i]
            program.append("\t//Round {}".format(i))
            program.append(
                "\tcx = sel3s([e[{}], e[{}], e[{}]], [{} , {}, {}, {}])".format(
                    3 * i, 3 * i + 1, 3 * i + 2, r[0].x, r[1].x, r[2].x, r[3].x
                )
            )
            program.append(
                "\tcy = sel2([e[{}], e[{}]], [{} , {}, {}, {}])".format(
                    3 * i, 3 * i + 1, r[0].y, r[1].y, r[2].y, r[3].y
                )
            )
            program.append("\ta = add(a, [cx, cy], context)")

        program.append("\treturn a")
        return imports + "\n".join(program)

    @property
    def dsl_code(self):
        return self.__gen_dsl_code()

    def gen_dsl_args(self):
        segments = self.segments
        return "field[{}] e".format(segments * (WINDOW_SIZE_BITS + 1))

    def write_dsl_code(self, file_name):
        with open(file_name, "w+") as f:
            for l in self.dsl_code:
                f.write(l)
