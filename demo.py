from bitstring import BitArray

from eddsa import *
from field import FQ


def pprint_hex(n, h):
    b = BitArray(int(h, 16).to_bytes(32, 'big')).bin
    s =  '[' + ', '.join(b) + '] \n'
    print('field[256] {} = {} \n'.format(n, s))


def pprint_point(n, p):
    x, y = p
    print('field[2] {} = [{}, {}] \n'.format(n, x, y))


def pprint_for_zokrates(pk, sig, msg):

    A = to_bytes(pk).hex()
    R = to_bytes(sig.R).hex()
    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]
    s = to_bytes(sig.S).hex()

    for n, h in  zip(['R', 'A', 'M0', 'M1'], [R, A, M0, M1]):
        pprint_hex(n, h)

    pprint_point('A', pk.pk)
    pprint_point('R', sig.R)
    pprint_hex('S', s)

    
if __name__ == "__main__":

    # Define message as 512bit, could be as SHA512 output
    msg = bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 05')

    # sk = PrivateKey.from_rand()
    # Seeded for debug purpose
    key = FQ(1997011358982923168928344992199991480689546837621580239342656433234255379025)
    sk = PrivateKey(key)
    sig = sk.sign(msg)

    pk = PublicKey.from_private(sk)
    pk.verify(sig, msg)

    pprint_for_zokrates(pk, sig, msg)
