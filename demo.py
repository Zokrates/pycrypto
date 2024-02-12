import hashlib

from znakes.curves import JubJub
from znakes.eddsa import PrivateKey, PublicKey
from znakes.utils import write_signature_for_zokrates_cli

if __name__ == "__main__":

    raw_msg = "This is my secret message"
    msg = hashlib.sha512(raw_msg.encode("utf-8")).digest()

    sk = PrivateKey.from_rand(JubJub)
    sig = sk.sign(msg)

    pk = PublicKey.from_private(sk)
    is_verified = pk.verify(sig, msg)
    print(is_verified)
    write_signature_for_zokrates_cli(pk, sig, msg, "zokrates_inputs.txt")
	
	