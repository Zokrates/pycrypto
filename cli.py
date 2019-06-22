import argparse
import sys
from zokrates_pycrypto.gadgets.pedersenHasher import PedersenHasher
from zokrates_pycrypto.babyjubjub import Point
from zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from zokrates_pycrypto.field import FQ


def main():
    parser = argparse.ArgumentParser(description="pycrypto command-line interface")
    subparsers = parser.add_subparsers(dest="subparser_name")

    # pedersen hash subcommand
    pedersen_parser = subparsers.add_parser(
        "hash",
        help="Compute a 256bit Pedersen hash. Preimage size is set to 512bit as default",
    )
    pedersen_parser.add_argument(
        "preimage", nargs=1, help="Provide preimage as hex string"
    )
    pedersen_parser.add_argument(
        "-s", "--size", type=int, help="Define message size in bits", default=64
    )
    pedersen_parser.add_argument(
        "-p", "--personalisation", help="Provide personalisation string", default="test"
    )

    # batch pedersen hash subcommand
    pedersen_hasher_parser = subparsers.add_parser(
        "batch_hasher",
        help="Efficiently compute multiple Pedersen hashes. Support for stdin and interactive promt",
    )

    pedersen_hasher_parser.add_argument(
        "-s", "--size", type=int, help="Define message size in bits", default=64
    )
    pedersen_hasher_parser.add_argument(
        "-p", "--personalisation", help="Provide personalisation string", default="test"
    )

    # keygen subcommand
    keygen_parser = subparsers.add_parser(
        "keygen",
        help="Returns space separated hex-string for a random private/public keypair on BabyJubJub curve",
    )
    keygen_parser.add_argument(
        "-p",
        "--from_private",
        help="Provide existing private key as hex string (64 chars)",
    )

    # eddsa signature generation subcommand
    sig_gen_parser = subparsers.add_parser(
        "sig-gen",
        help="Returns eddsa signature as space separated hex string. Private key and message needs to be provided",
    )
    sig_gen_parser.add_argument(
        "private_key", nargs=1, help="Provide private key as hexstring (64chars)"
    )

    sig_gen_parser.add_argument(
        "message", nargs=1, help="Provide message as hex string"
    )

    # EdDSA signature verify subcommand
    sig_verify_parser = subparsers.add_parser(
        "sig-verify", help="Verifies a EdDSA signaure. Returns boolean flag for success"
    )
    sig_verify_parser.add_argument(
        "public_key", nargs=1, help="Provide public key as hex string (64 chars)"
    )
    sig_verify_parser.add_argument(
        "message", nargs=1, help="Provide message as hex string"
    )
    sig_verify_parser.add_argument(
        "signature",
        nargs=2,
        help="Provide signaure as space separated hex sting (2x 64 chars)",
    )

    args = parser.parse_args()
    subparser_name = args.subparser_name

    if subparser_name == "hash":
        preimage = bytes.fromhex(args.preimage[0])
        if len(preimage) != args.size:
            raise ValueError(
                "Bad length for preimage: {} vs {}".format(len(preimage), args.size)
            )

        personalisation = args.personalisation.encode("ascii")
        point = PedersenHasher(personalisation).hash_bytes(preimage)
        digest = point.compress()

        assert len(digest.hex()) == 32 * 2  # check for correct length
        print("Hash digest", file=sys.stderr)
        print(digest.hex())

    elif subparser_name == "batch_hasher":
        personalisation = args.personalisation.encode("ascii")
        ph = PedersenHasher(personalisation)
        try:
            while True:
                x = input()
                if x == "exit":
                    sys.exit(0)
                preimage = bytes.fromhex(x)
                if len(preimage) != args.size:
                    raise ValueError(
                        "Bad length for preimage: {} vs {}".format(len(preimage), 64)
                    )
                point = ph.hash_bytes(preimage)
                digest = point.compress()
                assert len(digest.hex()) == 32 * 2  # check for correct length
                print(digest.hex())
        except EOFError:
            pass

    elif subparser_name == "keygen":
        if args.from_private:
            fe = FQ(int(args.from_private[0]))
            sk = PrivateKey(fe)
        else:
            sk = PrivateKey.from_rand()
        pk = PublicKey.from_private(sk)

        pk_hex = pk.p.compress().hex()
        sk_hex = hex(sk.fe.n)[2:]

        print("PrivateKey PublicKey", file=sys.stderr)
        print("{} {}".format(sk_hex, pk_hex))

    elif subparser_name == "sig-gen":
        sk_hex = int(args.private_key[0], 16)
        sk = PrivateKey(FQ(sk_hex))
        msg = bytes.fromhex(args.message[0])

        (r, s) = sk.sign(msg)
        s_hex = hex(s)[2:]
        r_hex = r.compress().hex()

        print("Signature_R Signature_S", file=sys.stderr)
        print("{} {}".format(r_hex, s_hex))

    elif subparser_name == "sig-verify":
        r_hex, s_hex = args.signature[0], args.signature[1]
        msg = bytes.fromhex(args.message[0])
        pk_hex = args.public_key[0]

        pk = PublicKey(Point.decompress(bytes.fromhex(pk_hex)))
        r = Point.decompress(bytes.fromhex(r_hex))
        s = FQ(int(s_hex, 16))

        success = pk.verify((r, s), msg)
        if success:
            sys.exit(0)
        else:
            sys.exit("Could not verfiy signature")

    else:
        raise NotImplementedError(
            "Sub-command not implemented: {}".format(subparser_name)
        )


if __name__ == "__main__":
    main()
