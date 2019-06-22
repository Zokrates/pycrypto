# ZoKrates pyCrypto

This repository contains accompanying crypto application code the for the zkSNARKs toolbox [ZoKrates](https://github.com/Zokrates/ZoKrates).

_This is a proof-of-concept implementation. It has not been tested for production._


## Install

Make sure you are running a python 3 runtime.

```bash
git clone https://github.com/Zokrates/pycrypto.git
pip install -r requirements.txt
```

## Example

### Compute SNARK-friendly Pedersen hash
Let's create a simple demo, called `demo.py`:
```python
from zokrates.gadgets.pedersenHasher import PedersenHasher

preimage = bytes.fromhex("1616")
# create an instance with personalisation string
hasher = PedersenHasher(b"test")
# hash payload
digest = hasher.hash_bytes(preimage)
print(digest)
# x:2685288813799964008676827085163841323150845457335242286797566359029072666741,
# y:3621301112689898657718575625160907319236763714743560759856749092648347440543

# write ZoKrates DSL code to disk
path = "pedersen.code"
hasher.write_dsl_code(path)

# write witness arguments to disk
path = "pedersen_witness.txt"
witness = hasher.gen_dsl_witness_bytes(preimage)
with open(path, "w+") as f:
    f.write(" ".join(witness))
```

We can now can run this python script via:

```bash
python demo.py
```
which should create the ZoKrates DSL code file `pedersen.code`, as well as a file which contains the witness `pedersen_witness.txt`.

Make sure you have the `zokrates` executable in the same folder. Then run the following command to compile the SNARK-circuit:
```bash
./zokrates compile -i pedersen.code
```

We can now conpute the witness:
```bash
`cat zokrates_witness.txt | ./zokrates compute-witness`

Witness:

~out_1 3621301112689898657718575625160907319236763714743560759856749092648347440543
~out_0 2685288813799964008676827085163841323150845457335242286797566359029072666741
```

As you can easily verify we get the same pedersen hash point for the Python and ZoKrates implementation.

### Create and verify Eddsa signature
Let's create a simple demo, called `demo.py`:

```python
import hashlib

from zokrates.eddsa import PrivateKey, PublicKey
from zokrates.field import FQ
from zokrates.utils import write_signature_for_zokrates_cli

if __name__ == "__main__":

    raw_msg = "This is my secret message"
    msg = hashlib.sha512(raw_msg.encode("utf-8")).digest()

    # sk = PrivateKey.from_rand()
    # Seeded for debug purpose
    key = FQ(1997011358982923168928344992199991480689546837621580239342656433234255379025)
    sk = PrivateKey(key)
    sig = sk.sign(msg)

    pk = PublicKey.from_private(sk)
    is_verified = pk.verify(sig, msg)
    print(is_verified)

    path = 'zokrates_witness.txt'
    write_signature_for_zokrates_cli(pk, sig, msg, path)
```

We can now can run this python script via:

```bash
python demo.py
```

which should create a file called `zokrates_witness.txt`.

These arguments can now be passed to the `verifyEddsa` function in ZoKrates via:

`cat zokrates_witness.txt | ./zokrates compute-witness`

## CLI Usage

`pycrypto` also provides a simple command-line interface to make it easy to integrate the used crypto primitives into your existing application code.

Some examples:

### Compute SNARK-friendly Pedersen hash
```bash
python cli.py hash 3755668da8deabd8cafbe1c26cda5a837ed5f832665c5ef94725f6884054d9083755668da8deabd8cafbe1c26cda5a837ed5f832665c5ef94725f6884054d908
```
where the first argument denotes the preimage as a hexstring.

### Create and verify a Eddsa signature
```bash
python cli.py keygen
# => 2af7ce3cba7002380d9e91f3c62b674e795aae6dfa6b949c8eaa8931c8a61267 3755668da8deabd8cafbe1c26cda5a837ed5f832665c5ef94725f6884054d908
# Private and public key

python cli.py sig-gen 2af7ce3cba7002380d9e91f3c62b674e795aae6dfa6b949c8eaa8931c8a61267 test_message
# => b844b6c30987ebe51ad8571c2b87149a6e738310128c8094ca141280d3b6ad91 130e85471c8b29c8f007ccc189d48e822fb4c98bee5f8368d5d0cb75c94f7712
# R and S element of Eddsa signature

python cli.py sig-verify 3755668da8deabd8cafbe1c26cda5a837ed5f832665c5ef94725f6884054d908 lol b844b6c30987ebe51ad8571c2b87149a6e738310128c8094ca141280d3b6ad91 130e85471c8b29c8f007ccc189d48e822fb4c98bee5f8368d5d0cb75c94f7712
# => True
```

## Contributing

We happily welcome contributions. You can either pick an existing issue, or reach out on [Gitter](https://gitter.im/ZoKrates/Lobby).

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in the work shall be licensed as above, without any additional terms or conditions.

### Setup
First install the development packages via `pip install -r requirements-dev.txt`.

In addition this repo uses the python package `pre-commit` to make sure the correct formatting (black & flake) is applied and all tests pass.
You can install it via `pip install pre-commit`.

Then you just need to call `pre-commit install`.

## License

This repo is released under the GNU Lesser General Public License v3.
