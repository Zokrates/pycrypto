# ZoKrates pyCrypto

This repository contains accompanying crypto application code for the zkSNARKs toolbox [ZoKrates](https://github.com/Zokrates/ZoKrates).

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
from zokrates_pycrypto.gadgets.pedersenHasher import PedersenHasher

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

from zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from zokrates_pycrypto.field import FQ
from zokrates_pycrypto.utils import write_signature_for_zokrates_cli

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

    path = 'zokrates_inputs.txt'
    write_signature_for_zokrates_cli(pk, sig, msg, path)
```

We can now can run this python script via:

```bash
python demo.py
```

which should create a file called `zokrates_inputs.txt`.

We can now create a small ZoKrates DSL file which wraps the existing `verifyEddsa` function in the standard library.

```
from "ecc/babyjubjubParams" import BabyJubJubParams
import "signatures/verifyEddsa.code" as verifyEddsa
import "ecc/babyjubjubParams.code" as context

def main(private field[2] R, private field S, field[2] A, u32[8] M0, u32[8] M1) -> (bool):

	BabyJubJubParams context = context()
	
    bool isVerified = verifyEddsa(R, S, A, M0, M1, context)

	return isVerified
````

After compiling this file we can now pass our input arguments into witness generation:

`cat zokrates_inputs.txt | ./zokrates compute-witness`

## CLI Usage

`pycrypto` also provides a simple command-line interface to make it easy to integrate the used crypto primitives into your existing application code.

Some examples:

### Compute SNARK-friendly Pedersen hash
```bash
python cli.py hash 3755668da8deabd8cafbe1c26cda5a837ed5f832665c5ef94725f6884054d9083755668da8deabd8cafbe1c26cda5a837ed5f832665c5ef94725f6884054d908
```
where the first argument denotes the preimage as a hexstring.

### Create and verify an EdDSA signature
```bash
python cli.py keygen
# => 37e334c51386a5c92152f592ef264b82ad52cf2bbfb6cee1c363e67be97732a ab466cd8924518f07172c0f8c695c60f77c11357b461d787ef31864a163f3995
# Private and public key

python cli.py sig-gen 37e334c51386a5c92152f592ef264b82ad52cf2bbfb6cee1c363e67be97732a 11dd22
# => 172a1794976d7d0272148c4be3b7ad74fd3a82376cd5995fc4d274e3593c0e6c 24e96be628208a9800336d23bd31318d8a9b95bc9bd8f6f01cae207c05062523
# R and S element of EdDSA signature

python cli.py sig-verify ab466cd8924518f07172c0f8c695c60f77c11357b461d787ef31864a163f3995 11dd22 172a1794976d7d0272148c4be3b7ad74fd3a82376cd5995fc4d274e3593c0e6c 24e96be628208a9800336d23bd31318d8a9b95bc9bd8f6f01cae207c05062523
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
