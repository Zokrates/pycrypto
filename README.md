<img src="icon.jpg" width="120px" align="right" />


# ZnaKes

A one-stop client library which facilitates the creation of arguments for zero-knowledge Proofs. ZnaKes provide an easy interface to generate zk-friendly crypto primitives necessary in efficient circuits developed with popular tools such as ZoKrates, Circom, Noir and so on...

:warning: _This is a proof-of-concept implementation. It has not been tested for production._

This repository code is primarily based from [ZoKrates Pycrypto](https://github.com/Zokrates/pycrypto) for the zkSNARKs toolbox [ZoKrates](https://github.com/Zokrates/ZoKrates).
Nonetheless, we plan of adding more primitives support by other tools as well.
Some of these primitives are:

- Poseidon, mimc and pedersen hashes.
- EdDSA signatures for multiple curves (`BN254`, `BLS12_381`...)
- ... and more!


## Install

Make sure you are running a python 3 runtime.

```bash
git clone https://github.com/ZK-Plus/ZnaKes.git && cd ZnaKes
pip install -r requirements.txt
```

## Example

### Create and verify Eddsa signature
Let's create a simple demo, called `demo.py`, in which we sign a hashed message with the BabyJubJub curve:

```python
import hashlib

from znakes.curves import BabyJubJub
from znakes.eddsa import PrivateKey, PublicKey

if __name__ == "__main__":

    raw_msg = "This is my secret message"
    msg = hashlib.sha512(raw_msg.encode("utf-8")).digest()

    sk = PrivateKey.from_rand()
    sig = sk.sign(msg)

    pk = PublicKey.from_private(sk)
    is_verified = pk.verify(sig, msg)
    print(is_verified)
```

## Contributing

We happily welcome contributions. You can either pick an existing issue or create a new issue. Before that make sure you have read our [CODE_OF_CONDUCT](.github/CODE_OF_CONDUCT.md) and [CONTRIBUTION GUIDELINES](.github/CONTRIBUTING.md)

Please note that your submited contributions shall be licensed as below, without any additional terms or conditions.

### Setup
First install the development packages via `pip install -r requirements-dev.txt`.

In addition this repo uses the python package `pre-commit` to make sure the correct formatting (black & flake) is applied and all tests pass.
You can install it via `pip install pre-commit`.

Then you just need to call `pre-commit install`.

## Acknowledgements

- [ZoKrates dev tem](https://github.com/Zokrates/ZoKrates/graphs/contributors) for providing a great starting point for this project and for the awesome tool ZoKrates.
- [jesse squires](https://github.com/jessesquires/.github) for the great `CONTRIBUTING.md` and `CODE_OF_CONDUCT` guidelines.
- [Josee9988](https://github.com/Josee9988/project-template) for the amazing issue templates.

## License

This repo is released under the GNU Lesser General Public License v3.
