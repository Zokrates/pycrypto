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

    path = './zokrates_args'
    write_signature_for_zokrates_cli(pk, sig, msg, path)
```

We can now can run this python script via:

```bash
python demo.py
```

which should create a file called `zokrates_args`.

These arguments can now be passed to the `verifyEddsa` function in ZoKrates via:

`cat zokrates_args | ./zokrates compute-witness`

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
