# Zero Knowledge Signature Verification

This repository contains the accompanying application code the for the blog post xxxxxxxx.

NOTE: Don't use this implementation for production.

### Instructions

Make sure you are running a python 3 runtime.

```bash
git clone git@github.com:stefandeml/zokrates_sig_example.git
pip install -r requirements.txt
```

Let's create a simple demo, called `demo.py`:

```python
import hashlib

from zokrates.eddsa import PrivateKey, PublicKey
from zokrates.field import FQ
from zokrates.utils import write_for_zokrates_cli

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
    write_for_zokrates_cli(pk, sig, msg, path)
```

We can now can run this python script via:

```bash
python demo.py
````

which should create a file called `zokrates_args`.
