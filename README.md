passw00t
========

Toy secure password locker.

Uses one file per encrypted "box" to be dropbox/sync friendly.

Boxes are encrypted with 256-bit AES key.

Key is unlocked from a `master.keys` file, which contains
the scrypt-encrypted key which is secured by the user's password.

All data structures are Protocol Buffers.  See `passw00t.proto` for
the spec.  The test program, `passw00t.py` uses:

    * https://pypi.python.org/pypi/palm/
    * https://pypi.python.org/pypi/pycrypto/
    * https://pypi.python.org/pypi/scrypt/
