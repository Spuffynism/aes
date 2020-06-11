[![crates.io](https://img.shields.io/badge/aes--ndlr-0.0.2-orange.svg)](https://crates.io/crates/aes-ndlr)

# aes-ndlr

A Rust AES implementation.

Supports ECB, CBC and CTR block cipher modes and PKCS7 padding.

## TODO

- ~~make usable as library~~
- ~~publish on crates.io~~
- ~~Remove generate.rs module as it's only used in tests~~
- ~~Remove rand dependency~~
- ~~complete unit tests~~
    - ~~math~~
    - ~~xor~~
    - ~~state~~
    - ~~ctr~~
    - ~~lib~~
- ~~complete integration tests~~
    - ~~aes~~
- see about using property testing
- properly document each file & functions
    - constants
    - key
    - lib
    - math
    - pad
    - state
    - word
    - xor
- ~~see about using randomly generated integration tests for encryption and decryption~~