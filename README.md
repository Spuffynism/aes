[![crates.io](https://img.shields.io/badge/aes--ndlr-0.0.1-orange.svg)](https://crates.io/crates/aes-ndlr)

# aes-ndlr

A Rust AES implementation.

Supports ECB, CBC and CTR block cipher modes and PKCS7 padding.

## TODO

- ~~make usable as library~~
- ~~publish on crates.io~~
- ~~Remove generate.rs module as it's only used in tests~~
- ~~Remove rand dependency~~
- complete unit tests
    - ~~math~~
    - ~~xor~~
    - ~~state~~
    - lib
- complete integration tests
    - aes
- see about using property testing