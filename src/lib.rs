use constants::*;
/// Resources used:
/// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
/// https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
use key::Key;
use pad::{Padding, pkcs7_pad};
use Padding::PKCS7;
use state::State;

pub mod pad;
pub mod key;
mod state;
mod xor;
mod math;
mod word;
mod constants;
mod ctr;

#[derive(PartialEq, Debug)]
pub struct AESEncryptionOptions<'a> {
    pub block_cipher_mode: &'a BlockCipherMode<'a>,
    pub padding: &'a Padding,
}

impl<'a> AESEncryptionOptions<'a> {
    pub fn new(block_cipher_mode: &'a BlockCipherMode, padding: &'a Padding) -> Self {
        AESEncryptionOptions {
            block_cipher_mode,
            padding,
        }
    }
}

impl Default for AESEncryptionOptions<'_> {
    fn default() -> Self {
        AESEncryptionOptions::new(&BlockCipherMode::ECB, &Padding::None)
    }
}

#[derive(PartialEq, Debug)]
pub struct Block(pub [[u8; 4]; Nb]);

#[derive(PartialEq, Debug)]
pub enum BlockCipherMode<'a> {
    ECB,
    CBC(&'a Iv),
    CTR(&'a Nonce),
}

impl Block {
    pub fn empty() -> Self {
        Block([[0; 4]; Nb])
    }
}

pub type Iv = Block;
pub type Nonce = [u8; 8];

/// At the start of the Cipher, the input is copied to the State array using the conventions
/// described in Sec. 3.4. After an initial Round Key addition, the State array is transformed by
/// implementing a round function 10, 12, or 14 times (depending on the key length), with the
/// final round differing slightly from the first Nr -1 rounds. The final State is then copied to
/// the output as described in Sec. 3.4.
pub fn encrypt_aes_128(raw_bytes: &[u8], key: &Key, options: &AESEncryptionOptions) -> Vec<u8> {
    let block_size = 16;

    let w = &key.do_key_expansion().0;
    let bytes = &if options.padding == &PKCS7 {
        pkcs7_pad(raw_bytes, block_size)
    } else {
        if let BlockCipherMode::CTR(nonce) = &options.block_cipher_mode {
            ctr::generate_ctr_byte_stream_for_length(raw_bytes.len(), &nonce)
        } else {
            raw_bytes.to_vec()
        }
    };
    let parts = bytes_to_parts(bytes);

    let mut cipher: Vec<u8> = Vec::with_capacity(raw_bytes.len());
    let mut previous_state: State = State::empty();

    for (i, part) in parts.iter().enumerate() {
        let mut state = State::from_part(part);
        if let BlockCipherMode::CBC(iv) = &options.block_cipher_mode {
            if i == 0 {
                state.xor_with_iv(&iv);
            } else {
                state.xor_with_state(&previous_state);
            };
        }

        state.add_round_key(&w[0..Nb]);

        for round in 1..Nr {
            state.sub_bytes();
            state.shift_rows();
            state.mix_columns();
            state.add_round_key(&w[round * Nb..(round + 1) * Nb]);
        }

        state.sub_bytes();
        state.shift_rows();
        state.add_round_key(&w[Nr * Nb..(Nr + 1) * Nb]);

        if let BlockCipherMode::CBC(_iv) = &options.block_cipher_mode {
            previous_state = state.clone();
        }

        cipher.append(state.to_block().as_mut());
    }

    if let BlockCipherMode::CTR(_nonce) = &options.block_cipher_mode {
        xor::fixed_key_xor(&raw_bytes, &cipher)
    } else {
        cipher
    }
}

/// The Cipher transformations in Sec. 5.1 can be inverted and then implemented in reverse order to
/// produce a straightforward Inverse Cipher for the AES algorithm. The individual transformations
/// used in the Inverse Cipher - InvShiftRows(), InvSubBytes(),InvMixColumns(),
/// and AddRoundKey() – process the State and are described in the following subsections.
pub fn decrypt_aes_128(cipher: &[u8], key: &Key, mode: &BlockCipherMode) -> Vec<u8> {
    if let BlockCipherMode::CTR(_nonce) = mode {
        panic!("Cannot decrypt using CTR block cipher mode. Use encryption instead.");
    }

    let w = &key.do_key_expansion().0;
    let parts = bytes_to_parts(cipher);
    let mut deciphered: Vec<u8> = Vec::with_capacity(cipher.len());
    let mut previous_state = State::empty();

    for (i, part) in parts.iter().enumerate() {
        let mut state = State::from_part(part);

        state.add_round_key(&w[Nr * Nb..(Nr + 1) * Nb]);

        for round in (1..Nr).rev() {
            state.inv_shift_rows();
            state.inv_sub_bytes();
            state.add_round_key(&w[round * Nb..(round + 1) * Nb]);
            state.inv_mix_columns();
        }

        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&w[0..Nb]);

        if let BlockCipherMode::CBC(iv) = mode {
            if i == 0 {
                state.xor_with_iv(iv);
            } else {
                state.xor_with_state(&previous_state);
            };
            previous_state = State::from_part(part);
        }

        deciphered.append(state.to_block().as_mut());
    }

    deciphered
}

pub fn bytes_to_parts(bytes: &[u8]) -> Vec<Vec<u8>> {
    let block_size = 16usize;

    let mut parts = vec![
        vec![0; block_size]; (bytes.len() as f32 / block_size as f32).ceil() as usize
    ];
    for (i, byte) in bytes.iter().enumerate() {
        parts[(i as f32 / block_size as f32).floor() as usize][i % block_size] = *byte;
    }

    parts
}

/// Some encryption/decryption test cases are taken from:
/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#[cfg(test)]
mod tests {
    use pad::Padding;

    use super::*;

    const ECB_KEY: Key = Key([
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    ]);
    const RAW_ECB: [u8; 16] = [
        0x0, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    ];
    const CIPHERED_ECB: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8,
        0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80,
        0x70, 0xb4, 0xc5, 0x5a
    ];

    const CBC_KEY: Key = Key([
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    ]);
    const CBC_IV: Iv = Block([
        [0x00, 0x01, 0x02, 0x03],
        [0x04, 0x05, 0x06, 0x07],
        [0x08, 0x09, 0x0a, 0x0b],
        [0x0c, 0x0d, 0x0e, 0x0f]
    ]);
    const CIPHERED_CBC: [u8; 16] = [
        0x76, 0x49, 0xab, 0xac,
        0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b,
        0x12, 0xe9, 0x19, 0x7d
    ];
    const RAW_CBC: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2,
        0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11,
        0x73, 0x93, 0x17, 0x2a
    ];

    const CTR_KEY: Key = Key([
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    ]);
    const CTR_NONCE: Nonce = [0xff; 8];
    const RAW_CTR: [u8; 16] = [
        0x30, 0xc8, 0x1c, 0x46,
        0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef
    ];
    const CIPHERED_CTR: [u8; 16] = [
        0x27, 0x5c, 0x37, 0xf4,
        0xd3, 0x53, 0xf9, 0x93,
        0x2f, 0x6c, 0xd4, 0x60,
        0xa1, 0xc2, 0xb2, 0x25
    ];

    #[test]
    fn default_encryption_options_are_ecb_with_no_padding() {
        let encryption_options = AESEncryptionOptions::default();

        assert_eq!(encryption_options.block_cipher_mode, &BlockCipherMode::ECB);
        assert_eq!(encryption_options.padding, &Padding::None);
    }

    #[test]
    fn empty_produces_empty_block() {
        let block = Block::empty();
        let expected_block = [
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
        ];

        assert_eq!(block.0, expected_block);
    }

    #[test]
    fn encrypts_in_ecb_mode() {
        let actual_cipher = encrypt_aes_128(
            &RAW_ECB,
            &ECB_KEY,
            &AESEncryptionOptions::new(
                &BlockCipherMode::ECB,
                &Padding::None,
            ),
        );

        assert_eq!(actual_cipher, CIPHERED_ECB);
    }

    #[test]
    fn decrypts_in_ecb_mode() {
        let actual_raw = decrypt_aes_128(
            &CIPHERED_ECB,
            &ECB_KEY,
            &BlockCipherMode::ECB,
        );

        assert_eq!(actual_raw, RAW_ECB);
    }

    #[test]
    fn encrypts_in_cbc_mode() {
        let actual_cipher = encrypt_aes_128(
            &RAW_CBC,
            &CBC_KEY,
            &AESEncryptionOptions::new(
                &BlockCipherMode::CBC(&CBC_IV),
                &Padding::None,
            ),
        );

        assert_eq!(actual_cipher, CIPHERED_CBC);
    }

    #[test]
    fn decrypts_in_cbc_mode() {
        let actual_raw = decrypt_aes_128(
            &CIPHERED_CBC,
            &CBC_KEY,
            &BlockCipherMode::CBC(&CBC_IV),
        );

        assert_eq!(actual_raw, RAW_CBC);
    }

    #[test]
    fn encrypts_in_ctr_mode() {
        let actual_cipher = encrypt_aes_128(
            &RAW_CTR,
            &CTR_KEY,
            &AESEncryptionOptions::new(
                &BlockCipherMode::CTR(&CTR_NONCE),
                &Padding::None,
            ),
        );

        assert_eq!(actual_cipher, CIPHERED_CTR);
    }

    #[test]
    fn decrypts_in_ctr_mode() {
        // CTR decryption uses the dencryption process
        let actual_raw = encrypt_aes_128(
            &CIPHERED_CTR,
            &CTR_KEY,
            &AESEncryptionOptions::new(
                &BlockCipherMode::CTR(&CTR_NONCE),
                &Padding::None,
            ),
        );
    }

    #[test]
    #[should_panic(expected = "Cannot decrypt using CTR block cipher mode. Use encryption instead.")]
    fn decryption_in_ctr_mode_should_panic() {
        decrypt_aes_128(
            &CIPHERED_CTR,
            &CTR_KEY,
            &BlockCipherMode::CTR(&CTR_NONCE),
        );
    }

    #[test]
    fn bytes_to_parts_converts_bytes_to_parts_of_block_size_length() {
        let bytes: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19,
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x30, 0x31
        ];
        let expected_parts = [
            [bytes[..16].to_vec()],
            [bytes[16..].to_vec()]
        ].concat();

        assert_eq!(bytes_to_parts(&bytes.to_vec()), expected_parts);
    }
}