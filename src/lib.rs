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
        let raw: &[u8] = &[
            0x0, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff
        ];
        let key = &Key([
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        ]);
        let expected_cipher = &[
            0x69, 0xc4, 0xe0, 0xd8,
            0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80,
            0x70, 0xb4, 0xc5, 0x5a
        ];

        let actual_cipher = encrypt_aes_128(
            &raw,
            &key,
            &AESEncryptionOptions::new(
                &BlockCipherMode::ECB,
                &Padding::None,
            ),
        );

        assert_eq!(actual_cipher, expected_cipher);
    }

    #[test]
    fn decrypts_in_ecb_mode() {
        let cipher: &[u8] = &[
            0x69, 0xc4, 0xe0, 0xd8,
            0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80,
            0x70, 0xb4, 0xc5, 0x5a
        ];
        let key = &Key([
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        ]);
        let expected_raw = &[
            0x0, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff
        ];

        let actual_raw = decrypt_aes_128(&cipher, &key, &BlockCipherMode::ECB);

        assert_eq!(actual_raw, expected_raw);
    }

    #[test]
    fn encrypt_in_cbc_mode() {}

    #[test]
    fn encrypts_in_cbc_mode() {}

    #[test]
    fn encrypts_in_ctr_mode() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
        ];
        let plain = [
            0xf6, 0x9f, 0x24, 0x45,
            0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b,
            0xe6, 0x6c, 0x37, 0x10
        ];
        let cipher = [
            0x1e, 0x03, 0x1d, 0xda,
            0x2f, 0xbe, 0x03, 0xd1,
            0x79, 0x21, 0x70, 0xa0,
            0xf3, 0x00, 0x9c, 0xee
        ];
    }

    #[test]
    fn decrypts_in_ctr_mode() {}

    #[test]
    fn bytes_to_parts_converts_bytes_to_parts_of_block_size_length() {
        let bytes: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
        ];
        let expected_parts = [
            [bytes[..16].to_vec()],
            [bytes[16..].to_vec()]
        ].concat();

        assert_eq!(bytes_to_parts(&bytes.to_vec()), expected_parts);
    }
}