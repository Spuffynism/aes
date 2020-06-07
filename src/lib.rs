use key::Key;
use pad::{Padding, pkcs7_pad};
/// Resources used:
/// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
/// https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
use Padding::PKCS7;

pub mod pad;
pub mod key;
mod state;
mod xor;
mod math;
mod word;

/// Non-linear substitution table used in several byte substitution transformations and in the
/// Key Expansion routine to perform a one-for-one substitution of a byte value.
const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

/// Inverse of the S-BOX. Used in the InvSubBytes step to perform reverse one-for-one substitution
/// of a byte.
const INVERSE_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

/// Number of columns (32-bit words) comprising the State. For this standard, Nb = 4.
#[allow(non_upper_case_globals)]
const Nb: usize = 4;

/// Number of rounds, which is a function of Nk and Nb (which is fixed). For this implementation,
/// Nr = 10. (because this is only aes-128)
#[allow(non_upper_case_globals)]
const Nr: usize = 10;

/// Number of 32-bit words comprising the Cipher Key. For this implementation, Nk = 4. (because
/// this is only aes-128)
#[allow(non_upper_case_globals)]
const Nk: usize = 4;

/// Round constant word array.
#[allow(non_upper_case_globals)]
const Rcon: [[u8; 4]; 10] = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00],
];

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
pub enum BlockCipherMode<'a> {
    ECB,
    CBC(&'a Iv),
    CTR(&'a Nonce),
}

#[derive(PartialEq, Debug)]
pub struct Block(pub [[u8; 4]; Nb]);

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
            generate_ctr_bytes_for_length(raw_bytes.len(), &nonce)
        } else {
            raw_bytes.to_vec()
        }
    };
    let parts = bytes_to_parts(bytes);

    let mut cipher: Vec<u8> = Vec::with_capacity(raw_bytes.len());
    let mut previous_state: state::State = state::State::empty();

    for (i, part) in parts.iter().enumerate() {
        let mut state = state::State::from_part(part);
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

// TODO(nich): Spend time to make sure this works correctly
fn generate_ctr_bytes_for_length(length: usize, nonce: &Nonce) -> Vec<u8> {
    let block_size = 16;
    let mut counter = 0u8;
    (0..length - (length % block_size) + block_size).collect::<Vec<usize>>()
        .iter()
        .enumerate()
        .map(|(i, _)|
            if (i % block_size) < nonce.len() {
                nonce[i % block_size]
            } else if (i % block_size) == nonce.len() {
                counter += 1;

                counter - 1
            } else {
                0u8
            }
        )
        .collect::<Vec<u8>>()
}

/// The Cipher transformations in Sec. 5.1 can be inverted and then implemented in reverse order to
/// produce a straightforward Inverse Cipher for the AES algorithm. The individual transformations
/// used in the Inverse Cipher - InvShiftRows(), InvSubBytes(),InvMixColumns(),
/// and AddRoundKey() – process the State and are described in the following subsections.
pub fn decrypt_aes_128(cipher: &[u8], key: &Key, mode: &BlockCipherMode) -> Vec<u8> {
    let w = &key.do_key_expansion().0;
    let parts = bytes_to_parts(cipher);
    let mut deciphered: Vec<u8> = Vec::with_capacity(cipher.len());
    let mut previous_state = state::State::empty();

    for (i, part) in parts.iter().enumerate() {
        let mut state = state::State::from_part(part);

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
            previous_state = state::State::from_part(part);
        }

        deciphered.append(state.to_block().as_mut());
    }

    deciphered
}

pub fn bytes_to_parts(bytes: &[u8]) -> Vec<Vec<u8>> {
    let block_size = 16;

    let mut parts = vec![
        vec![0; block_size as usize]; (bytes.len() as f32 / block_size as f32).ceil() as usize
    ];
    for (i, byte) in bytes.iter().enumerate() {
        parts[(i as f32 / block_size as f32).floor() as usize][i % block_size as usize] = *byte;
    }

    parts
}

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
    fn encrypt_aes_128_in_ecb_mode_encrypts() {
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
    #[ignore]
    fn generate_ctr_bytes_for_length_test() {
        let length = 15;
        let nonce = [0, 1, 2, 3, 4, 5, 6, 7];

        let generated_bytes = generate_ctr_bytes_for_length(length, &nonce);

        assert!(false, "TODO: Write tests for ctr bytes generation for length");
    }

    #[test]
    fn decrypt_aes_128_in_ecb_mode_nist_test_case() {
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
    fn bytes_to_parts_converts_bytes_to_parts_of_block_size_length() {
        let bytes: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
        ];
        let expected_parts = vec![
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            vec![16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
        ];

        assert_eq!(bytes_to_parts(&bytes.to_vec()), expected_parts);
    }
}