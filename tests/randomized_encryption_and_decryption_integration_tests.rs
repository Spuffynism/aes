extern crate aes_ndlr as aes;

use std::ops::Range;

use aes::{AESEncryptionOptions, BlockCipherMode, decrypt_aes_128, encrypt_aes_128, pad::Padding};
use generate::{generate_bytes_for_length, generate_iv, generate_key};

mod generate;

const BLOCK_SIZE: usize = 16;
const TEST_CASES: Range<usize> = 0..100;

#[test]
fn encrypt_and_decrypt_ecb() {
    for _ in TEST_CASES {
        let raw_size = generate::random_byte() as usize * BLOCK_SIZE;
        let raw: &[u8] = &generate_bytes_for_length(raw_size)[..];
        let key = &generate_key();
        let iv = &generate_iv();

        let cipher = encrypt_aes_128(
            &raw,
            key,
            &AESEncryptionOptions::new(
                &BlockCipherMode::CBC(iv),
                &Padding::None,
            ),
        );
        let actual_deciphered = decrypt_aes_128(&cipher, key, &BlockCipherMode::CBC(iv));

        assert_eq!(raw, &actual_deciphered[..]);
    }
}

#[test]
fn encrypt_and_decrypt_cbc() {
    for _ in TEST_CASES {
        let raw_size = generate::random_byte() as usize * BLOCK_SIZE;
        let raw: &[u8] = &generate_bytes_for_length(raw_size)[..];
        let key = &generate_key();
        let iv = &generate_iv();

        let cipher = encrypt_aes_128(
            &raw,
            key,
            &AESEncryptionOptions::new(
                &BlockCipherMode::CBC(iv),
                &Padding::None,
            ),
        );
        let actual_deciphered = decrypt_aes_128(&cipher, key, &BlockCipherMode::CBC(iv));

        assert_eq!(raw, &actual_deciphered[..]);
    }
}

#[test]
fn encrypt_and_decrypt_ctr() {
    for _ in TEST_CASES {
        let raw_size = generate::random_byte() as usize * BLOCK_SIZE;
        let raw: &[u8] = &generate_bytes_for_length(raw_size)[..];
        let key = &generate_key();
        let generated_bytes = generate_bytes_for_length(8);
        let nonce = [
            generated_bytes[0],
            generated_bytes[1],
            generated_bytes[2],
            generated_bytes[3],
            generated_bytes[4],
            generated_bytes[5],
            generated_bytes[6],
            generated_bytes[7],
        ];
        let mode = BlockCipherMode::CTR(&nonce);
        let options = &AESEncryptionOptions::new(
            &mode,
            &Padding::None,
        );

        let ciphered = encrypt_aes_128(&raw, &key, &options);
        let deciphered = encrypt_aes_128(&ciphered, &key, &options);

        assert_eq!(deciphered, raw);
    }
}