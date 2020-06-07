extern crate aes_ndlr;

use aes_ndlr::{AESEncryptionOptions, decrypt_aes_128, encrypt_aes_128};
use aes_ndlr::key::Key;

fn main() {
    let text = "Some piece of text to encrypt".as_bytes();
    let key = Key::from_string("some key to use for encryption");
    let encryption_options = AESEncryptionOptions::default();

    let cipher = encrypt_aes_128(
        &text,
        &key,
        &AESEncryptionOptions::default(),
    );

    let deciphered_cipher = decrypt_aes_128(
        &cipher,
        &key,
        encryption_options.block_cipher_mode,
    );

    println!("Clear text: {}", String::from_utf8(text.to_vec()).unwrap());
    println!("Ciphertext: {}", String::from_utf8_lossy(&cipher));
    println!("Deciphered: {}", String::from_utf8(deciphered_cipher).unwrap());
}