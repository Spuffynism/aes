extern crate rand;

use self::rand::RngCore;
use aes::{Iv, Block, key::Key};

pub fn generate_iv() -> Iv {
    let byte = random_byte;
    Block([
        [byte(), byte(), byte(), byte()],
        [byte(), byte(), byte(), byte()],
        [byte(), byte(), byte(), byte()],
        [byte(), byte(), byte(), byte()]
    ])
}

pub fn random_byte() -> u8 {
    rand::random::<u8>()
}

pub fn generate_key() -> Key {
    let mut key = [0; 16];
    for item in key.iter_mut() {
        *item = random_byte();
    }

    Key(key)
}

pub fn generate_bytes_for_length(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut bytes);

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_iv() {
        let iv = generate_iv().0;

        assert_some_randomness(&iv);
        assert_eq!(iv.len(), 4);

        iv.iter()
            .for_each(|row| {
                assert_some_randomness(&row[..]);
                assert_eq!(row.len(), 4);
            });
    }

    #[test]
    fn generates_key() {
        let key = generate_key().0;

        assert_some_randomness(&key[..]);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn generate_bytes_for_length_test() {
        let length = 51;
        let bytes = generate_bytes_for_length(length);

        assert_some_randomness(&bytes);
        assert_eq!(bytes.len(), length as usize);
    }

    fn assert_some_randomness<T>(random_bytes: &[T]) {
        assert!(!random_bytes.is_empty());
    }
}