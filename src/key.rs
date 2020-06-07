use ::{Nb, Nk, Nr, xor};
use word::{rot_word, sub_word};
use Rcon;

#[derive(PartialEq, Debug)]
pub struct Key(pub [u8; 16]);

pub struct KeySchedule(pub [[u8; 4]; Nb * (Nr + 1)]);

impl Key {
    pub fn from_string(string: &str) -> Self {
        let mut out = [0u8; 16];
        let bytes = string.as_bytes();
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = bytes[i];
        }

        Key(out)
    }

    /// Routine used to generate a series of Round Keys from the Cipher Key.
    /// The Key Expansion generates a total of Nb (Nr + 1) words: the algorithm requires
    /// an initial set of Nb words, and each of the Nr rounds requires Nb words of key data. The
    /// resulting key schedule consists of a linear array of 4-byte words, denoted [wi ], with i in
    /// the range 0 <= i < Nb(Nr + 1).
    pub fn do_key_expansion(&self) -> KeySchedule {
        let mut w = [[0u8; Nk]; Nb * (Nr + 1)];

        for i in 0..Nk {
            let key_part = &self.0[4 * i..4 * i + 4];
            w[i] = [key_part[0], key_part[1], key_part[2], key_part[3]];
        }

        for i in Nk..(Nb * (Nr + 1)) {
            let mut temp = w[i - 1].to_vec();
            if i % Nk == 0 {
                let xored = xor::fixed_key_xor(
                    &sub_word(&rot_word(&temp)),
                    &Rcon[(i / Nk) - 1],
                );
                temp = xored;
            } else if Nk > 6 && i % Nk == 4 {
                temp = sub_word(&temp);
            }
            let key = xor::fixed_key_xor(&w[i - Nk][..], &temp);
            w[i] = [key[0], key[1], key[2], key[3]];
        }

        KeySchedule(w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_creates_key_from_string() {
        let key = Key::from_string("SOME KEY ABCDEFG");
        let expected_key_value = [
            0x53, 0x4f, 0x4d, 0x45,
            0x20, 0x4b, 0x45, 0x59,
            0x20, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47
        ];

        assert_eq!(key.0, expected_key_value);
    }

    #[test]
    fn key_expansion_test() {
        // as provided in official paper
        let key = &Key([
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
        ]);
        // also known as w
        let expected_key_schedule: [[u8; 4]; 44] = [
            // copy of key
            [0x2b, 0x7e, 0x15, 0x16],
            [0x28, 0xae, 0xd2, 0xa6],
            [0xab, 0xf7, 0x15, 0x88],
            [0x09, 0xcf, 0x4f, 0x3c],

            // rest of expansion
            [0xa0, 0xfa, 0xfe, 0x17],
            [0x88, 0x54, 0x2c, 0xb1],
            [0x23, 0xa3, 0x39, 0x39],
            [0x2a, 0x6c, 0x76, 0x05],
            [0xf2, 0xc2, 0x95, 0xf2],
            [0x7a, 0x96, 0xb9, 0x43],
            [0x59, 0x35, 0x80, 0x7a],
            [0x73, 0x59, 0xf6, 0x7f],
            [0x3d, 0x80, 0x47, 0x7d],
            [0x47, 0x16, 0xfe, 0x3e],
            [0x1e, 0x23, 0x7e, 0x44],
            [0x6d, 0x7a, 0x88, 0x3b],
            [0xef, 0x44, 0xa5, 0x41],
            [0xa8, 0x52, 0x5b, 0x7f],
            [0xb6, 0x71, 0x25, 0x3b],
            [0xdb, 0x0b, 0xad, 0x00],
            [0xd4, 0xd1, 0xc6, 0xf8],
            [0x7c, 0x83, 0x9d, 0x87],
            [0xca, 0xf2, 0xb8, 0xbc],
            [0x11, 0xf9, 0x15, 0xbc],
            [0x6d, 0x88, 0xa3, 0x7a],
            [0x11, 0x0b, 0x3e, 0xfd],
            [0xdb, 0xf9, 0x86, 0x41],
            [0xca, 0x00, 0x93, 0xfd],
            [0x4e, 0x54, 0xf7, 0x0e],
            [0x5f, 0x5f, 0xc9, 0xf3],
            [0x84, 0xa6, 0x4f, 0xb2],
            [0x4e, 0xa6, 0xdc, 0x4f],
            [0xea, 0xd2, 0x73, 0x21],
            [0xb5, 0x8d, 0xba, 0xd2],
            [0x31, 0x2b, 0xf5, 0x60],
            [0x7f, 0x8d, 0x29, 0x2f],
            [0xac, 0x77, 0x66, 0xf3],
            [0x19, 0xfa, 0xdc, 0x21],
            [0x28, 0xd1, 0x29, 0x41],
            [0x57, 0x5c, 0x00, 0x6e],
            [0xd0, 0x14, 0xf9, 0xa8],
            [0xc9, 0xee, 0x25, 0x89],
            [0xe1, 0x3f, 0x0c, 0xc8],
            [0xb6, 0x63, 0x0c, 0xa6]
        ];

        let actual_key_schedule = key.do_key_expansion();

        assert_eq!(actual_key_schedule.0.to_vec(), expected_key_schedule.to_vec());
    }
}