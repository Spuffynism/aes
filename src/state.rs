use ::{math, Nb};
use ::{S_BOX, INVERSE_S_BOX};
use Iv;

#[derive(Debug, Clone, PartialEq)]
pub struct State {
    data: [[u8; 4]; Nb],
}

impl State {
    pub fn from_part(part: &[u8]) -> State {
        let mut state = State::empty();
        for r in 0..4 {
            for c in 0..Nb {
                state.data[c][r] = part[r + 4 * c];
            }
        }

        state
    }

    pub fn empty() -> State {
        State { data: [[0u8; 4]; Nb] }
    }

    pub fn to_block(&self) -> Vec<u8> {
        let mut out = vec![0u8; 4 * Nb];
        for r in 0..4 {
            for c in 0..Nb {
                out[r + 4 * c] = self.data[c][r];
            }
        }

        out
    }

    pub fn xor_with_state(&mut self, other: &State) {
        self.xor(&[&other.data[0], &other.data[1], &other.data[2], &other.data[3]])
    }

    pub fn xor(&mut self, data: &[&[u8; 4]; Nb]) {
        for r in 0..4 {
            for c in 0..Nb {
                self.data[r][c] ^= data[r][c];
            }
        }
    }

    pub fn xor_with_iv(&mut self, iv: &Iv) {
        for r in 0..4 {
            for c in 0..Nb {
                self.data[r][c] ^= iv.0[r][c];
            }
        }
    }

    /// Transformation in the Cipher and Inverse Cipher in which a Round
    /// Key is added to the State using an XOR operation. The length of a
    /// Round Key equals the size of the State (i.e., for Nb = 4, the Round
    /// Key length equals 128 bits/16 bytes).
    /// TODO: Add length restriction to round_key
    pub fn add_round_key(&mut self, round_key: &[[u8; 4]]) {
        self.xor(&[&round_key[0], &round_key[1], &round_key[2], &round_key[3]]);
    }

    /// Transformation in the Cipher that processes the State using a nonlinear byte
    /// substitution table (S-box) that operates on each of the State bytes
    /// independently.
    pub fn sub_bytes(&mut self) {
        self.sub_bytes_with_box(&S_BOX)
    }

    /// Transformation in the Inverse Cipher that is the inverse of SubBytes
    pub fn inv_sub_bytes(&mut self) {
        self.sub_bytes_with_box(&INVERSE_S_BOX)
    }

    fn sub_bytes_with_box(&mut self, substitution_box: &[u8; 256]) {
        for row in self.data.iter_mut() {
            for byte in row.iter_mut() {
                *byte = substitution_box[*byte as usize];
            }
        }
    }

    /// Transformation in the Cipher that processes the State by cyclically
    /// shifting the last three rows of the State by different offsets.
    pub fn shift_rows(&mut self) {
        self.data = [
            [self.data[0][0], self.data[1][1], self.data[2][2], self.data[3][3]],
            [self.data[1][0], self.data[2][1], self.data[3][2], self.data[0][3]],
            [self.data[2][0], self.data[3][1], self.data[0][2], self.data[1][3]],
            [self.data[3][0], self.data[0][1], self.data[1][2], self.data[2][3]],
        ]
    }

    /// Transformation in the Inverse Cipher that is the inverse of ShiftRows
    pub fn inv_shift_rows(&mut self) {
        self.data = [
            [self.data[0][0], self.data[3][1], self.data[2][2], self.data[1][3]],
            [self.data[1][0], self.data[0][1], self.data[3][2], self.data[2][3]],
            [self.data[2][0], self.data[1][1], self.data[0][2], self.data[3][3]],
            [self.data[3][0], self.data[2][1], self.data[1][2], self.data[0][3]],
        ]
    }

    /// Transformation in the Cipher that takes all of the columns of the
    /// State and mixes their data (independently of one another) to
    /// produce new columns.
    pub fn mix_columns(&mut self) {
        let fixed_polynomial: &[&[u8]] = &[
            &[0x02, 0x03, 0x01, 0x01],
            &[0x01, 0x02, 0x03, 0x01],
            &[0x01, 0x01, 0x02, 0x03],
            &[0x03, 0x01, 0x01, 0x02],
        ];
        self.mix_columns_using_substitution_matrix(fixed_polynomial)
    }

    /// Transformation in the Inverse Cipher that is the inverse of MixColumns
    pub fn inv_mix_columns(&mut self) {
        let fixed_polynomial: &[&[u8]] = &[
            &[0x0e, 0x0b, 0x0d, 0x09],
            &[0x09, 0x0e, 0x0b, 0x0d],
            &[0x0d, 0x09, 0x0e, 0x0b],
            &[0x0b, 0x0d, 0x09, 0x0e],
        ];

        self.mix_columns_using_substitution_matrix(fixed_polynomial)
    }

    // TODO: Find a way to do this without using a temporary array
    fn mix_columns_using_substitution_matrix(&mut self, substitution_matrix: &[&[u8]]) {
        let mut mixed_columns = [[0; 4]; Nb];
        for c in 0..Nb {
            for r in 0..4 {
                let mut multiplications_xor = 0;
                for i in 0..4 {
                    multiplications_xor ^= math::multiply_in_g(substitution_matrix[r][i],
                                                               self.data[c][i])
                }
                mixed_columns[c][r] = multiplications_xor
            }
        }

        self.data = mixed_columns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_round_key_test() {
        let key_schedule: &[[u8; 4]; 4] = &[
            [0x13, 0x11, 0x1d, 0x7f],
            [0xe3, 0x94, 0x4a, 0x17],
            [0xf3, 0x07, 0xa7, 0x8b],
            [0x4d, 0x2b, 0x30, 0xc5]
        ];
        let mut state = State {
            data: [
                [0x69, 0xc4, 0xe0, 0xd8],
                [0x6a, 0x7b, 0x04, 0x30],
                [0xd8, 0xcd, 0xb7, 0x80],
                [0x70, 0xb4, 0xc5, 0x5a]
            ]
        };
        let expected_state = State {
            data: [
                [0x7a, 0xd5, 0xfd, 0xa7],
                [0x89, 0xef, 0x4e, 0x27],
                [0x2b, 0xca, 0x10, 0x0b],
                [0x3d, 0x9f, 0xf5, 0x9f]
            ]
        };

        state.add_round_key(key_schedule);

        assert_eq!(state, expected_state);
    }

    #[test]
    fn mix_columns_test() {}

    #[test]
    fn inv_mix_columns_test() {
        let test_cases = &mut [
            (State {
                data: [
                    [0xbd, 0x6e, 0x7c, 0x3d],
                    [0xf2, 0xb5, 0x77, 0x9e],
                    [0x0b, 0x61, 0x21, 0x6e],
                    [0x8b, 0x10, 0xb6, 0x89]
                ]
            }, State {
                data: [
                    [0x47, 0x73, 0xb9, 0x1f],
                    [0xf7, 0x2f, 0x35, 0x43],
                    [0x61, 0xcb, 0x01, 0x8e],
                    [0xa1, 0xe6, 0xcf, 0x2c]
                ]
            }),
            (State {
                data: [
                    [0xfd, 0xe3, 0xba, 0xd2],
                    [0x05, 0xe5, 0xd0, 0xd7],
                    [0x35, 0x47, 0x96, 0x4e],
                    [0xf1, 0xfe, 0x37, 0xf1]
                ]
            }, State {
                data: [
                    [0x2d, 0x7e, 0x86, 0xa3],
                    [0x39, 0xd9, 0x39, 0x3e],
                    [0xe6, 0x57, 0x0a, 0x11],
                    [0x01, 0x90, 0x4e, 0x16]
                ]
            })
        ];

        for (state, expected_state) in test_cases.iter_mut() {
            state.inv_mix_columns();
            assert_eq!(&state, &expected_state);
        }
    }

    #[test]
    fn inv_shift_rows_test() {
        let mut state = State {
            data: [
                [0x7a, 0xd5, 0xfd, 0xa7],
                [0x89, 0xef, 0x4e, 0x27],
                [0x2b, 0xca, 0x10, 0x0b],
                [0x3d, 0x9f, 0xf5, 0x9f]
            ]
        };
        let expected_state = State {
            data: [
                [0x7a, 0x9f, 0x10, 0x27],
                [0x89, 0xd5, 0xf5, 0x0b],
                [0x2b, 0xef, 0xfd, 0x9f],
                [0x3d, 0xca, 0x4e, 0xa7]
            ]
        };

        state.inv_shift_rows();

        assert_eq!(state, expected_state);
    }

    #[test]
    fn inv_sub_bytes_test() {
        let mut state = State {
            data: [
                [0x7a, 0x9f, 0x10, 0x27],
                [0x89, 0xd5, 0xf5, 0x0b],
                [0x2b, 0xef, 0xfd, 0x9f],
                [0x3d, 0xca, 0x4e, 0xa7]
            ]
        };
        let expected_state = State {
            data: [
                [0xbd, 0x6e, 0x7c, 0x3d],
                [0xf2, 0xb5, 0x77, 0x9e],
                [0x0b, 0x61, 0x21, 0x6e],
                [0x8b, 0x10, 0xb6, 0x89]
            ]
        };

        state.inv_sub_bytes();

        assert_eq!(state, expected_state);
    }
}