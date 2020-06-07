use S_BOX;

/// Function used in the Key Expansion routine that takes a four-byte
/// word and performs a cyclic permutation.
pub fn rot_word(word: &[u8]) -> Vec<u8> {
    assert_eq!(word.len(), 4);

    [&word[1..], &[word[0]]].concat()
}

/// Function used in the Key Expansion routine that takes a four-byte
/// input word and applies an S-box to each of the four bytes to
/// produce an output word.
pub fn sub_word(word: &[u8]) -> Vec<u8> {
    assert_eq!(word.len(), 4);

    word.iter().map(|word| S_BOX[*word as usize]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot_word_rotates_word() {
        let word: &[u8] = &[0, 1, 2, 3];
        let expected_word: &[u8] = &[1, 2, 3, 0];

        let actual_word = rot_word(word);
        assert_eq!(actual_word.as_slice(), expected_word);
    }

    #[test]
    fn sub_word_substitutes_word() {
        let word: &[u8] = &[0, 1, 2, 3];
        let expected_word: &[u8] = &[0x63, 0x7c, 0x77, 0x7b];

        let actual_word = sub_word(word);

        assert_eq!(actual_word.as_slice(), expected_word);
    }
}