#[derive(PartialEq, Debug)]
pub enum Padding {
    PKCS7,
    None,
}

/// Pads bytes to block_size using pkcs7 padding
///
/// See: https://tools.ietf.org/html/rfc5652#section-6.3
pub fn pkcs7_pad(bytes: &[u8], block_size: u8) -> Vec<u8> {
    let mut pad_length = block_size - (bytes.len() as u8 % block_size);

    if pad_length == 0 {
        pad_length = block_size;
    }

    [&bytes[..], &vec![pad_length; pad_length as usize][..]].concat()
}

#[cfg(test)]
mod tests {
    use pad::pkcs7_pad;

    #[test]
    fn pads_empty_bytes() {
        let empty = &[];
        let block_size = 16;

        let expected = &[16u8; 16];

        assert_eq!(expected.to_vec(), pkcs7_pad(empty, block_size));
    }

    #[test]
    fn pads_to_length() {
        let some_bytes = &[12; 12];
        let block_size = 16;

        let expected = &[
            12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
            4, 4, 4, 4
        ];

        assert_eq!(expected.to_vec(), pkcs7_pad(some_bytes, block_size));
    }

    #[test]
    fn ads_complete_padding_block_when_is_already_at_length() {
        let full_bytes = &[16; 16];
        let block_size = 16;

        let expected = &[16; 16 * 2];

        assert_eq!(expected.to_vec(), pkcs7_pad(full_bytes, block_size));
    }
}