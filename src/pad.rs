use pad::Error::{InvalidLastPaddingByte, InconsistentPadding};

/// see https://tools.ietf.org/html/rfc5652#section-6.3
pub fn pkcs7_pad(bytes: &[u8], block_size: u8) -> Vec<u8> {
    let mut pad_length = block_size - (bytes.len() as u8 % block_size);

    if pad_length == 0 {
        pad_length = block_size;
    }

    [&bytes[..], &vec![pad_length; pad_length as usize][..]].concat()
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InconsistentPadding,
    InvalidLastPaddingByte,
}

pub fn validate_pkcs7_pad(bytes: &[u8], block_size: u8) -> Result<(), Error> {
    assert!(bytes.len() >= 2);
    assert!(block_size >= 2);

    let padding_length = *bytes.last().unwrap();

    if padding_length == 0
        || padding_length > block_size
        || padding_length as usize > bytes.len() {
        return Err(InvalidLastPaddingByte);
    }

    let last_block = bytes.len() - padding_length as usize..;
    let pad = &bytes[last_block];

    match pad.iter().all(|byte| *byte == padding_length) {
        true => Ok(()),
        false => Err(InconsistentPadding)
    }
}

pub fn remove_pkcs7_padding(bytes: &[u8]) -> Vec<u8> {
    let pad = *bytes.last().unwrap();

    bytes[..bytes.len() - pad as usize].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_pkcs7_pad_test() {
        let block_size = 16;
        let block = &vec![
            13, 3, 206, 79, 0, 46, 143, 222,
            214, 77, 158, 253, 203, 223, 251, 60
        ];
        let pad = &vec![block_size as u8; block_size];

        let padded_block = &[
            &block[..],
            &pad[..]
        ].concat();

        assert!(validate_pkcs7_pad(padded_block, block_size as u8).is_ok());
    }
}