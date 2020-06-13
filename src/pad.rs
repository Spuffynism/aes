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
    #[test]
    fn pkcs7_pads() {
        unimplemented!();
    }
}