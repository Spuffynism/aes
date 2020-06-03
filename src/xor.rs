pub fn fixed_xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(input.len(), key.len());

    fixed_key_xor(input, key)
}

pub fn single_byte_xor(input: &[u8], key: u8) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(input.len());

    for item in input.iter() {
        result.push(item ^ key);
    }

    result
}

pub fn fixed_key_xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(input.len());

    for (i, item) in input.iter().enumerate() {
        result.push(item ^ key[i % key.len()]);
    }

    result
}