pub fn fixed_key_xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(input.len());

    for (i, item) in input.iter().enumerate() {
        result.push(item ^ key[i % key.len()]);
    }

    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(false, true, "TODO: Write tests for xor module");
    }
}