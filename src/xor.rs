pub fn fixed_key_xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(input.len());

    for (i, item) in input.iter().enumerate() {
        let key_byte = if key.len() > 0 {
            key[i % key.len()]
        } else {
            0
        };
        result.push(item ^ key_byte);
    }

    result
}

#[cfg(test)]
mod tests {
    use xor::fixed_key_xor;

    #[test]
    fn rotates_xor_key() {
        struct TestCase<'a> {
            input: &'a [u8],
            key: &'a [u8],
            expected: &'a [u8],
        }
        let test_cases = vec![
            TestCase {
                input: &[0x01, 0x02, 0x03, 0x04, 0x05],
                key: &[0x01, 0x02, 0x03],
                expected: &[0x01 ^ 0x01, 0x02 ^ 0x02, 0x03 ^ 0x03, 0x04 ^ 0x01, 0x05 ^ 0x02],
            },
            TestCase {
                input: &[0xff, 0xfe, 0xfd, 0xfc],
                key: &[0x01, 0xff],
                expected: &[0xff ^ 0x01, 0xfe ^ 0xff, 0xfd ^ 0x01, 0xfc ^ 0xff],
            }
        ];

        for case in test_cases.iter() {
            let result = fixed_key_xor(&case.input, &case.key);
            assert_eq!(result, case.expected);
        }
    }

    #[test]
    fn given_single_byte_xors_with_byte() {
        struct TestCase<'a> {
            input: &'a [u8],
            key: &'a [u8],
            expected: &'a [u8],
        }
        let test_cases = vec![
            TestCase {
                input: &[0x01, 0x02, 0x03, 0x04],
                key: &[0x01],
                expected: &[0x01 ^ 0x01, 0x02 ^ 0x01, 0x03 ^ 0x01, 0x04 ^ 0x01],
            },
            TestCase {
                input: &[0xff, 0xfe, 0xfd, 0xfc],
                key: &[0x01],
                expected: &[0xff ^ 0x01, 0xfe ^ 0x01, 0xfd ^ 0x01, 0xfc ^ 0x01],
            }
        ];

        for case in test_cases.iter() {
            let result = fixed_key_xor(&case.input, &case.key);
            assert_eq!(result, case.expected);
        }
    }

    #[test]
    fn given_input_shorter_than_key_xors() {
        let input = &[0x01, 0xff];
        let key = &[0x01, 0x02, 0x03, 0x04];

        let expected = &[0x01 ^ 0x01, 0xff ^ 0x02];

        let result = fixed_key_xor(input, key);
        assert_eq!(result, expected);
    }

    #[test]
    fn given_empty_input_doesnt_xor() {
        let input = &[];
        let key = &[0x01, 0xff];

        let expected = &[];

        let result = fixed_key_xor(input, key);
        assert_eq!(result, expected);
    }

    #[test]
    fn given_empty_key_doesnt_xor() {
        let input = &[0x01, 0xff];
        let key = &[];

        let expected = &[0x01, 0xff];

        let result = fixed_key_xor(input, key);
        assert_eq!(result, expected);
    }
}