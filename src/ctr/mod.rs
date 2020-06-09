use Nonce;

/// Generates a byte stream of the form:
/// Nonce + {C} + Nonce + {C+1} + Nonce + {C+2}... etc. where C is a 8 byte counter
/// Source:
/// https://web.archive.org/web/20150226072817/http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ctr/ctr-spec.pdf
pub fn generate_ctr_byte_stream_for_length(length: usize, nonce: &Nonce) -> Vec<u8> {
    let block_size = 16;
    let mut counter = 0u8;
    let byte_stream_length_padding = if length % block_size != 0 {
        block_size - (length % block_size)
    } else {
        0
    };

    (0..length + byte_stream_length_padding).collect::<Vec<usize>>()
        .iter()
        .enumerate()
        .map(|(i, _)|
            if (i % block_size) < nonce.len() {
                nonce[i % block_size]
            } else if block_size - (i % block_size) == 1 {
                counter += if counter < 0xff { 1 } else { 0 };

                counter
            } else {
                0u8
            }
        )
        .collect::<Vec<u8>>()
}

#[cfg(test)]
mod tests {
    use std::u16;
    use std::u32;

    use super::*;

    #[test]
    fn generate_ctr_bytes_for_length_test() {
        struct TestCase {
            length: usize,
            nonce: [u8; 8],
            expected: Vec<u8>,
        }

        let test_cases: Vec<TestCase> = vec![
            TestCase {
                length: 0,
                nonce: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                expected: Vec::new(),
            },
            TestCase {
                length: 16,
                nonce: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                expected: vec![
                    &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
                    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01][..]
                ].concat(),
            },
            TestCase {
                length: 17,
                nonce: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                expected: vec![
                    &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
                    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01][..],
                    &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
                    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02][..],
                ].concat(),
            }
        ];

        for test_case in test_cases.iter() {
            let generated_bytes = generate_ctr_byte_stream_for_length(
                test_case.length,
                &test_case.nonce);

            assert_eq!(generated_bytes, test_case.expected);
        }
    }

    #[test]
    fn generates_ctr_bytes_for_counter_up_to_1_byte() {
        let max_length = u16::MAX as usize;
        let nonce = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

        let generated_bytes = generate_ctr_byte_stream_for_length(
            max_length,
            &nonce,
        );

        let expected = vec![
            &nonce[..],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff][..]
        ].concat();

        assert_eq!(generated_bytes[generated_bytes.len() - 16..], expected[..]);
    }
}