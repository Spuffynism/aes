/// Adapted from https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example
/// In the polynomial representation, multiplication in GF(2^8) (denoted by •) corresponds with the
/// multiplication of polynomials modulo an irreducible polynomial of degree 8. A polynomial is
/// irreducible if its only divisors are one and itself
pub fn multiply_in_g(polynomial_value: u8, state_value: u8) -> u8 {
    let irreducible_polynomial = 0x1b;
    let mut a = polynomial_value;
    let mut b = state_value;
    let mut p = 0;

    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }

        let hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= irreducible_polynomial;
        }
        b >>= 1;
    }

    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiply_in_g_test() {
        struct TestCase {
            a: u8,
            b: u8,
            expected: u8,
        }
        let test_cases: Vec<TestCase> = vec![
            TestCase { a: 0x57, b: 0x83, expected: 0xc1 },
            TestCase { a: 0x57, b: 0x13, expected: 0xfe },
            TestCase { a: 0x57, b: 0x02, expected: 0xae },
            TestCase { a: 0x57, b: 0x04, expected: 0x47 },
            TestCase { a: 0x57, b: 0x08, expected: 0x8e },
            TestCase { a: 0x57, b: 0x10, expected: 0x07 }
        ];

        for case in test_cases.iter() {
            let actual_result = multiply_in_g(case.a, case.b);
            assert_eq!(actual_result, case.expected);
        }
    }
}