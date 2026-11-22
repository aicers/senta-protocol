//! Unpadded, canonical base64url, the only encoding JWS and signed contents
//! use for bytes.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Decodes unpadded base64url, rejecting padding, characters outside the
/// URL-safe alphabet (`+`, `/`, whitespace and the like) and non-canonical
/// encodings whose unused trailing bits are not zero.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    // `URL_SAFE_NO_PAD` requires the absence of padding and, by default,
    // rejects non-zero trailing bits; both are asserted by the tests below.
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// Decodes unpadded base64url into exactly `N` bytes.
pub(crate) fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    decode(text)?.try_into().ok()
}

/// Encodes bytes as unpadded base64url.
pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for len in 0..10 {
            let bytes: Vec<u8> = (0..len).map(|i: u8| i.wrapping_mul(37)).collect();
            assert_eq!(decode(&encode(&bytes)), Some(bytes));
        }
    }

    #[test]
    fn rejects_padding() {
        assert_eq!(decode("YQ"), Some(b"a".to_vec()));
        assert_eq!(decode("YQ=="), None);
        assert_eq!(decode("YWI="), None);
    }

    #[test]
    fn rejects_standard_alphabet() {
        // 0xfb 0xff encodes as `-_8` in base64url and `+/8` in base64.
        assert_eq!(decode("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(decode("+/8"), None);
    }

    #[test]
    fn rejects_non_canonical_trailing_bits() {
        // `YQ` is canonical for "a"; `YR` carries the same byte with a
        // non-zero unused bit.
        assert_eq!(decode("YR"), None);
    }

    #[test]
    fn rejects_whitespace_and_impossible_lengths() {
        assert_eq!(decode("Y Q"), None);
        assert_eq!(decode("YQ\n"), None);
        assert_eq!(decode("Y"), None);
    }

    #[test]
    fn decodes_fixed_length() {
        assert_eq!(decode_array::<1>("YQ"), Some(*b"a"));
        assert_eq!(decode_array::<2>("YQ"), None);
    }
}
