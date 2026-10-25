//! Base32 of RFC 4648 without padding: the account TOTP secret
//! and the backup codes use its alphabet.

pub const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Strict decoding: upper-case alphabet only, no padding, and a length that
/// unpadded Base32 can have. The trailing pad bits are not checked.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    if matches!(text.len() % 8, 1 | 3 | 6) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in text.bytes() {
        let value = ALPHABET.iter().position(|&c| c == byte)?;
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_test_vectors() {
        // RFC 4648 §10 without the padding.
        let cases = [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn decoding_is_strict() {
        assert_eq!(decode("MZXW6==="), None);
        assert_eq!(decode("mzxw6"), None);
        assert_eq!(decode("MZXW1"), None);
        assert_eq!(decode("M"), None);
        assert_eq!(decode("MZX"), None);
        assert_eq!(decode("MZXW6Y"), None);
    }

    #[test]
    fn twenty_bytes_give_32_characters() {
        let text = encode(&[0xffu8; 20]);
        assert_eq!(text.len(), 32);
        assert_eq!(decode(&text).unwrap(), [0xffu8; 20]);
    }
}
