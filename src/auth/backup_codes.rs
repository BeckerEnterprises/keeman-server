//! Backup codes of the second factor: 10 codes of 10 Base32
//! characters, stored as Argon2id hashes and usable once.

use crate::crypto::base32::ALPHABET;
use crate::crypto::random_bytes;

pub const COUNT: usize = 10;
pub const LENGTH: usize = 10;

/// Ten new codes: one random byte per character, its lower five bits
/// select the character (uniform, because 256 is a multiple of 32).
pub fn generate() -> Result<Vec<String>, getrandom::Error> {
    (0..COUNT)
        .map(|_| {
            let bytes = random_bytes::<LENGTH>()?;
            Ok(bytes
                .iter()
                .map(|b| char::from(ALPHABET[usize::from(b & 31)]))
                .collect())
        })
        .collect()
}

/// The code as hashed: spaces and hyphens removed, `a`–`z` upper-cased;
/// `None` unless exactly 10 Base32 characters remain.
pub fn normalize(input: &str) -> Option<String> {
    let code: String = input
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (code.len() == LENGTH && code.bytes().all(|b| ALPHABET.contains(&b))).then_some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_ten_distinct_codes() {
        let codes = generate().unwrap();
        assert_eq!(codes.len(), COUNT);
        for code in &codes {
            assert_eq!(normalize(code).as_deref(), Some(code.as_str()));
        }
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), COUNT);
    }

    #[test]
    fn normalises_input() {
        assert_eq!(normalize("abcde-fghij").as_deref(), Some("ABCDEFGHIJ"));
        assert_eq!(normalize(" ABCDE FGHI7 ").as_deref(), Some("ABCDEFGHI7"));
        assert_eq!(normalize("ABCDEFGHI"), None);
        assert_eq!(normalize("ABCDEFGHIJK"), None);
        assert_eq!(normalize("ABCDEFGHI1"), None);
        assert_eq!(normalize("ABCDEFGHIß"), None);
        assert_eq!(normalize("ABCDE\tFGHIJ"), None);
    }
}
