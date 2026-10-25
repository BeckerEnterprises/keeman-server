//! Account TOTP: RFC 6238 with HMAC-SHA1, 6 digits and 30 s.
//! `hotp` also supports SHA-256/512 and up to 8 digits so the shared test
//! vectors can check it completely.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::{Choice, ConstantTimeEq};

use crate::crypto::base32;

pub const PERIOD: i64 = 30;
pub const DIGITS: u32 = 6;
/// Length of a new account TOTP secret in bytes.
pub const SECRET_BYTES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

fn mac<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let mut mac = <M as KeyInit>::new_from_slice(key).ok()?;
    mac.update(message);
    Some(mac.finalize().into_bytes().to_vec())
}

/// HOTP value (RFC 4226 §5.3) of `counter`, reduced to `digits` digits.
/// `None` only for unsupported digit counts.
pub fn hotp(algorithm: Algorithm, secret: &[u8], counter: u64, digits: u32) -> Option<u32> {
    if !(6..=8).contains(&digits) {
        return None;
    }
    let message = counter.to_be_bytes();
    let digest = match algorithm {
        Algorithm::Sha1 => mac::<Hmac<Sha1>>(secret, &message),
        Algorithm::Sha256 => mac::<Hmac<Sha256>>(secret, &message),
        Algorithm::Sha512 => mac::<Hmac<Sha512>>(secret, &message),
    }?;
    let offset = usize::from(digest.last()? & 0x0f);
    let bytes: [u8; 4] = digest.get(offset..offset + 4)?.try_into().ok()?;
    let value = u32::from_be_bytes(bytes) & 0x7fff_ffff;
    Some(value % 10u32.pow(digits))
}

/// Time step of a Unix time in seconds.
pub fn step(unix_seconds: i64) -> i64 {
    unix_seconds.div_euclid(PERIOD)
}

/// The 6-digit account code of a time step.
pub fn code(secret: &[u8], step: i64) -> Option<String> {
    let counter = u64::try_from(step).ok()?;
    let value = hotp(Algorithm::Sha1, secret, counter, DIGITS)?;
    Some(format!("{value:06}"))
}

/// Checks a 6-digit code against the steps T−1, T and T+1 that are newer than
/// `last_step` and returns the smallest matching step. All
/// candidates are computed and compared in constant time; the caller still
/// has to store the step conditionally to make the code single-use.
pub fn verify(
    secret: &[u8],
    input: &str,
    unix_seconds: i64,
    last_step: Option<i64>,
) -> Option<i64> {
    let now = step(unix_seconds);
    let mut found: Option<i64> = None;
    for candidate in [now - 1, now, now + 1] {
        let Some(expected) = code(secret, candidate) else {
            continue;
        };
        let matches: Choice = expected.as_bytes().ct_eq(input.as_bytes());
        let fresh = last_step.is_none_or(|last| candidate > last);
        if bool::from(matches) && fresh && found.is_none() {
            found = Some(candidate);
        }
    }
    found
}

/// Bytes of the e-mail address in the key URI: everything but RFC 3986
/// unreserved characters is percent-encoded with upper-case hex.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 3);
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `otpauth://totp/KeeMan:<email>?secret=…&issuer=KeeMan`.
pub fn otpauth_uri(email: &str, secret: &[u8]) -> String {
    format!(
        "otpauth://totp/KeeMan:{}?secret={}&issuer=KeeMan",
        percent_encode(email),
        base32::encode(secret)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"12345678901234567890";
    /// 2026-10-25T00:00:00Z, a multiple of 30 s.
    const NOW: i64 = 1_792_886_400;

    fn at(offset_steps: i64) -> String {
        code(SECRET, step(NOW) + offset_steps).unwrap()
    }

    #[test]
    fn rfc_6238_sha1_value() {
        // RFC 6238 appendix B: T = 59 → 94287082 with 8 digits.
        assert_eq!(hotp(Algorithm::Sha1, SECRET, 1, 8), Some(94_287_082));
        assert_eq!(code(SECRET, 1).unwrap(), "287082");
        assert_eq!(hotp(Algorithm::Sha1, SECRET, 1, 5), None);
        assert_eq!(hotp(Algorithm::Sha1, SECRET, 1, 9), None);
    }

    #[test]
    fn accepts_one_step_either_way() {
        for offset in [-1, 0, 1] {
            assert_eq!(
                verify(SECRET, &at(offset), NOW + 10, None),
                Some(step(NOW) + offset)
            );
        }
        for offset in [-2, 2] {
            assert_eq!(verify(SECRET, &at(offset), NOW + 10, None), None);
        }
        let window = [at(-1), at(0), at(1)];
        let wrong = (0..)
            .map(|n| format!("{n:06}"))
            .find(|c| !window.contains(c))
            .unwrap();
        assert_eq!(verify(SECRET, &wrong, NOW, None), None);
    }

    #[test]
    fn rejects_used_and_older_steps() {
        let now = step(NOW);
        assert_eq!(verify(SECRET, &at(0), NOW, Some(now)), None);
        assert_eq!(verify(SECRET, &at(-1), NOW, Some(now)), None);
        assert_eq!(verify(SECRET, &at(1), NOW, Some(now)), Some(now + 1));
        assert_eq!(verify(SECRET, &at(0), NOW, Some(now - 1)), Some(now));
    }

    #[test]
    fn steps_follow_the_period() {
        assert_eq!(step(0), 0);
        assert_eq!(step(29), 0);
        assert_eq!(step(30), 1);
        assert_eq!(step(-1), -1);
        assert_eq!(code(SECRET, -1), None);
    }

    #[test]
    fn key_uri_encodes_the_address() {
        assert_eq!(
            otpauth_uri("alice+x@example.com", &[0u8; 20]),
            "otpauth://totp/KeeMan:alice%2Bx%40example.com?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&issuer=KeeMan"
        );
        assert_eq!(percent_encode("jörg_~.-@ä"), "j%C3%B6rg_~.-%40%C3%A4");
    }
}
