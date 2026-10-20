// SPDX-License-Identifier: MIT
//! TOTP (RFC 6238) on top of HOTP (RFC 4226): code generation, verification, base32 secrets and
//! the `otpauth://` URI.
//!
//! Ported from GoTOTP (https://github.com/MrTuNNe/GoTOTP, MIT, by the same owner). Changes: SHA1
//! is the default (authenticator apps ignore the algorithm parameter), the code is compared in
//! constant time, a window of one step either side is accepted, a step that was already used is
//! refused, the secret is 160 bits, secrets under 128 bits are refused, and no input can make it
//! panic.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

/// Seconds per time step.
pub const PERIOD: u64 = 30;
/// Digits of a code.
pub const DIGITS: usize = 6;
/// Bytes of a new secret (160 bits, the size RFC 4226 recommends).
pub const SECRET_LEN: usize = 20;
/// Fewest bytes a secret may have (128 bits). RFC 4226 section 4 requires at least 128 bits;
/// shorter secrets are refused rather than checked.
pub const MIN_SECRET_LEN: usize = 16;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    /// The name used in the `otpauth://` URI.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The secret is shorter than [`MIN_SECRET_LEN`] or not valid base32.
    BadSecret,
    /// The code is not exactly six ASCII digits.
    BadCode,
    /// The code does not match the current step or its neighbours.
    WrongCode,
    /// The code matches only a step that was already used.
    Reused,
    /// The OS random number generator failed.
    Random,
    /// The issuer or the user name is empty.
    BadLabel,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::BadSecret => "the secret is too short or not valid base32",
            Error::BadCode => "the code is not exactly six digits",
            Error::WrongCode => "the code is wrong",
            Error::Reused => "the code was already used",
            Error::Random => "the system random number generator failed",
            Error::BadLabel => "the issuer and the user name must not be empty",
        })
    }
}

impl std::error::Error for Error {}

/// A new random secret of [`SECRET_LEN`] bytes from the OS random number generator.
pub fn generate_secret() -> Result<[u8; SECRET_LEN], Error> {
    let mut secret = [0u8; SECRET_LEN];
    getrandom::fill(&mut secret).map_err(|_| Error::Random)?;
    Ok(secret)
}

/// Base32 (RFC 4648) without padding.
pub fn encode_secret(secret: &[u8]) -> String {
    let mut out = String::with_capacity(secret.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0);
    for &byte in secret {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[((buffer >> bits) & 31) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Decodes base32, ignoring case and any trailing `=` padding. Leftover bits of a last partial
/// character are dropped, as authenticator apps do. A result shorter than [`MIN_SECRET_LEN`] is
/// refused.
pub fn decode_secret(text: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.trim_end_matches('=').bytes() {
        let value = match c.to_ascii_uppercase() {
            letter @ b'A'..=b'Z' => letter - b'A',
            digit @ b'2'..=b'7' => digit - b'2' + 26,
            _ => return Err(Error::BadSecret),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    check_secret(&out)?;
    Ok(out)
}

fn check_secret(secret: &[u8]) -> Result<(), Error> {
    if secret.len() < MIN_SECRET_LEN {
        Err(Error::BadSecret)
    } else {
        Ok(())
    }
}

/// RFC 4226 HOTP value with dynamic truncation, `digits` digits (at most 9).
fn hotp(secret: &[u8], algorithm: Algorithm, counter: u64, digits: u32) -> String {
    let message = counter.to_be_bytes();
    // HMAC accepts keys of any length, so `new_from_slice` cannot fail.
    let digest = match algorithm {
        Algorithm::Sha1 => mac_bytes::<Hmac<Sha1>>(secret, &message),
        Algorithm::Sha256 => mac_bytes::<Hmac<Sha256>>(secret, &message),
        Algorithm::Sha512 => mac_bytes::<Hmac<Sha512>>(secret, &message),
    };
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let truncated = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    format!(
        "{:0width$}",
        truncated % 10u32.pow(digits),
        width = digits as usize
    )
}

fn mac_bytes<M: Mac + hmac::digest::KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
    // Generic only to share this body between the three hash functions.
    let mut mac = <M as Mac>::new_from_slice(key).expect("HMAC takes keys of any length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// The code for the time step that contains `now` (seconds since the Unix epoch).
pub fn code(secret: &[u8], algorithm: Algorithm, now: u64) -> Result<String, Error> {
    check_secret(secret)?;
    Ok(hotp(secret, algorithm, now / PERIOD, DIGITS as u32))
}

/// Checks `input` against the step of `now` and the steps just before and after it, and returns
/// the step that matched. A step at or below `last_used_step` is refused, so a code works once.
/// The caller must store the returned step before it lets the user in.
pub fn verify(
    secret: &[u8],
    algorithm: Algorithm,
    input: &str,
    now: u64,
    last_used_step: Option<u64>,
) -> Result<u64, Error> {
    check_secret(secret)?;
    if input.len() != DIGITS || !input.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::BadCode);
    }
    let current = now / PERIOD;
    let mut accepted = None;
    let mut reused = false;
    // Every candidate is compared, whether or not an earlier one matched.
    for step in current.saturating_sub(1)..=current.saturating_add(1) {
        let expected = hotp(secret, algorithm, step, DIGITS as u32);
        if bool::from(expected.as_bytes().ct_eq(input.as_bytes())) {
            if last_used_step.is_some_and(|last| step <= last) {
                reused = true;
            } else {
                accepted = Some(step);
            }
        }
    }
    match (accepted, reused) {
        (Some(step), _) => Ok(step),
        (None, true) => Err(Error::Reused),
        (None, false) => Err(Error::WrongCode),
    }
}

/// The `otpauth://totp` URI that authenticator apps read from a QR code.
pub fn otpauth_uri(
    secret: &[u8],
    algorithm: Algorithm,
    issuer: &str,
    user: &str,
) -> Result<String, Error> {
    if issuer.is_empty() || user.is_empty() {
        return Err(Error::BadLabel);
    }
    if secret.is_empty() {
        return Err(Error::BadSecret);
    }
    let (issuer, user) = (percent_encode(issuer), percent_encode(user));
    Ok(format!(
        "otpauth://totp/{issuer}:{user}?secret={}&issuer={issuer}&algorithm={}&digits={DIGITS}\
         &period={PERIOD}",
        encode_secret(secret),
        algorithm.name(),
    ))
}

/// Percent-encodes everything but the RFC 3986 unreserved characters.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // GoTOTP's test key (a 32-byte secret).
    const GO_KEY: &str = "OK6ZZOALZY6RNZBPM4QKD2ZFO5F3PTP56VIAXLDJLEHBPLJJIZNQ";
    const GO_TIME: u64 = 1723719527;

    fn go_secret() -> Vec<u8> {
        decode_secret(GO_KEY).unwrap()
    }

    // RFC 6238 appendix B: the seed is the ASCII string repeated to the hash's block size.
    const SHA1_SEED: &[u8] = b"12345678901234567890";
    const SHA256_SEED: &[u8] = b"12345678901234567890123456789012";
    const SHA512_SEED: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    // (time, SHA1, SHA256, SHA512), the 8-digit codes of the RFC.
    const RFC_VECTORS: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn rfc6238_vectors_eight_digits() {
        for (time, sha1, sha256, sha512) in RFC_VECTORS {
            let step = time / PERIOD;
            assert_eq!(
                hotp(SHA1_SEED, Algorithm::Sha1, step, 8),
                sha1,
                "SHA1 {time}"
            );
            assert_eq!(
                hotp(SHA256_SEED, Algorithm::Sha256, step, 8),
                sha256,
                "SHA256 {time}"
            );
            assert_eq!(
                hotp(SHA512_SEED, Algorithm::Sha512, step, 8),
                sha512,
                "SHA512 {time}"
            );
        }
    }

    #[test]
    fn rfc6238_vectors_six_digits() {
        for (time, sha1, sha256, sha512) in RFC_VECTORS {
            assert_eq!(
                code(SHA1_SEED, Algorithm::Sha1, time).unwrap(),
                sha1[2..],
                "SHA1 {time}"
            );
            assert_eq!(
                code(SHA256_SEED, Algorithm::Sha256, time).unwrap(),
                sha256[2..],
                "SHA256 {time}"
            );
            assert_eq!(
                code(SHA512_SEED, Algorithm::Sha512, time).unwrap(),
                sha512[2..],
                "SHA512 {time}"
            );
        }
    }

    #[test]
    fn rfc4226_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(hotp(SHA1_SEED, Algorithm::Sha1, counter as u64, 6), *want);
        }
    }

    #[test]
    fn default_algorithm_is_sha1() {
        assert_eq!(Algorithm::default(), Algorithm::Sha1);
    }

    #[test]
    fn gotp_codes() {
        let secret = go_secret();
        assert_eq!(code(&secret, Algorithm::Sha256, GO_TIME).unwrap(), "611626");
        assert_eq!(code(&secret, Algorithm::Sha1, GO_TIME).unwrap(), "032332");
        assert_eq!(code(&secret, Algorithm::Sha512, GO_TIME).unwrap(), "319711");
    }

    #[test]
    fn gotp_verify_and_expiry() {
        let secret = go_secret();
        let ok = |alg, input, now| verify(&secret, alg, input, now, None).is_ok();
        assert!(ok(Algorithm::Sha256, "611626", GO_TIME));
        assert!(ok(Algorithm::Sha1, "032332", GO_TIME));
        assert!(ok(Algorithm::Sha512, "319711", GO_TIME));
        // 53 s later the step is two ahead: out of the window.
        assert!(!ok(Algorithm::Sha256, "611626", 1723719580));
        assert!(!ok(Algorithm::Sha1, "032332", 1723719580));
        assert!(!ok(Algorithm::Sha512, "319711", 1723719580));
        // A code of another algorithm is refused.
        assert!(!ok(Algorithm::Sha1, "611626", GO_TIME));
        assert!(!ok(Algorithm::Sha512, "611626", GO_TIME));
        // An old code is refused now.
        assert!(!ok(Algorithm::Sha256, "149425", 1_800_000_000));
    }

    #[test]
    fn algorithms_give_distinct_codes() {
        let secret = go_secret();
        let codes = [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512]
            .map(|alg| code(&secret, alg, GO_TIME).unwrap());
        assert!(codes[0] != codes[1] && codes[1] != codes[2] && codes[0] != codes[2]);
    }

    #[test]
    fn random_secret_works() {
        let secret = generate_secret().unwrap();
        assert_eq!(secret.len(), 20);
        assert_ne!(secret, generate_secret().unwrap());
        let text = encode_secret(&secret);
        assert_eq!(text.len(), 32);
        assert_eq!(decode_secret(&text).unwrap(), secret);
        assert_eq!(code(&secret, Algorithm::Sha1, GO_TIME).unwrap().len(), 6);
    }

    #[test]
    fn short_secrets_are_refused() {
        let short = [0x42u8; MIN_SECRET_LEN - 1];
        assert_eq!(code(&[], Algorithm::Sha1, GO_TIME), Err(Error::BadSecret));
        assert_eq!(
            code(&short, Algorithm::Sha1, GO_TIME),
            Err(Error::BadSecret)
        );
        assert_eq!(
            verify(&[], Algorithm::Sha1, "000000", GO_TIME, None),
            Err(Error::BadSecret)
        );
        assert_eq!(
            verify(&short, Algorithm::Sha1, "000000", GO_TIME, None),
            Err(Error::BadSecret)
        );
    }

    #[test]
    fn minimum_length_secret_is_accepted() {
        let secret = [0x42u8; MIN_SECRET_LEN];
        let input = code(&secret, Algorithm::Sha1, GO_TIME).unwrap();
        assert_eq!(
            verify(&secret, Algorithm::Sha1, &input, GO_TIME, None),
            Ok(GO_TIME / PERIOD)
        );
    }

    #[test]
    fn verify_window_edges() {
        let secret = SHA1_SEED;
        let now = 1_000_000_000u64;
        let step = now / PERIOD;
        let at = |s: u64| code(secret, Algorithm::Sha1, s * PERIOD).unwrap();
        let check = |s: u64| verify(secret, Algorithm::Sha1, &at(s), now, None);
        assert_eq!(check(step), Ok(step));
        assert_eq!(check(step - 1), Ok(step - 1));
        assert_eq!(check(step + 1), Ok(step + 1));
        assert_eq!(check(step - 2), Err(Error::WrongCode));
        assert_eq!(check(step + 2), Err(Error::WrongCode));
    }

    #[test]
    fn verify_window_at_time_zero_and_max() {
        let secret = SHA1_SEED;
        for now in [0, 29, u64::MAX] {
            let wanted = code(secret, Algorithm::Sha1, now).unwrap();
            assert_eq!(
                verify(secret, Algorithm::Sha1, &wanted, now, None),
                Ok(now / PERIOD)
            );
        }
    }

    #[test]
    fn verify_refuses_reuse() {
        let secret = SHA1_SEED;
        let now = 1_000_000_000u64;
        let step = now / PERIOD;
        let input = code(secret, Algorithm::Sha1, now).unwrap();
        let used = verify(secret, Algorithm::Sha1, &input, now, None).unwrap();
        assert_eq!(
            verify(secret, Algorithm::Sha1, &input, now, Some(used)),
            Err(Error::Reused)
        );
        // Still refused when the clock moves on within the window.
        assert_eq!(
            verify(secret, Algorithm::Sha1, &input, now + PERIOD, Some(used)),
            Err(Error::Reused)
        );
        // An older step than the last used one is refused too.
        let older = code(secret, Algorithm::Sha1, now - PERIOD).unwrap();
        assert_eq!(
            verify(secret, Algorithm::Sha1, &older, now, Some(step)),
            Err(Error::Reused)
        );
        // A newer step is accepted.
        let newer = code(secret, Algorithm::Sha1, now + PERIOD).unwrap();
        assert_eq!(
            verify(secret, Algorithm::Sha1, &newer, now, Some(step)),
            Ok(step + 1)
        );
    }

    #[test]
    fn verify_refuses_malformed_codes() {
        let secret = SHA1_SEED;
        let good = code(secret, Algorithm::Sha1, 59).unwrap();
        let bad = [
            "",
            "1",
            "12345",
            "1234567",
            " 94287",
            "94287 ",
            "94287\n",
            "+94287",
            "-94287",
            "9428a7",
            "９４２８７０",
            "٩٤٢٨٧٠",
            "94287\0",
        ];
        for input in bad {
            assert_eq!(
                verify(secret, Algorithm::Sha1, input, 59, None),
                Err(Error::BadCode),
                "{input:?}"
            );
        }
        let spaced = format!("{} {}", &good[..3], &good[3..]);
        assert_eq!(
            verify(secret, Algorithm::Sha1, &spaced, 59, None),
            Err(Error::BadCode)
        );
        assert_eq!(verify(secret, Algorithm::Sha1, &good, 59, None), Ok(1));
    }

    #[test]
    fn code_keeps_leading_zeros() {
        // The RFC 4226 vector at time 1111111109 starts with a zero.
        assert_eq!(
            code(SHA1_SEED, Algorithm::Sha1, 1111111109).unwrap(),
            "081804"
        );
    }

    #[test]
    fn base32_known_values() {
        // RFC 4648 section 10, without padding.
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
            assert_eq!(encode_secret(plain.as_bytes()), encoded);
        }
    }

    #[test]
    fn decode_refuses_short_secrets() {
        assert_eq!(decode_secret(""), Err(Error::BadSecret));
        assert_eq!(decode_secret("===="), Err(Error::BadSecret));
        assert_eq!(
            decode_secret(&encode_secret(&[0x42; 15])),
            Err(Error::BadSecret)
        );
        assert_eq!(
            decode_secret(&encode_secret(&[0x42; 16])).unwrap(),
            [0x42; 16]
        );
    }

    #[test]
    fn base32_decoding_is_tolerant_of_case_and_padding() {
        let secret = go_secret();
        assert_eq!(decode_secret(&GO_KEY.to_lowercase()).unwrap(), secret);
        assert_eq!(decode_secret(&format!("{GO_KEY}====")).unwrap(), secret);
        assert_eq!(
            decode_secret(&format!("{}==", GO_KEY.to_lowercase())).unwrap(),
            secret
        );
    }

    #[test]
    fn base32_decoding_refuses_bad_input() {
        for suffix in ["1", "8", " ", "\n", "\0", "é", "=A"] {
            let text = format!("{GO_KEY}{suffix}");
            assert_eq!(decode_secret(&text), Err(Error::BadSecret), "{text:?}");
        }
    }

    #[test]
    fn base32_round_trips() {
        for len in MIN_SECRET_LEN..=64usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let text = encode_secret(&data);
            assert!(!text.contains('='));
            assert_eq!(decode_secret(&text).unwrap(), data);
        }
        assert_eq!(
            decode_secret(GO_KEY).map(|s| encode_secret(&s)),
            Ok(GO_KEY.to_string())
        );
    }

    #[test]
    fn uri_has_all_parameters() {
        let uri = otpauth_uri(
            SHA1_SEED,
            Algorithm::Sha1,
            "mrtunne.info",
            "admin@admin.test",
        );
        assert_eq!(
            uri.unwrap(),
            "otpauth://totp/mrtunne.info:admin%40admin.test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
             &issuer=mrtunne.info&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn uri_percent_encodes_label_and_issuer() {
        let uri = otpauth_uri(SHA1_SEED, Algorithm::Sha256, "My Co&x:y", "a b/ü?#=").unwrap();
        assert!(uri.starts_with("otpauth://totp/My%20Co%26x%3Ay:a%20b%2F%C3%BC%3F%23%3D?"));
        assert!(uri.contains("&issuer=My%20Co%26x%3Ay&algorithm=SHA256&"));
        assert_eq!(uri.matches('?').count(), 1);
        assert_eq!(uri.matches('#').count(), 0);
    }

    #[test]
    fn uri_refuses_empty_parts() {
        let uri = |secret: &[u8], issuer, user| otpauth_uri(secret, Algorithm::Sha1, issuer, user);
        assert_eq!(uri(SHA1_SEED, "", "user"), Err(Error::BadLabel));
        assert_eq!(uri(SHA1_SEED, "Issuer", ""), Err(Error::BadLabel));
        assert_eq!(uri(b"", "Issuer", "user"), Err(Error::BadSecret));
    }
}
