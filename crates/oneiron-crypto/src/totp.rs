//! RFC 6238's authenticator-app profile: HMAC-SHA1, six digits and
//! 30-second steps. The caller owns enrollment and replay consumption.

use hmac_sha1::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroize;

/// Decimal digits in the interoperable authenticator-app profile.
pub const TOTP_DIGITS: usize = 6;
/// RFC 6238's default time step, in Unix seconds (T0 = 0).
pub const TOTP_PERIOD_SECS: u64 = 30;
/// Adjacent steps accepted for authenticator clock drift.
pub const TOTP_DRIFT_STEPS: u64 = 1;
const DECIMAL_MODULUS: u32 = 1_000_000;

/// The six-digit code an authenticator app shows at `unix_secs` for a
/// provisioning secret in RFC 4648 base32, upper case and unpadded, as an
/// enrollment hands it out: the device side of [`matching_totp_step`], for
/// tests and tools that play the authenticator. `None` for a secret that is
/// not such base32.
pub fn totp_code_for_secret(base32_secret: &str, unix_secs: u64) -> Option<String> {
    let mut seed = Vec::with_capacity(base32_secret.len() * 5 / 8);
    let mut bits = 0u32;
    let mut available = 0u32;
    for symbol in base32_secret.bytes() {
        let value = match symbol {
            b'A'..=b'Z' => symbol - b'A',
            b'2'..=b'7' => symbol - b'2' + 26,
            _ => return None,
        };
        bits = (bits << 5) | u32::from(value);
        available += 5;
        if available >= 8 {
            available -= 8;
            seed.push(((bits >> available) & 0xff) as u8);
        }
    }
    let mut mac = Hmac::<Sha1>::new_from_slice(&seed).ok()?;
    mac.update(&(unix_secs / TOTP_PERIOD_SECS).to_be_bytes());
    let mut tag = mac.finalize().into_bytes();
    let offset = usize::from(tag[19] & 0x0f);
    let binary = u32::from_be_bytes([
        tag[offset] & 0x7f,
        tag[offset + 1],
        tag[offset + 2],
        tag[offset + 3],
    ]);
    tag.as_mut_slice().zeroize();
    seed.zeroize();
    bits.zeroize();
    Some(format!(
        "{:0width$}",
        binary % DECIMAL_MODULUS,
        width = TOTP_DIGITS
    ))
}

/// The newest step whose code matches, or none. `unix_secs` is real Unix
/// time, not the authority observation clock. No replay state lives here:
/// the caller consumes this exact returned step in its authority writer.
pub fn matching_totp_step(seed: &[u8], code: &str, unix_secs: u64) -> Option<u64> {
    if code.len() != TOTP_DIGITS || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let current = unix_secs / TOTP_PERIOD_SECS;
    let mut matched = None;
    for step in current.saturating_sub(TOTP_DRIFT_STEPS)..=current.saturating_add(TOTP_DRIFT_STEPS)
    {
        let mut mac = Hmac::<Sha1>::new_from_slice(seed).ok()?;
        mac.update(&step.to_be_bytes());
        let mut tag = mac.finalize().into_bytes();
        let offset = usize::from(tag[19] & 0x0f);
        let binary = u32::from_be_bytes([
            tag[offset] & 0x7f,
            tag[offset + 1],
            tag[offset + 2],
            tag[offset + 3],
        ]);
        let mut value = binary % DECIMAL_MODULUS;
        let mut digits = [b'0'; TOTP_DIGITS];
        for digit in digits.iter_mut().rev() {
            *digit += (value % 10) as u8;
            value /= 10;
        }
        let difference = digits
            .iter()
            .zip(code.bytes())
            .fold(0u8, |diff, (a, b)| diff | (*a ^ b));
        tag.as_mut_slice().zeroize();
        digits.zeroize();
        if difference == 0 {
            matched = Some(step);
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::{matching_totp_step, totp_code_for_secret};

    /// RFC 6238 appendix B's SHA-1 seed, "12345678901234567890", in base32.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn the_authenticator_side_shows_rfc_6238_codes() {
        // Appendix B's eight-digit values, cut to the profile's six digits.
        for (unix_secs, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ] {
            assert_eq!(
                totp_code_for_secret(RFC_SECRET, unix_secs).as_deref(),
                Some(code)
            );
            assert_eq!(
                matching_totp_step(b"12345678901234567890", code, unix_secs),
                Some(unix_secs / super::TOTP_PERIOD_SECS)
            );
        }
        assert_eq!(totp_code_for_secret("not base32!", 59), None);
    }
}
