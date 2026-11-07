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
