//! The credential a spooled exchange carries: the one complete
//! `Authorization` value the daemon hands over once the broker holds the
//! body, installed by the broker alone.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::HeaderValue;
use zeroize::Zeroizing;

use crate::send::git_watchable;
use crate::{MAX_SECRET, Refusal};

/// The credential an exchange carries: the complete `Authorization` value,
/// marked sensitive, and the token in it the reply is watched for.
pub(crate) struct Credential {
    pub(crate) header: HeaderValue,
    pub(crate) watched: Zeroizing<Vec<u8>>,
}

/// Reads `secret` as one `Authorization` value, its outer whitespace
/// trimmed: visible ASCII and spaces, a scheme, then its credentials. The
/// token watched for is the credentials, or for `Basic` the password the
/// base64 holds (its user name when the password is empty or GitHub's
/// `x-oauth-basic`). Any token up to [`MAX_SECRET`] bytes goes
/// ([`git_watchable`]); the reply's echo watch searches its literal forms.
pub(crate) fn read_authorization(secret: &[u8]) -> Result<Credential, Refusal> {
    let value = secret.trim_ascii();
    if value.is_empty()
        || value.len() > MAX_SECRET
        || !value.iter().all(|byte| (0x20..0x7f).contains(byte))
    {
        return Err(Refusal::Secret);
    }
    let space = value
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(Refusal::Secret)?;
    let scheme = &value[..space];
    let credentials = value[space..].trim_ascii();
    if credentials.is_empty()
        || !scheme
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+".contains(byte))
    {
        return Err(Refusal::Secret);
    }
    let watched = if scheme.eq_ignore_ascii_case(b"basic") {
        let decoded = Zeroizing::new(STANDARD.decode(credentials).map_err(|_| Refusal::Secret)?);
        let colon = decoded
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(Refusal::Secret)?;
        let (user, password) = (&decoded[..colon], &decoded[colon + 1..]);
        let token = if password.is_empty() || password == b"x-oauth-basic" {
            user
        } else {
            password
        };
        Zeroizing::new(token.to_vec())
    } else {
        Zeroizing::new(credentials.to_vec())
    };
    if !git_watchable(&watched) {
        return Err(Refusal::Secret);
    }
    let mut header = HeaderValue::from_bytes(value).map_err(|_| Refusal::Secret)?;
    header.set_sensitive(true);
    Ok(Credential { header, watched })
}
