//! The provider rules of [`super::detect`]: a known provider's key, read at a
//! token's start and at each later offset inside it.

/// How a key body is read: from the token's start, by each provider's own
/// length rule over token bytes; inside a token, over a fixed length.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Body {
    Token,
    Embedded,
}

/// The bytes an AWS access key id is read over, its prefix included.
pub const ACCESS_KEY_ID_LEN: usize = 20;

/// How a provider rule reads the bytes from its prefix on.
pub enum KeyShape {
    /// An AWS access key id: its first [`ACCESS_KEY_ID_LEN`] bytes are
    /// upper-case letters and digits, at a token's start or inside one.
    AccessKeyId,
    /// [`key_matches`]'s rule, with its body length and byte rules.
    Suffix {
        suffix_len: usize,
        exact_len: bool,
        alphanumeric: bool,
    },
}

/// One provider rule: `prefix`, then `suffix_len` body bytes (`exact_len`:
/// only those are read). Inside a token the body is always read over exactly
/// `suffix_len` bytes, alphanumeric ones when the provider's keys are, and
/// holds a digit or capital.
pub fn key_matches(
    token: &str,
    prefix: &str,
    suffix_len: usize,
    exact_len: bool,
    alphanumeric: bool,
    body: Body,
) -> bool {
    match body {
        Body::Token => suffix_matches(token, prefix, suffix_len, exact_len, is_ascii_token_body),
        Body::Embedded => {
            let allowed: fn(u8) -> bool = if alphanumeric {
                |byte: u8| byte.is_ascii_alphanumeric()
            } else {
                is_ascii_token_body
            };
            suffix_matches(token, prefix, suffix_len, true, allowed)
                && token.as_bytes()[prefix.len()..prefix.len() + suffix_len]
                    .iter()
                    .any(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
        }
    }
}

fn suffix_matches(
    token: &str,
    prefix: &str,
    suffix_len: usize,
    exact_len: bool,
    allowed: fn(u8) -> bool,
) -> bool {
    let token = token.as_bytes();
    let prefix = prefix.as_bytes();
    if prefix.is_empty() || token.len() < prefix.len() + suffix_len {
        return false;
    }

    if !token.starts_with(prefix) {
        return false;
    }
    let suffix_start = prefix.len();
    let min_suffix_end = suffix_start + suffix_len;
    let suffix = if exact_len {
        &token[suffix_start..min_suffix_end]
    } else {
        &token[suffix_start..]
    };
    suffix.iter().copied().all(allowed)
}

fn is_ascii_token_body(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}
