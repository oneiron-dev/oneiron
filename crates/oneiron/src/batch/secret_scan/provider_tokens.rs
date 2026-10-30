//! The provider rules of [`super::detect`]: a known provider's key, read at a
//! token's start and at each later offset inside it.

use super::{
    REASON_AWS_ACCESS_KEY_ID, REASON_GITHUB_TOKEN, REASON_GOOGLE_API_KEY, REASON_OPENAI_KEY,
    REASON_SLACK_TOKEN, REASON_STRIPE_KEY, shapes,
};

/// Where [`super::detect`]'s provider rules read a key in `text`: each whole
/// token one names, with its reason.
pub(super) fn provider_token_spans(text: &str) -> Vec<(std::ops::Range<usize>, &'static str)> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')))
        .filter_map(|token| {
            classify_token(token).map(|reason| (shapes::span_of(text, token), reason))
        })
        .collect()
}

pub(super) fn classify_token(token: &str) -> Option<&'static str> {
    // A credential still counts after leading token bytes (`Xghp_…`), so every
    // later offset is a candidate start too (F23, H49/H66). There a key body
    // is read over its fixed length only, keeping the scan linear, a provider
    // whose real keys are alphanumeric must match as such, and the body must
    // hold a digit or capital, as a real key's random body does, so snake or
    // kebab prose (`highs_and_lows_…`, `risk_live_…`, `task-proj-…`) is not
    // read as a key.
    // The token is ASCII by construction, so every offset is a char boundary.
    classify_at(token, Body::Token)
        .or_else(|| (1..token.len()).find_map(|start| classify_at(&token[start..], Body::Embedded)))
}

/// The provider rules for a key that starts inside a longer token, read at
/// `candidate`'s start: what [`classify_token`] reads at each later offset,
/// for a stream reader that keeps a window of a token, not all of it.
pub(crate) fn embedded_credential(candidate: &[u8]) -> Option<&'static str> {
    std::str::from_utf8(candidate)
        .ok()
        .and_then(|candidate| classify_at(candidate, Body::Embedded))
}

/// How a key body is read: from the token's start, by each provider's own
/// length rule over token bytes; inside a token, over a fixed length.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Body {
    Token,
    Embedded,
}

fn classify_at(token: &str, body: Body) -> Option<&'static str> {
    if is_aws_access_key_id(token) {
        Some(REASON_AWS_ACCESS_KEY_ID)
    } else if is_github_token(token, body) {
        Some(REASON_GITHUB_TOKEN)
    } else if is_google_api_key(token, body) {
        Some(REASON_GOOGLE_API_KEY)
    } else if is_openai_key(token, body) {
        Some(REASON_OPENAI_KEY)
    } else if is_slack_token(token, body) {
        Some(REASON_SLACK_TOKEN)
    } else if is_stripe_key(token, body) {
        Some(REASON_STRIPE_KEY)
    } else {
        None
    }
}

fn is_aws_access_key_id(token: &str) -> bool {
    let candidate = token.as_bytes();
    if candidate.len() < 20 || !(candidate.starts_with(b"AKIA") || candidate.starts_with(b"ASIA")) {
        return false;
    }
    candidate[..20]
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn is_github_token(token: &str, body: Body) -> bool {
    ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
        .iter()
        .any(|prefix| key_matches(token, prefix, 36, true, true, body))
        || key_matches(token, "github_pat_", 70, false, false, body)
}

fn is_google_api_key(token: &str, body: Body) -> bool {
    key_matches(token, "AIza", 35, true, false, body)
}

fn is_openai_key(token: &str, body: Body) -> bool {
    key_matches(token, "sk-proj-", 32, false, false, body)
        || key_matches(token, "sk-", 48, true, true, body)
}

fn is_slack_token(token: &str, body: Body) -> bool {
    ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"]
        .iter()
        .any(|prefix| key_matches(token, prefix, 24, false, false, body))
}

fn is_stripe_key(token: &str, body: Body) -> bool {
    key_matches(token, "sk_live_", 24, false, true, body)
        || key_matches(token, "rk_live_", 24, false, true, body)
}

/// One provider rule: `prefix`, then `suffix_len` body bytes (`exact_len`:
/// only those are read). Inside a token the body is always read over exactly
/// `suffix_len` bytes, alphanumeric ones when the provider's keys are, and
/// holds a digit or capital.
fn key_matches(
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
