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
    // A rule reads a key only from its prefix on, so only the offsets where
    // one starts are read ([`key_starts`]), the token's start as a token.
    // The token is ASCII by construction, so every offset is a char boundary.
    key_starts(token).find_map(|start| {
        let body = if start == 0 {
            Body::Token
        } else {
            Body::Embedded
        };
        classify_at(&token[start..], body)
    })
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
    PROVIDER_RULES
        .iter()
        .find(|rule| rule.matches(token, body))
        .map(|rule| rule.reason)
}

/// The bytes an AWS access key id is read over, its prefix included.
const ACCESS_KEY_ID_LEN: usize = 20;

/// Every provider rule, in the order [`classify_at`] reads them: the first
/// that matches names the reason. Each reads a key only from its prefix on.
const PROVIDER_RULES: [ProviderRule; 18] = [
    ProviderRule::access_key_id("AKIA"),
    ProviderRule::access_key_id("ASIA"),
    ProviderRule::key(REASON_GITHUB_TOKEN, "ghp_", 36, true, true),
    ProviderRule::key(REASON_GITHUB_TOKEN, "gho_", 36, true, true),
    ProviderRule::key(REASON_GITHUB_TOKEN, "ghu_", 36, true, true),
    ProviderRule::key(REASON_GITHUB_TOKEN, "ghs_", 36, true, true),
    ProviderRule::key(REASON_GITHUB_TOKEN, "ghr_", 36, true, true),
    ProviderRule::key(REASON_GITHUB_TOKEN, "github_pat_", 70, false, false),
    ProviderRule::key(REASON_GOOGLE_API_KEY, "AIza", 35, true, false),
    ProviderRule::key(REASON_OPENAI_KEY, "sk-proj-", 32, false, false),
    ProviderRule::key(REASON_OPENAI_KEY, "sk-", 48, true, true),
    ProviderRule::key(REASON_SLACK_TOKEN, "xoxb-", 24, false, false),
    ProviderRule::key(REASON_SLACK_TOKEN, "xoxp-", 24, false, false),
    ProviderRule::key(REASON_SLACK_TOKEN, "xoxa-", 24, false, false),
    ProviderRule::key(REASON_SLACK_TOKEN, "xoxr-", 24, false, false),
    ProviderRule::key(REASON_SLACK_TOKEN, "xoxs-", 24, false, false),
    ProviderRule::key(REASON_STRIPE_KEY, "sk_live_", 24, false, true),
    ProviderRule::key(REASON_STRIPE_KEY, "rk_live_", 24, false, true),
];

/// The fewest bytes any provider rule reads a key in.
const MIN_KEY_LEN: usize = min_key_len(&PROVIDER_RULES);

/// The bytes some provider rule's prefix starts with.
static PREFIX_HEADS: [bool; 256] = prefix_heads(&PROVIDER_RULES);

/// One provider rule: a key that starts with `prefix`, its bytes read by
/// `shape`, named by `reason`.
struct ProviderRule {
    reason: &'static str,
    prefix: &'static str,
    shape: KeyShape,
}

/// How a provider rule reads the bytes from its prefix on.
enum KeyShape {
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

impl ProviderRule {
    const fn access_key_id(prefix: &'static str) -> Self {
        Self {
            reason: REASON_AWS_ACCESS_KEY_ID,
            prefix,
            shape: KeyShape::AccessKeyId,
        }
    }

    const fn key(
        reason: &'static str,
        prefix: &'static str,
        suffix_len: usize,
        exact_len: bool,
        alphanumeric: bool,
    ) -> Self {
        Self {
            reason,
            prefix,
            shape: KeyShape::Suffix {
                suffix_len,
                exact_len,
                alphanumeric,
            },
        }
    }

    /// Whether `candidate` holds this rule's key from its start.
    fn matches(&self, candidate: &str, body: Body) -> bool {
        match self.shape {
            KeyShape::AccessKeyId => {
                let candidate = candidate.as_bytes();
                candidate.len() >= ACCESS_KEY_ID_LEN
                    && candidate.starts_with(self.prefix.as_bytes())
                    && candidate[..ACCESS_KEY_ID_LEN]
                        .iter()
                        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            }
            KeyShape::Suffix {
                suffix_len,
                exact_len,
                alphanumeric,
            } => key_matches(candidate, self.prefix, suffix_len, exact_len, alphanumeric, body),
        }
    }

    /// The fewest bytes a candidate holding this rule's key has: [`Self::matches`]
    /// finds no key in a shorter one.
    const fn min_len(&self) -> usize {
        match self.shape {
            KeyShape::AccessKeyId => ACCESS_KEY_ID_LEN,
            KeyShape::Suffix { suffix_len, .. } => self.prefix.len() + suffix_len,
        }
    }

    /// Whether this rule may read a key at `candidate`'s start: it starts with
    /// the prefix and holds [`Self::min_len`] bytes. [`Self::matches`] finds a
    /// key only where this holds.
    fn may_start(&self, candidate: &[u8]) -> bool {
        candidate.len() >= self.min_len() && candidate.starts_with(self.prefix.as_bytes())
    }
}

/// [`ProviderRule::min_len`]'s least over `rules`.
const fn min_key_len(rules: &[ProviderRule]) -> usize {
    let mut least = usize::MAX;
    let mut at = 0;
    while at < rules.len() {
        let len = rules[at].min_len();
        if len < least {
            least = len;
        }
        at += 1;
    }
    least
}

/// Which bytes a prefix in `rules` starts with; every byte when a rule has no
/// prefix, since such a rule may start anywhere.
const fn prefix_heads(rules: &[ProviderRule]) -> [bool; 256] {
    let mut heads = [false; 256];
    let mut at = 0;
    while at < rules.len() {
        let Some(&head) = rules[at].prefix.as_bytes().first() else {
            return [true; 256];
        };
        heads[head as usize] = true;
        at += 1;
    }
    heads
}

/// Each offset of `token`, in order, where some provider rule may read a key
/// ([`ProviderRule::may_start`]). [`classify_at`] finds no key at any other
/// offset, so a token holding no provider prefix is read nowhere.
fn key_starts(token: &str) -> impl Iterator<Item = usize> {
    let bytes = token.as_bytes();
    // An offset past the last with `MIN_KEY_LEN` bytes left holds no key, and
    // an empty candidate holds none.
    let starts = (bytes.len() + 1)
        .saturating_sub(MIN_KEY_LEN)
        .min(bytes.len());
    (0..starts).filter(move |&start| {
        PREFIX_HEADS[usize::from(bytes[start])]
            && PROVIDER_RULES
                .iter()
                .any(|rule| rule.may_start(&bytes[start..]))
    })
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
