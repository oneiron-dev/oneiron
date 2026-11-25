//! Warm keys (pass 34, `34-compute-general/DESIGN.md` section 4.1; row P2): the short strings
//! that name what is expensive to bring to a machine, `repo:<mirror>`, `env:<name>`,
//! `weights:<digest>`, `dataset:<digest>`, `toolchain:<name>`, `worktree:<repo>@<commit>`. An
//! order lists the keys its work reads; a node's template maps the keys it knows to paths; the
//! node reports which it holds. Nothing about a key's content is read or sent.
//!
//! One rule for a key's form, read by the order's door, the issuer's quote and the node alike:
//! a kind of lowercase letters, digits, `_` or `-`, a colon, and a name of printable ASCII with
//! no whitespace, at most [`WARM_KEY_MAX_BYTES`] in all. The bounds here size a message and
//! choose nothing (DESIGN 6.3, the constants paragraph).

/// The most bytes one warm key holds.
pub const WARM_KEY_MAX_BYTES: usize = 128;

/// The most warm keys one attempt lists: the reserve's and the submit's bound.
pub const ATTEMPT_WARM_KEYS_MAX: usize = 32;

/// The most warm keys one issuer's wanted list names for a machine: the bound of that ask.
pub const WANTED_WARM_KEYS_MAX: usize = 1024;

/// Why a list of warm keys is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WarmKeyInvalid {
    /// The key is not `<kind>:<name>` within [`WARM_KEY_MAX_BYTES`].
    #[error("warm_key_invalid: {0:?} is not <kind>:<name> of at most {WARM_KEY_MAX_BYTES} bytes")]
    Form(String),
    /// The list names one key twice.
    #[error("warm_key_invalid: {0:?} is listed twice")]
    Repeated(String),
    /// The list holds more keys than its bound.
    #[error("warm_keys_too_many: {count} keys, at most {max}")]
    TooMany { count: usize, max: usize },
}

impl WarmKeyInvalid {
    /// The refusal's code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Form(_) | Self::Repeated(_) => "warm_key_invalid",
            Self::TooMany { .. } => "warm_keys_too_many",
        }
    }
}

/// Whether `key` has a warm key's form.
#[must_use]
pub fn warm_key_valid(key: &str) -> bool {
    let Some((kind, name)) = key.split_once(':') else {
        return false;
    };
    key.len() <= WARM_KEY_MAX_BYTES
        && !kind.is_empty()
        && !name.is_empty()
        && kind.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
        && name.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Checks a list of warm keys: each of a key's form, none twice, at most `max`.
///
/// # Errors
///
/// The first [`WarmKeyInvalid`] found.
pub fn check_warm_keys(keys: &[String], max: usize) -> Result<(), WarmKeyInvalid> {
    if keys.len() > max {
        return Err(WarmKeyInvalid::TooMany {
            count: keys.len(),
            max,
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for key in keys {
        if !warm_key_valid(key) {
            return Err(WarmKeyInvalid::Form(key.clone()));
        }
        if !seen.insert(key.as_str()) {
            return Err(WarmKeyInvalid::Repeated(key.clone()));
        }
    }
    Ok(())
}
