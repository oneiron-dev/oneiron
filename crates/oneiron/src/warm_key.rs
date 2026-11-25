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
//!
//! An order stored before row P2 may hold wishes of any form (`wishes.warm` was a free list
//! then): it reads as before, and only the keys of a warm key's form reach a node
//! ([`usable_warm_keys`]).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// The most bytes one warm key holds.
pub const WARM_KEY_MAX_BYTES: usize = 128;

/// The most warm keys one attempt lists: the reserve's and the submit's bound.
pub const ATTEMPT_WARM_KEYS_MAX: usize = 32;

/// The most warm keys one issuer's wanted list names for a machine: the bound of that ask.
pub const WANTED_WARM_KEYS_MAX: usize = 1024;

/// What an issuer asks a node to keep (row P2): the warm keys of its open orders that may run
/// there, at most [`WANTED_WARM_KEYS_MAX`]. `overflow`: those orders list more keys than one ask
/// carries, so the node removes no cache while the ask holds. Each ask replaces the issuer's
/// last.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmWanted {
    pub keys: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub overflow: bool,
}

impl WarmWanted {
    /// The ask for `keys`: the usable ones, at most [`WANTED_WARM_KEYS_MAX`], and whether one
    /// was left out for the bound.
    #[must_use]
    pub fn of<'a>(keys: impl IntoIterator<Item = &'a String>) -> Self {
        let (keys, overflow) = usable_warm_keys(keys, WANTED_WARM_KEYS_MAX);
        Self { keys, overflow }
    }
}

/// The keys of `keys` that have a warm key's form, each once, in their order, at most `max`;
/// and whether such a key was left out for the bound.
#[must_use]
pub fn usable_warm_keys<'a>(
    keys: impl IntoIterator<Item = &'a String>,
    max: usize,
) -> (Vec<String>, bool) {
    let mut seen = BTreeSet::new();
    let mut usable = Vec::new();
    for key in keys {
        if !warm_key_valid(key) || !seen.insert(key.as_str()) {
            continue;
        }
        if usable.len() == max {
            return (usable, true);
        }
        usable.push(key.clone());
    }
    (usable, false)
}

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
    let mut seen = BTreeSet::new();
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
