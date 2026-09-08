//! Validated git identity newtypes: ref names, object ids, observations, expectations, publications.

use super::config::{GIT_WIRE_MAX_REF_BYTES, GIT_WIRE_OID_HEX_LEN};
use super::failure::invalid;
use super::{GIT_WIRE_KEEP_REF_PREFIX, GitWireResult};
use crate::error::Result;

/// A validated full git ref name under `refs/`.
///
/// `HEAD` is deliberately not a ref name here: GitWire never compare-and-sets
/// or publishes the symbolic head, and the checkout port pins an explicit
/// commit instead. The accepted byte set is narrow enough that a name is always
/// safe as an unquoted `update-ref --stdin` field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitRefName(String);

impl GitRefName {
    /// Parses a full ref name. Short names, option shapes, revision syntax,
    /// lock shapes, and any byte git may later reject are refused here.
    pub fn parse_full(value: impl Into<String>) -> GitWireResult<Self> {
        let value = value.into();
        validate_full_ref_name(&value)?;
        Ok(Self(value))
    }

    /// The validated ref name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn is_keep_ref(&self) -> bool {
        self.0.starts_with(GIT_WIRE_KEEP_REF_PREFIX)
    }
}

fn validate_full_ref_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > GIT_WIRE_MAX_REF_BYTES {
        return Err(invalid("git ref name must be non-empty and bounded"));
    }
    if !value.starts_with("refs/") {
        return Err(invalid("git ref name must be a full refs/ name"));
    }
    if value.ends_with('/') || value.contains("//") || value.contains("..") {
        return Err(invalid("git ref name must not use empty or relative parts"));
    }
    let shaped = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'));
    if !shaped {
        return Err(invalid(
            "git ref name must be [A-Za-z0-9._-/] after the refs/ prefix",
        ));
    }
    let mut parts = 0;
    for part in value.split('/') {
        if part.is_empty() || part.starts_with('.') || part.ends_with(".lock") || part == ".." {
            return Err(invalid("git ref name component is not a valid ref path"));
        }
        parts += 1;
    }
    if parts < 2 {
        return Err(invalid("git ref name must have a category and a leaf"));
    }
    Ok(())
}

/// A validated 40-character lower-hex, non-zero git object id.
///
/// `checkout::lease` owns a byte-array `GitOid` of its own; the two convert
/// through hex at the [`CheckoutRepoOps`] boundary and never alias.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GitOid(String);

impl GitOid {
    /// Parses a 40-character lower-hex object id.
    pub fn parse_hex(value: impl Into<String>) -> GitWireResult<Self> {
        let value = value.into();
        if value.len() != GIT_WIRE_OID_HEX_LEN
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid("git oid must be 40 lower-hex characters"));
        }
        if value.bytes().all(|byte| byte == b'0') {
            return Err(invalid("git oid must not be the null oid"));
        }
        Ok(Self(value))
    }

    /// The validated object id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A ref and the value GitWire observed for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedGitRef {
    pub name: GitRefName,
    pub oid: Option<GitOid>,
}

/// What a publication requires of a ref's current value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitRefExpectation {
    /// The ref must not exist.
    Absent,
    /// The ref must carry exactly this value.
    Value(GitOid),
    /// No requirement. Reserved for protection refs, which carry no decision.
    Any,
}

impl GitRefExpectation {
    pub(super) fn from_observed(oid: Option<&GitOid>) -> Self {
        match oid {
            Some(oid) => Self::Value(oid.clone()),
            None => Self::Absent,
        }
    }

    pub(super) fn holds_for(&self, observed: Option<&GitOid>) -> bool {
        match self {
            Self::Absent => observed.is_none(),
            Self::Value(expected) => observed == Some(expected),
            Self::Any => true,
        }
    }

    pub(super) fn wire(&self) -> Option<String> {
        match self {
            Self::Absent => Some(String::new()),
            Self::Value(oid) => Some(oid.as_str().to_owned()),
            Self::Any => None,
        }
    }

    pub(super) fn from_wire(value: Option<&String>) -> Result<Self> {
        match value {
            None => Ok(Self::Any),
            Some(text) if text.is_empty() => Ok(Self::Absent),
            Some(text) => Ok(Self::Value(GitOid::parse_hex(text.clone())?)),
        }
    }
}

/// One ref move in a publication transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRefPublication {
    pub(super) name: GitRefName,
    pub(super) expected: GitRefExpectation,
    pub(super) next: Option<GitOid>,
}

impl GitRefPublication {
    /// Moves `name` to `next`, requiring `expected` first.
    pub fn update(name: GitRefName, expected: GitRefExpectation, next: GitOid) -> Self {
        Self {
            name,
            expected,
            next: Some(next),
        }
    }

    /// Deletes `name`, requiring `expected` first.
    pub fn delete(name: GitRefName, expected: GitRefExpectation) -> Self {
        Self {
            name,
            expected,
            next: None,
        }
    }

    /// The published ref.
    pub fn name(&self) -> &GitRefName {
        &self.name
    }

    /// The value the decision was made against.
    pub fn expected(&self) -> &GitRefExpectation {
        &self.expected
    }

    /// The value the ref is moved to, or `None` for a deletion.
    pub fn next(&self) -> Option<&GitOid> {
        self.next.as_ref()
    }

    pub(super) fn satisfied_by(&self, observed: Option<&GitOid>) -> bool {
        observed == self.next.as_ref()
    }

    pub(super) fn stdin_line(&self) -> String {
        let name = self.name.as_str();
        let expectation = self.expected.wire();
        match (&self.next, expectation) {
            (Some(next), Some(expected)) => {
                let next = next.as_str();
                if expected.is_empty() {
                    format!("update {name} {next} \"\"\n")
                } else {
                    format!("update {name} {next} {expected}\n")
                }
            }
            (Some(next), None) => format!("update {name} {}\n", next.as_str()),
            (None, Some(expected)) if !expected.is_empty() => {
                format!("delete {name} {expected}\n")
            }
            (None, _) => format!("delete {name}\n"),
        }
    }
}
