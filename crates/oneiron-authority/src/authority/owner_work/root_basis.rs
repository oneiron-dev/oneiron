//! A root request's revision basis (FIX 5551): the heads its `seen` is the
//! revision of, as the recorder folded them, signed with the request as its
//! witness.
//!
//! The basis is the target's roster head and accepted-roster head, each by
//! its entry, nil where the target has none. Its revision is the act's
//! `seen`, exactly, so the witness is what the owner's revision covers and
//! never a caller's list beside it. Ids and entry hashes only; no seed,
//! piece or secret byte.

use rmpv::Value;

use crate::error::Result;

use super::*;

const BASIS_KEYS: [&str; 2] = ["roster", "roster_trusted"];

/// The heads a root request's revision is over, as its recorder folded them
/// (CALLS ROOT_WORK_REVISION): the target's roster revision and its accepted
/// roster revision, each by its entry.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct RootRevisionBasis {
    /// The entry of the target's roster revision.
    pub roster: Option<AuthorityEntryHash>,
    /// The entry of the target's accepted roster revision.
    pub roster_trusted: Option<AuthorityEntryHash>,
}

impl RootRevisionBasis {
    /// The revision these heads are: [`act_revision`] under
    /// [`ROOT_WORK_REVISION_CONTEXT`] over the two standing entries.
    #[must_use]
    pub fn revision(&self) -> [u8; 32] {
        act_revision(
            ROOT_WORK_REVISION_CONTEXT,
            self.roster.iter().chain(&self.roster_trusted).copied(),
        )
    }
}

/// Canonical map, always both keys in this order: roster, then
/// roster_trusted, each an entry hash or nil.
pub(super) fn root_basis_value(basis: &RootRevisionBasis) -> Value {
    let optional = |entry: Option<AuthorityEntryHash>| entry.map_or(Value::Nil, binary_value);
    Value::Map(vec![
        (Value::from("roster"), optional(basis.roster)),
        (
            Value::from("roster_trusted"),
            optional(basis.roster_trusted),
        ),
    ])
}

/// The [`root_basis_value`] inverse, fail-closed: exactly the two keys, in
/// order, each nil or a 32-byte hash.
pub(super) fn decode_root_basis(value: &Value) -> Result<RootRevisionBasis> {
    let entries = map_entries(value)?;
    validate_keys(entries, &BASIS_KEYS)?;
    let ordered = entries.len() == BASIS_KEYS.len()
        && entries
            .iter()
            .zip(BASIS_KEYS.iter())
            .all(|((key, _), name)| key.as_str() == Some(*name));
    if !ordered {
        return Err(invalid_authority());
    }
    Ok(RootRevisionBasis {
        roster: decode_optional_hash(required(entries, "roster")?)?,
        roster_trusted: decode_optional_hash(required(entries, "roster_trusted")?)?,
    })
}
