//! A root request's revision basis (FIX 5551): the heads its `seen` is the
//! revision of, as the recorder folded them, signed with the request as its
//! witness.
//!
//! The act's `seen` alone cannot tell a target that has not yet folded a root
//! record or an anchor's mark the recorder held from roots that moved since
//! the owner decided: both hash to another revision. The basis names the
//! heads themselves, so the target can tell which of its own heads differ.
//! It is checked against `seen` when the request decodes: the revision of
//! the basis is the act's `seen`, exactly, so the witness is what the owner's
//! revision covers and never a caller's list beside it. Ids and entry hashes
//! only; no seed, piece or secret byte.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::error::Result;

use super::*;

const BASIS_KEYS: [&str; 4] = ["roots", "roster", "roster_trusted", "anchored"];

/// The heads a root request's revision is over, as its recorder folded them
/// (CALLS ROOT_WORK_REVISION): every valid owner root by its id, and the
/// target's roster revision, its accepted roster revision and the head of
/// each anchor's chain of it. The root the change binds and its anchor's
/// chain of the target are left out, as the revision leaves them out.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct RootRevisionBasis {
    /// Every owner root the revision covers, by its id.
    pub roots: BTreeSet<RecoveryRootId>,
    /// The entry of the target's roster revision.
    pub roster: Option<AuthorityEntryHash>,
    /// The entry of the target's accepted roster revision.
    pub roster_trusted: Option<AuthorityEntryHash>,
    /// The head of each anchor's chain of the target, by anchor key.
    pub anchored: BTreeMap<[u8; 32], AuthorityEntryHash>,
}

impl RootRevisionBasis {
    /// The revision these heads are: [`act_revision`] under
    /// [`ROOT_WORK_REVISION_CONTEXT`] over every root id and standing entry.
    #[must_use]
    pub fn revision(&self) -> [u8; 32] {
        let standing = self
            .roster
            .iter()
            .chain(&self.roster_trusted)
            .chain(self.anchored.values())
            .copied();
        act_revision(
            ROOT_WORK_REVISION_CONTEXT,
            self.roots.iter().map(|root| root.0).chain(standing),
        )
    }
}

/// Canonical map: roots (ascending ids), roster, roster_trusted (each an
/// entry hash or nil), then anchored, an array of `[anchor, entry]` pairs
/// ascending by anchor key.
pub(super) fn root_basis_value(basis: &RootRevisionBasis) -> Value {
    let optional = |entry: Option<AuthorityEntryHash>| entry.map_or(Value::Nil, binary_value);
    Value::Map(vec![
        (
            Value::from("roots"),
            Value::Array(
                basis
                    .roots
                    .iter()
                    .map(|root| binary_value(root.0))
                    .collect(),
            ),
        ),
        (Value::from("roster"), optional(basis.roster)),
        (
            Value::from("roster_trusted"),
            optional(basis.roster_trusted),
        ),
        (
            Value::from("anchored"),
            Value::Array(
                basis
                    .anchored
                    .iter()
                    .map(|(anchor, entry)| {
                        Value::Array(vec![binary_value(*anchor), binary_value(*entry)])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// The [`root_basis_value`] inverse, fail-closed: every array strictly
/// ascending, every pair exactly two hashes.
pub(super) fn decode_root_basis(value: &Value) -> Result<RootRevisionBasis> {
    let entries = map_entries(value)?;
    validate_keys(entries, &BASIS_KEYS)?;
    let roots = decode_hash_array(required(entries, "roots")?)?;
    if !ascending(&roots) {
        return Err(invalid_authority());
    }
    let Value::Array(pairs) = required(entries, "anchored")? else {
        return Err(invalid_authority());
    };
    let mut anchored = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let Value::Array(pair) = pair else {
            return Err(invalid_authority());
        };
        let [anchor, entry] = pair.as_slice() else {
            return Err(invalid_authority());
        };
        anchored.push((decode_hash(anchor)?, decode_hash(entry)?));
    }
    let anchors: Vec<[u8; 32]> = anchored.iter().map(|(anchor, _)| *anchor).collect();
    if !ascending(&anchors) {
        return Err(invalid_authority());
    }
    Ok(RootRevisionBasis {
        roots: roots.into_iter().map(RecoveryRootId).collect(),
        roster: decode_optional_hash(required(entries, "roster")?)?,
        roster_trusted: decode_optional_hash(required(entries, "roster_trusted")?)?,
        anchored: anchored.into_iter().collect(),
    })
}

/// Strictly ascending: sorted, no duplicate.
fn ascending(values: &[[u8; 32]]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
