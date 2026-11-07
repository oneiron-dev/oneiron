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
//!
//! Beside the heads, under the same signature and outside the revision, the
//! basis carries the recorder's causal evidence for them (FIX 6556): the
//! anchor the revision left out for the root the change binds, and the
//! parents each anchor chain head's entry names. They are no heads: the
//! revision stays the one every target computes from its own fold, so an
//! equal revision is equal as before. A target reads them only to prove a
//! lag: the bound anchor where the bound root's record has not reached it,
//! and the parents against the head's own signed entry where it stores the
//! head but has not folded it. Each is omitted when empty, so a basis
//! without them keeps its bytes.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::error::Result;

use super::*;

const BASIS_KEYS: [&str; 4] = ["roots", "roster", "roster_trusted", "anchored"];
/// The bound anchor's key, present only when the basis names one.
const BOUND_KEY: &str = "bound";
/// The anchor heads' parents' key, present only when the basis names some.
const PARENTS_KEY: &str = "parents";

/// The heads a root request's revision is over, as its recorder folded them
/// (CALLS ROOT_WORK_REVISION): every valid owner root by its id, and the
/// target's roster revision, its accepted roster revision and the head of
/// each anchor's chain of it. The root the change binds and its anchor's
/// chain of the target are left out, as the revision leaves them out. The
/// bound anchor and the anchor heads' parents ride beside them, outside the
/// revision (FIX 6556).
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
    /// The anchor whose roots and chain of the target the revision leaves
    /// out: the anchor of the root the change binds, as the recorder folded
    /// its record. `None` when the change binds no root or the recorder held
    /// no record of it; the target then leaves out the anchor its own fold
    /// holds the root under, as before.
    pub bound: Option<[u8; 32]>,
    /// The parents each anchor chain head's entry names, by the head's
    /// entry, for the heads the recorder stores. Every key is a value of
    /// `anchored`.
    pub parents: BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
}

impl RootRevisionBasis {
    /// The revision these heads are: [`act_revision`] under
    /// [`ROOT_WORK_REVISION_CONTEXT`] over every root id and standing entry.
    /// The bound anchor and the parents are no heads and stay out of it.
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
/// ascending by anchor key; then bound, the anchor key, when there is one;
/// then parents, when any head has them, an array of `[entry, [parent, ..]]`
/// pairs ascending by entry, each parent list ascending.
pub(super) fn root_basis_value(basis: &RootRevisionBasis) -> Value {
    let optional = |entry: Option<AuthorityEntryHash>| entry.map_or(Value::Nil, binary_value);
    let mut entries = vec![
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
    ];
    // Absent when empty, so a basis signed without them keeps its bytes.
    if let Some(anchor) = basis.bound {
        entries.push((Value::from(BOUND_KEY), binary_value(anchor)));
    }
    if !basis.parents.is_empty() {
        entries.push((
            Value::from(PARENTS_KEY),
            Value::Array(
                basis
                    .parents
                    .iter()
                    .map(|(entry, parents)| {
                        Value::Array(vec![
                            binary_value(*entry),
                            Value::Array(
                                parents.iter().map(|parent| binary_value(*parent)).collect(),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ));
    }
    Value::Map(entries)
}

/// The [`root_basis_value`] inverse, fail-closed: every array strictly
/// ascending, every pair exactly two values, the bound anchor none of the
/// anchors whose chain heads it names, and each parent list a head's: of an
/// `anchored` entry, non-empty and no longer than an entry's parents may be.
pub(super) fn decode_root_basis(value: &Value) -> Result<RootRevisionBasis> {
    let entries = map_entries(value)?;
    let named = |name: &str| {
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
    };
    // The exact key set: the heads' keys, and each optional key present.
    let mut keys = BASIS_KEYS.to_vec();
    keys.extend(
        [BOUND_KEY, PARENTS_KEY]
            .into_iter()
            .filter(|name| named(*name).is_some()),
    );
    validate_keys(entries, &keys)?;
    let roots = decode_hash_array(required(entries, "roots")?)?;
    if !ascending(&roots) {
        return Err(invalid_authority());
    }
    let anchored: BTreeMap<[u8; 32], AuthorityEntryHash> =
        decode_pairs(required(entries, "anchored")?, decode_hash)?
            .into_iter()
            .collect();
    let bound = named(BOUND_KEY).map(decode_hash).transpose()?;
    if bound.is_some_and(|anchor| anchored.contains_key(&anchor)) {
        return Err(invalid_authority());
    }
    let heads: BTreeSet<AuthorityEntryHash> = anchored.values().copied().collect();
    let parents: BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>> =
        match named(PARENTS_KEY) {
            None => BTreeMap::new(),
            Some(value) => {
                let pairs = decode_pairs(value, |parents| {
                    let parents = decode_hash_array(parents)?;
                    if parents.is_empty() || parents.len() > MAX_PARENTS || !ascending(&parents) {
                        return Err(invalid_authority());
                    }
                    Ok(parents.into_iter().collect::<BTreeSet<_>>())
                })?;
                // Canonical only: non-empty, and each a witnessed head's.
                if pairs.is_empty() || pairs.iter().any(|(entry, _)| !heads.contains(entry)) {
                    return Err(invalid_authority());
                }
                pairs.into_iter().collect()
            }
        };
    Ok(RootRevisionBasis {
        roots: roots.into_iter().map(RecoveryRootId).collect(),
        roster: decode_optional_hash(required(entries, "roster")?)?,
        roster_trusted: decode_optional_hash(required(entries, "roster_trusted")?)?,
        anchored,
        bound,
        parents,
    })
}

/// An array of `[hash, value]` pairs, strictly ascending by hash, each
/// value read by `second`.
fn decode_pairs<T>(
    value: &Value,
    second: impl Fn(&Value) -> Result<T>,
) -> Result<Vec<([u8; 32], T)>> {
    let Value::Array(pairs) = value else {
        return Err(invalid_authority());
    };
    let mut decoded = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let Value::Array(pair) = pair else {
            return Err(invalid_authority());
        };
        let [first, rest] = pair.as_slice() else {
            return Err(invalid_authority());
        };
        decoded.push((decode_hash(first)?, second(rest)?));
    }
    let firsts: Vec<[u8; 32]> = decoded.iter().map(|(first, _)| *first).collect();
    if !ascending(&firsts) {
        return Err(invalid_authority());
    }
    Ok(decoded)
}

/// Strictly ascending: sorted, no duplicate.
fn ascending(values: &[[u8; 32]]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
