//! An image's replay evidence (OF-469, FIX 3007): the fold state at each
//! covered row off the frontier, as the image's reference fold settled it,
//! so a fold past the image seeds a late fork on any covered row and
//! re-judges a covered row in this install's context without the history
//! (CALLS "FIX 3007 replay representation").
//!
//! Each row's point is explicit: a row the fold holds no state at is
//! [`ReplayPoint::Rejected`]; a row with one keeps it whole every
//! [`AUTHORITY_REPLAY_FULL_STRIDE`] rows down a first-parent chain, and
//! otherwise as the fields that differ from the whole state it rests on.
//! The encoding is deterministic and lossless: [`fold_state_fields`] names
//! every field of the fold state, so a field added there without a name here
//! does not compile. An image whose evidence would pass the encoded size cap
//! carries [`ReplayEvidence::FrontierOnly`] instead and claims no per-row
//! replay (CALLS AUTHORITY_REPLAY_OVERFLOW); every fold past it keeps
//! today's history request. A point that does not decode is no evidence,
//! never a refusal.

use serde::de::DeserializeOwned;

use super::*;

/// How many rows down a first-parent chain a whole state is kept again: the
/// most fields deltas any reconstruction applies is one point's (CALLS "FIX
/// 3007 replay representation").
pub(in crate::authority) const AUTHORITY_REPLAY_FULL_STRIDE: u32 = 32;

/// What an image whose replay evidence would pass the size cap carries
/// instead (CALLS AUTHORITY_REPLAY_OVERFLOW): its frontier states alone.
pub(in crate::authority) const AUTHORITY_REPLAY_OVERFLOW: ReplayEvidence =
    ReplayEvidence::FrontierOnly;

/// The fold states an image keeps off its frontier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::authority) enum ReplayEvidence {
    /// One point at each covered row off the frontier, keyed ascending.
    Rows(BTreeMap<AuthorityEntryHash, ReplayPoint>),
    /// The frontier states alone: no fold past the image reads a state off
    /// its frontier.
    FrontierOnly,
}

/// One covered row's fold state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::authority) enum ReplayPoint {
    /// The fold holds no state at this row.
    Rejected,
    /// The whole state.
    Full(Box<FoldState>),
    /// The whole state at `base`, an ancestor of this row down its
    /// first-parent chain, with each named field replaced.
    Delta {
        base: AuthorityEntryHash,
        fields: BTreeMap<String, FieldBytes>,
    },
}

/// One field's value as its own MessagePack bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::authority) struct FieldBytes(Vec<u8>);

impl Serialize for FieldBytes {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for FieldBytes {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Bytes;
        impl serde::de::Visitor<'_> for Bytes {
            type Value = FieldBytes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a fold state field byte string")
            }

            fn visit_bytes<E: serde::de::Error>(
                self,
                bytes: &[u8],
            ) -> std::result::Result<FieldBytes, E> {
                Ok(FieldBytes(bytes.to_vec()))
            }

            fn visit_byte_buf<E: serde::de::Error>(
                self,
                bytes: Vec<u8>,
            ) -> std::result::Result<FieldBytes, E> {
                Ok(FieldBytes(bytes))
            }
        }
        deserializer.deserialize_byte_buf(Bytes)
    }
}

fn encode_field<T: Serialize>(value: &T) -> Option<FieldBytes> {
    rmp_serde::to_vec_named(value).ok().map(FieldBytes)
}

fn decode_field<T: DeserializeOwned>(bytes: &FieldBytes) -> Option<T> {
    rmp_serde::from_slice(&bytes.0).ok()
}

/// Every field of [`FoldState`], by name: the fields a delta may replace,
/// the delta between two states, and a delta applied. The pattern names
/// each field, so the list and the struct cannot drift apart.
macro_rules! fold_state_fields {
    ($($field:ident),* $(,)?) => {
        const FIELDS: &[&str] = &[$(stringify!($field)),*];

        /// The fields of `state` that differ from `base`, each encoded;
        /// None where one does not encode.
        fn state_delta(
            base: &FoldState,
            state: &FoldState,
        ) -> Option<BTreeMap<String, FieldBytes>> {
            let FoldState { $($field: _),* } = state;
            let mut fields = BTreeMap::new();
            $(
                if base.$field != state.$field {
                    fields.insert(stringify!($field).to_owned(), encode_field(&state.$field)?);
                }
            )*
            Some(fields)
        }

        /// `base` with each field of `fields` replaced; None where a name is
        /// unknown or a value does not decode.
        fn apply_delta(base: &FoldState, fields: &BTreeMap<String, FieldBytes>) -> Option<FoldState> {
            let mut state = base.clone();
            for (name, bytes) in fields {
                match name.as_str() {
                    $(stringify!($field) => state.$field = decode_field(bytes)?,)*
                    _ => return None,
                }
            }
            Some(state)
        }
    };
}

fold_state_fields!(
    slips,
    vault_id,
    roster,
    genesis_recovery_dismissed,
    recovery_redundancy_established,
    federation_pacts,
    federation_confirms,
    critical_write_confirms,
    consumed_critical_write_confirm_nonces,
    critical_write_confirm_nonce_provenance,
    conflicted_critical_write_confirms,
    federation_grant_bindings,
    actor_bindings,
    actor_binding_revocations,
    actor_revocation_hashes,
    seqs,
    machines,
    machine_keys,
    root_anchors,
    anchor_entries,
    host_custody_keys,
    worlds,
    refused_world_edits,
    grant_travel,
    refused_grant_travel,
    checkpoint_policy,
    home_pick,
    conversation_training,
    conversation_training_vault,
    home_candidacy,
    owner_work,
    world_keys,
    refused_world_keys,
    key_admitters,
    hosted,
    actor_rows,
    residence_directives,
);

impl ReplayEvidence {
    /// The points of the rows `order` names, parents first, each row's
    /// parents in `parents` and its state in `states` (none for a row the
    /// fold holds no state at), resting on `kept`'s points for any parent
    /// they already hold. Every row of `order` gets a point.
    pub(in crate::authority) fn points_of(
        order: &[AuthorityEntryHash],
        parents: &dyn Fn(&AuthorityEntryHash) -> Option<Vec<AuthorityEntryHash>>,
        states: &dyn Fn(&AuthorityEntryHash) -> Option<FoldState>,
        kept: &BTreeMap<AuthorityEntryHash, ReplayPoint>,
    ) -> Option<BTreeMap<AuthorityEntryHash, ReplayPoint>> {
        let mut points = BTreeMap::new();
        // Each row's whole state it rests on, and how far down from it.
        let mut anchors = BTreeMap::<AuthorityEntryHash, (AuthorityEntryHash, u32)>::new();
        let mut wholes = BTreeMap::<AuthorityEntryHash, FoldState>::new();
        for hash in order {
            let Some(state) = states(hash) else {
                points.insert(*hash, ReplayPoint::Rejected);
                continue;
            };
            let anchor = parents(hash).into_iter().flatten().find_map(|parent| {
                if let Some(anchor) = anchors.get(&parent) {
                    return Some(*anchor);
                }
                match kept.get(&parent) {
                    Some(ReplayPoint::Full(_)) => Some((parent, 0)),
                    _ => None,
                }
            });
            let delta = anchor
                .filter(|(_, depth)| depth + 1 < AUTHORITY_REPLAY_FULL_STRIDE)
                .and_then(|(base, depth)| {
                    let whole = match wholes.get(&base) {
                        Some(whole) => whole,
                        None => match kept.get(&base) {
                            Some(ReplayPoint::Full(whole)) => whole,
                            _ => return None,
                        },
                    };
                    Some((base, depth + 1, state_delta(whole, &state)?))
                });
            match delta {
                Some((base, depth, fields)) => {
                    anchors.insert(*hash, (base, depth));
                    points.insert(*hash, ReplayPoint::Delta { base, fields });
                }
                None => {
                    anchors.insert(*hash, (*hash, 0));
                    wholes.insert(*hash, state.clone());
                    points.insert(*hash, ReplayPoint::Full(Box::new(state)));
                }
            }
        }
        Some(points)
    }

    /// Whether the evidence holds a point at `hash`, without decoding it.
    pub(in crate::authority) fn holds(&self, hash: &AuthorityEntryHash) -> bool {
        matches!(self, Self::Rows(points) if points.contains_key(hash))
    }

    /// Whether the fold holds no state at `hash`, as the evidence shows it.
    pub(in crate::authority) fn rejected(&self, hash: &AuthorityEntryHash) -> bool {
        matches!(self, Self::Rows(points) if matches!(points.get(hash), Some(ReplayPoint::Rejected)))
    }

    /// The state at `hash`: `Some(None)` where the fold holds none, and None
    /// where the evidence keeps no point or its point does not decode.
    pub(in crate::authority) fn state_at(
        &self,
        hash: &AuthorityEntryHash,
    ) -> Option<Option<FoldState>> {
        let Self::Rows(points) = self else {
            return None;
        };
        match points.get(hash)? {
            ReplayPoint::Rejected => Some(None),
            ReplayPoint::Full(state) => Some(Some((**state).clone())),
            ReplayPoint::Delta { base, fields } => match points.get(base)? {
                ReplayPoint::Full(whole) => apply_delta(whole, fields).map(Some),
                _ => None,
            },
        }
    }

    /// The points, checked alone: exactly `off_frontier`'s rows, each whole
    /// state naming `vault_id`, each delta resting on a whole state it holds
    /// and replacing only known fields, never the vault.
    pub(super) fn shape(
        &self,
        vault_id: &AuthorityVaultId,
        off_frontier: impl Iterator<Item = AuthorityEntryHash>,
    ) -> Result<()> {
        let Self::Rows(points) = self else {
            return Ok(());
        };
        if !points.keys().copied().eq(off_frontier) {
            return Err(refused("checkpoint image replay coverage"));
        }
        let sound = points.values().all(|point| match point {
            ReplayPoint::Rejected => true,
            ReplayPoint::Full(state) => state.vault_id == *vault_id,
            ReplayPoint::Delta { base, fields } => {
                matches!(points.get(base), Some(ReplayPoint::Full(_)))
                    && fields
                        .keys()
                        .all(|name| name != "vault_id" && FIELDS.contains(&name.as_str()))
            }
        });
        if !sound {
            return Err(refused("checkpoint image replay points"));
        }
        Ok(())
    }
}

/// `rows`' hashes, each after every parent of it among `rows`, ties by
/// hash; a row on a cycle comes last.
pub(in crate::authority) fn parents_first_of(
    rows: &BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
) -> Vec<AuthorityEntryHash> {
    let mut waiting = BTreeMap::new();
    let mut children = BTreeMap::<_, Vec<_>>::new();
    let mut ready = BTreeSet::new();
    for (hash, parents) in rows {
        let parents: BTreeSet<_> = parents
            .iter()
            .filter(|parent| rows.contains_key(*parent))
            .collect();
        for parent in &parents {
            children.entry(**parent).or_default().push(*hash);
        }
        if parents.is_empty() {
            ready.insert(*hash);
        } else {
            waiting.insert(*hash, parents.len());
        }
    }
    let mut order = Vec::with_capacity(rows.len());
    while let Some(hash) = ready.pop_first() {
        order.push(hash);
        for child in children.get(&hash).into_iter().flatten() {
            if let Some(count) = waiting.get_mut(child) {
                *count -= 1;
                if *count == 0 {
                    waiting.remove(child);
                    ready.insert(*child);
                }
            }
        }
    }
    order.extend(waiting.into_keys());
    order
}
