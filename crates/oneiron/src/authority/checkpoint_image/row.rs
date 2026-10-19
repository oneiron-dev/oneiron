//! One covered row's summary in a checkpoint v2 image: the row's scaffold
//! and, for a row a fold or a store door past the image reads whole, its
//! canonical signed body.
//!
//! Each summary marks whether its body is required (FIX 2988): an image that
//! drops a body its row's kind requires fails at decode, before any adopter
//! or door reads it, rather than undercounting a door's view. The marker is
//! committed by the image id and so by every attestation of it; it is no
//! proof against the raw rows. An adopter still trusts the attested fold:
//! without raw history it cannot tell a dishonest signer who changed both a
//! row's marker and its body.

use serde::{Deserialize, Serialize};

use super::*;

/// One covered row, as a fold past the image reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCheckpointRow {
    pub signer: AuthorityKey,
    pub seq: u64,
    /// The parents, in the signed row's order.
    pub parents: Vec<AuthorityEntryHash>,
    /// The world of a side-branch row.
    pub world: Option<EntityId>,
    /// Whether the row is a slip op (a mint, a slip revocation or a
    /// consumption): a store door counts a slip issuer's slip ops toward no
    /// bound.
    pub slip_op: bool,
    /// Whether the image must carry the row's body: true exactly for a row
    /// whose kind a fold or a store door past the image reads whole
    /// ([`carries_body`]), whether or not the row folded valid. The genesis
    /// always requires it.
    pub body_required: bool,
    /// The canonical signed body of a row a fold or a store door past the
    /// image reads whole (an approval, a binding, a confirm, a revocation, a
    /// handoff, an enrollment, the genesis, a root record, a machine profile,
    /// a world edit, a grant travel choice, a world-key record or an owner
    /// work request or result); None for every other row. Present exactly
    /// when `body_required`.
    #[serde(with = "body_bytes")]
    pub body: Option<Vec<u8>>,
}

/// Whether an image carries the canonical signed body of a covered row of
/// `op`'s kind: each row a fold past the image reads whole
/// ([`crate::authority::fold_resume::is_projected`]: an approval, a binding,
/// a confirm, a device revocation, a handoff, a machine profile, a world-key
/// record, an owner work request, result or cancel),
/// and each row a store door past it reads whole to judge a new row: the
/// genesis and each device enrollment the consent structure rests on, the
/// root records that name owner anchors, the actor revocations a signer's
/// revocations count, and the world edits and grant travel choices that may
/// be a stranger's.
fn carries_body(op: &AuthorityOp) -> bool {
    crate::authority::fold_resume::is_projected(op)
        || matches!(
            op,
            AuthorityOp::Genesis { .. }
                | AuthorityOp::EnrollDevice { .. }
                | AuthorityOp::OwnerRoot(_)
                | AuthorityOp::RevokeActor { .. }
                | AuthorityOp::WorldPrivacy(_)
                | AuthorityOp::GrantTravelSet(_)
                | AuthorityOp::CheckpointPolicySet(_)
                | AuthorityOp::HomeNodePick(_)
                | AuthorityOp::ConversationTrainingSet(_)
                | AuthorityOp::ConversationTrainingVaultSet(_)
        )
}

impl AuthorityCheckpointRow {
    /// The summary of covered row `entry`, whose stored canonical signed body
    /// is `body`: the one place a builder marks a row's body required and
    /// carries it.
    pub(in crate::authority) fn of(entry: &AuthorityLogEntry, body: &[u8]) -> Self {
        let body_required = carries_body(&entry.op);
        Self {
            signer: entry.signer_key().clone(),
            seq: entry.seq,
            parents: entry.parent_hashes.clone(),
            world: crate::authority::world_privacy::side_world(&entry.op),
            slip_op: crate::authority::log_budget::is_slip_op(&entry.op),
            body_required,
            body: body_required.then(|| body.to_vec()),
        }
    }
}

/// One covered row's summary, checked alone: its body is present exactly
/// where it is marked required (FIX 2988), and a carried body is the row it
/// summarizes.
pub(super) fn shape_row(hash: &AuthorityEntryHash, row: &AuthorityCheckpointRow) -> Result<()> {
    if row.body_required != row.body.is_some() {
        return Err(refused("checkpoint image row body presence"));
    }
    match &row.body {
        Some(body) => row_body_matches(hash, row, body),
        None => Ok(()),
    }
}

/// A carried body is the canonical signed row its summary names, of a kind
/// the image carries whole, as its summary marks it.
fn row_body_matches(
    hash: &AuthorityEntryHash,
    row: &AuthorityCheckpointRow,
    body: &[u8],
) -> Result<()> {
    let entry = decode_authority_log_entry_body(body)?;
    if authority_entry_hash(&entry)? != *hash
        || entry.signer_key() != &row.signer
        || entry.seq != row.seq
        || entry.parent_hashes != row.parents
        || crate::authority::world_privacy::side_world(&entry.op) != row.world
        || crate::authority::log_budget::is_slip_op(&entry.op) != row.slip_op
        || carries_body(&entry.op) != row.body_required
    {
        return Err(refused("checkpoint image row body"));
    }
    Ok(())
}

/// A row body as one MessagePack byte string.
mod body_bytes {
    use serde::de::{Error, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        body: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match body {
            Some(bytes) => serializer.serialize_some(&Bin(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Ok(Option::<BinBuf>::deserialize(deserializer)?.map(|body| body.0))
    }

    struct Bin<'a>(&'a [u8]);

    impl Serialize for Bin<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.0)
        }
    }

    struct BinBuf(Vec<u8>);

    impl<'de> Deserialize<'de> for BinBuf {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_byte_buf(BinVisitor)
        }
    }

    struct BinVisitor;

    impl Visitor<'_> for BinVisitor {
        type Value = BinBuf;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a row body byte string")
        }

        fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            Ok(BinBuf(bytes.to_vec()))
        }

        fn visit_byte_buf<E: Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            Ok(BinBuf(bytes))
        }
    }
}
