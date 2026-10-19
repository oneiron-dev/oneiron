//! One covered row's summary in a checkpoint v2 image: the row's scaffold
//! and, for a row a fold or a store door past the image reads whole, its
//! canonical signed body.

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
    /// The canonical signed body of a row a fold or a store door past the
    /// image reads whole (an approval, a binding, a confirm, a revocation, a
    /// handoff, an enrollment, the genesis, a root record, a machine profile,
    /// a world edit, a grant travel choice, a world-key record or an owner
    /// work request or result); None for every other row.
    #[serde(with = "body_bytes")]
    pub body: Option<Vec<u8>>,
}

/// Whether an image carries the canonical signed body of a covered row of
/// `op`'s kind: each row a fold past the image reads whole
/// ([`crate::authority::fold_resume::is_projected`]: an approval, a binding,
/// a confirm, a device revocation, a handoff, a machine profile, a world-key
/// record, an owner work request or result),
/// and each row a store door past it reads whole to judge a new row: the
/// genesis and each device enrollment the consent structure rests on, the
/// root records that name owner anchors, the actor revocations a signer's
/// revocations count, and the world edits and grant travel choices that may
/// be a stranger's.
pub(in crate::authority) fn carries_body(op: &AuthorityOp) -> bool {
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
        )
}

/// A carried body is the canonical signed row its summary names, and a row
/// the image carries whole.
pub(super) fn row_body_matches(
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
        || !carries_body(&entry.op)
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
