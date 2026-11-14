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
//!
//! Each summary also marks the signed row's kind and whether it is sealed
//! (census L5-22 1a-iii). An image that covers a sealed row carries every
//! covered row's body ([`super::AuthorityCheckpointV2::covers_sealed_row`]):
//! an adopter whose custody does not open that row folds the carried rows
//! itself, and the sender's fold grants it nothing.

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
    /// The signed row's op kind, as its verified scaffold names it, whether
    /// or not its record opens here.
    pub op_kind: String,
    /// Whether the signed row is sealed: its op holds a commitment node, so
    /// its record is an overlay row a reader's custody may not open.
    pub sealed: bool,
    /// Whether the image must carry the row's body: true exactly for a row
    /// whose kind a fold or a store door past the image reads whole
    /// ([`carries_body`]), whether or not the row folded valid, and for every
    /// row of an image that covers a sealed row. The genesis always requires
    /// it. A residence row dropped for
    /// [`super::AUTHORITY_RESIDENCE_BODY_OVERFLOW`] requires none, as before
    /// #4095 carried them (FIX 11400).
    pub body_required: bool,
    /// The canonical signed body of a row a fold or a store door past the
    /// image reads whole (an approval, a binding, a confirm, a revocation, a
    /// handoff, an enrollment, the genesis, a root record, a machine profile,
    /// a world edit, a grant travel choice, a world-key record, an owner
    /// work request or result, or an owner handover); None for every other
    /// row. Present exactly when `body_required`. A residence row dropped for
    /// [`super::AUTHORITY_RESIDENCE_BODY_OVERFLOW`] carries none (FIX 11400).
    #[serde(with = "body_bytes")]
    pub body: Option<Vec<u8>>,
}

/// Whether an image carries the canonical signed body of a covered
/// row of `op`'s kind: each row a fold past the image reads whole
/// ([`crate::authority::fold_resume::is_projected`]: an approval, a binding,
/// a confirm, a device revocation, a handoff, a machine profile, a world-key
/// record, an owner work request, result or cancel),
/// and each row a store door past it reads whole to judge a new row: the
/// genesis and each device enrollment the consent structure rests on (an
/// owner's own device key enrollment among them, FIX 4920), the root records
/// that name owner anchors, the actor revocations a signer's
/// revocations count, and the world edits, grant travel choices, frontier
/// joins and custody permit pieces (FIX 11866) that may be a stranger's; each owner handover, whose signed
/// grant ids a restore across it reads (FIX 5765), and each membership
/// execution record, whose withdrawn Grants a store reader and whose
/// handover a restore reads (FIX 12335); and each row whose
/// transition reads the install's pin or its admitted peers' roots, which a
/// fold under another pin or peer set judges again (a home candidacy, a
/// federation lifecycle act; FIX 3004, 3005); and each residence directive
/// and result, which a machine's directive reader reads past the image (FIX
/// 5412). An image past the optional-compaction trigger drops its residence
/// bodies for [`super::AUTHORITY_RESIDENCE_BODY_OVERFLOW`] (FIX 11400).
fn carries_body(op: &AuthorityOp) -> bool {
    crate::authority::fold_resume::is_projected(op)
        || matches!(
            op,
            AuthorityOp::Genesis { .. }
                | AuthorityOp::EnrollDevice { .. }
                | AuthorityOp::OwnerKeyEnroll(_)
                | AuthorityOp::OwnerRoot(_)
                | AuthorityOp::RevokeActor { .. }
                | AuthorityOp::WorldPrivacy(_)
                | AuthorityOp::GrantTravelSet(_)
                | AuthorityOp::CheckpointPolicySet(_)
                | AuthorityOp::HomeNodePick(_)
                | AuthorityOp::OriginCut(_)
                | AuthorityOp::DeviceSuccession(_)
                | AuthorityOp::ConversationTrainingSet(_)
                | AuthorityOp::ConversationTrainingVaultSet(_)
                | AuthorityOp::AgentGrantAct(_)
                | AuthorityOp::PolicySettingSet(_)
                | AuthorityOp::ExportAct(_)
                | AuthorityOp::FrontierJoin(_)
                | AuthorityOp::CustodyPermitPiece(_)
                | AuthorityOp::OwnerHandover(_)
                | AuthorityOp::MembershipExecution(_)
                | AuthorityOp::HomeCandidacy(_)
                | AuthorityOp::FederationLifecycle(_)
                | AuthorityOp::ResidenceDirective(_)
                | AuthorityOp::ResidenceResult(_)
        )
}

impl AuthorityCheckpointRow {
    /// The summary of covered row `row`, whose stored canonical signed body
    /// is `body`: the one place a builder marks a row's body required and
    /// carries it. With `every_body` (the image covers a sealed row) every
    /// row carries its body; a sealed row is never summarized without it.
    /// [`super::AuthorityCheckpointV2::compact_optional_evidence`] may drop
    /// residence bodies after (FIX 11400), never from such an image.
    ///
    /// # Errors
    /// A body whose scaffold does not verify or is not `row`'s, and a sealed
    /// row without `every_body`.
    pub(in crate::authority) fn of(row: &FoldRow, body: &[u8], every_body: bool) -> Result<Self> {
        let scaffold = verify_authority_log_entry_scaffold(body)?;
        if scaffold.hash != row.hash()? || (scaffold.sealed && !every_body) {
            return Err(Error::InvariantViolation("checkpoint image row summary"));
        }
        let body_required = every_body || row.op().is_some_and(carries_body);
        Ok(Self {
            signer: row.signer_key().clone(),
            seq: row.seq(),
            parents: row.parent_hashes().to_vec(),
            world: row
                .op()
                .and_then(crate::authority::world_privacy::side_world),
            slip_op: crate::authority::log_budget::is_slip_row(row),
            op_kind: scaffold.op_kind,
            sealed: scaffold.sealed,
            body_required,
            body: body_required.then(|| body.to_vec()),
        })
    }
}

/// One covered row's summary, checked alone: its body is present exactly
/// where it is marked required (FIX 2988), and a carried body is the row it
/// summarizes. With `every_body` (the image covers a sealed row) every row
/// carries its body. A residence row dropped for
/// [`super::AUTHORITY_RESIDENCE_BODY_OVERFLOW`] requires and carries none,
/// as before #4095 carried them (FIX 11400).
pub(super) fn shape_row(
    hash: &AuthorityEntryHash,
    row: &AuthorityCheckpointRow,
    every_body: bool,
) -> Result<()> {
    if row.body_required != row.body.is_some() || (every_body && row.body.is_none()) {
        return Err(refused("checkpoint image row body presence"));
    }
    match &row.body {
        Some(body) => row_body_matches(hash, row, body, every_body),
        None => Ok(()),
    }
}

/// A carried body is the canonical signed row its summary names, of the
/// kind and sealing its summary marks, carried whole as its summary marks
/// it. A sealed body is checked without custody: its public fields and its
/// signatures ([`verify_authority_public_row`]), never its record.
fn row_body_matches(
    hash: &AuthorityEntryHash,
    row: &AuthorityCheckpointRow,
    body: &[u8],
    every_body: bool,
) -> Result<()> {
    let (read, scaffold) = if authority_body_is_sealed(body)? {
        let public = verify_authority_public_row(body)?;
        let scaffold = public.scaffold().clone();
        (FoldRow::PassThrough(public), scaffold)
    } else {
        let entry = decode_authority_log_entry_body(body)?;
        (
            FoldRow::Open(entry),
            verify_authority_log_entry_scaffold(body)?,
        )
    };
    if scaffold.hash != *hash
        || scaffold.signer.public_key != row.signer
        || scaffold.seq != row.seq
        || scaffold.parent_hashes != row.parents
        || scaffold.op_kind != row.op_kind
        || scaffold.sealed != row.sealed
        || read
            .op()
            .and_then(crate::authority::world_privacy::side_world)
            != row.world
        || crate::authority::log_budget::is_slip_row(&read) != row.slip_op
        || (every_body || read.op().is_some_and(carries_body)) != row.body_required
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
