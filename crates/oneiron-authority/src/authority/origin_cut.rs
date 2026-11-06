//! The owner's cut of a repository's origin authority (FIX 15740, Engine
//! 11-06 02:54; ARCH-0068: "Refs are SINGLE-WRITER PER REPO", "Cutover = an
//! authority epoch"), and its wire codec.
//!
//! When the owner cuts a served repository's origin authority on the host
//! that serves it, that host's install, a live machine of the vault in any
//! role, signs one cut per portable id the repository stands under, in the
//! same transaction as the host's own authority row. The cut carries the
//! portable id, his act ([`OwnerAct`], kind `origin_cut`, target the id
//! [`origin_cut_target`] derives from the portable id), the epoch the cut
//! opens and the one machine that writes the repository's refs at that
//! epoch. Its `seen` is the repository's live cuts as the cutting host read
//! them, under [`ORIGIN_CUT_REVISION_CONTEXT`]. It is a main-log entry, so
//! every machine the owner admits folds it and judges a carried repository
//! manifest against the exact epoch and writer.
//!
//! The record is shape only: an epoch of at least one and a writer machine.
//! Whether that machine still stands is each machine's own judgement when it
//! checks a manifest's signature. The cut is the owner's: no Grant action
//! names it, so an agent's act never makes it.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_ORIGIN_CUT: &str = "origin_cut";
const ORIGIN_CUT_KEYS: [&str; 6] = [
    OP_KEY_KIND,
    OP_KEY_ACT,
    "machine",
    "repo",
    "epoch",
    "writer",
];
/// The domain of an origin cut's `seen`, beside the home pick's
/// ([`HOME_PICK_REVISION_CONTEXT`]): BLAKE3 over it and the repository's
/// sorted live cut hashes, in the `PolicyRevision` shape.
pub const ORIGIN_CUT_REVISION_CONTEXT: &[u8] = b"oneiron/origin-cut-revision/v1";

/// The target an origin cut act names: an id derived from the repository's
/// 32-byte portable id, so every install names the same target and the act
/// binds the one repository the cut carries.
pub fn origin_cut_target(repo: &[u8; 32]) -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::ORIGIN_CUT_TARGET,
        &[repo.as_slice()],
    )
}

/// One owner cut of a repository's origin authority, signed by the install
/// key of `machine`, a live machine of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginCut {
    /// The owner's act: who decided, from which surface, on which of the
    /// repository's cut revisions. Its kind is `origin_cut` and its target
    /// [`origin_cut_target`] of `repo`.
    pub act: OwnerAct,
    /// The carrier: the machine whose install key signed the cut.
    pub machine: EntityId,
    /// The repository's portable id: 32 random bytes, minted once.
    pub repo: [u8; 32],
    /// The authority epoch the cut opens, never zero.
    pub epoch: u64,
    /// The one machine that writes the repository's refs at `epoch`.
    pub writer: EntityId,
}

impl OriginCut {
    pub fn validate(&self) -> Result<()> {
        // The cut is the owner's own: no Grant action names it, and no ask
        // answers it, so only his say-so makes it.
        if self.epoch == 0
            || self.act.act != OwnerActKind::OriginCut
            || self.act.by != ActBy::Owner
            || self.act.answer.is_some()
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// The act names the cut's own repository.
    pub fn validate_entry(&self, _entry: &AuthorityLogEntry) -> Result<()> {
        self.act
            .validate_carried(OwnerActKind::OriginCut, origin_cut_target(&self.repo)?)
    }
}

pub(super) fn origin_cut_value(cut: &OriginCut) -> Value {
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(OP_KIND_ORIGIN_CUT)),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&cut.act),
        ),
        (Value::from("machine"), Value::from(cut.machine.to_hex())),
        (
            Value::from("repo"),
            super::wire_encode::binary_value(cut.repo),
        ),
        (Value::from("epoch"), Value::from(cut.epoch)),
        (Value::from("writer"), Value::from(cut.writer.to_hex())),
    ])
}

/// A 32-byte repository id, a u64 epoch and a canonical writer id; the op's
/// shape check then refuses a zero epoch.
pub(super) fn decode_origin_cut(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &ORIGIN_CUT_KEYS)?;
    Ok(AuthorityOp::OriginCut(OriginCut {
        act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        repo: super::wire_decode::decode_hash(required(entries, "repo")?)?,
        epoch: required(entries, "epoch")?
            .as_u64()
            .ok_or_else(invalid_authority)?,
        writer: decode_canonical_id(required(entries, "writer")?)?,
    }))
}
