//! The owner's word that no other machine of the vault is left, which joins
//! one machine born of a restore (row RESTORED-COPIES-ENROL-EACH-OTHER;
//! Setting DESIGN pass 15e "Joined", second way; RULING
//! RESTORED-COPIES-JOIN-SCOPE = A), and its wire codec.
//!
//! A copy restored from a checkpoint image is not a machine of the vault
//! until a machine that has joined joins it. When no such machine is left
//! (the owner lost every device), the owner says so: one row names the
//! held enrolment of the install he is on, and the act ([`OwnerAct`], kind
//! `restored_machine_join`) targets that enrolment's machine. Its `seen` is
//! [`restored_machine_join_seen`] of the enrolment, so the act binds the one
//! enrolment it was decided on. It is an owner act, so it is proved like one
//! (CARRIER-SELF-ANSWER): a key the vault trusts as the owner's signs it
//! alone, with no carrier, since the copy carries nothing before it joins.
//!
//! The record is shape only. Whether its signer proves the owner's will,
//! and whether its enrolment is one the fold holds for that machine, are the
//! fold's judgement in `oneiron::authority`. No Grant action names it, so an
//! agent's act never makes it.

use rmpv::Value;

use crate::error::Result;

use super::*;

pub const OP_KIND_RESTORED_MACHINE_JOIN: &str = "restored_machine_join";
const RESTORED_MACHINE_JOIN_KEYS: [&str; 3] = [OP_KEY_KIND, OP_KEY_ACT, "enrolment"];
/// The domain of a restored machine join's `seen`, in the `PolicyRevision`
/// shape: BLAKE3 over it and the one enrolment the act joins.
pub const RESTORED_MACHINE_JOIN_REVISION_CONTEXT: &[u8] =
    b"oneiron/restored-machine-join-revision/v1";

/// The `seen` a restored machine join names: the revision of the one held
/// enrolment it joins.
#[must_use]
pub fn restored_machine_join_seen(enrolment: &AuthorityEntryHash) -> [u8; 32] {
    act_revision(RESTORED_MACHINE_JOIN_REVISION_CONTEXT, [*enrolment])
}

/// One owner join of a machine born of a restore, signed by an owner key of
/// the vault alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredMachineJoin {
    /// The owner's act: who decided, from which surface. Its kind is
    /// `restored_machine_join`, its target the joined machine, and its
    /// `seen` [`restored_machine_join_seen`] of `enrolment`.
    pub act: OwnerAct,
    /// The held enrolment of the machine born of a restore that the act
    /// joins: an entry in the row's own ancestry.
    pub enrolment: AuthorityEntryHash,
}

impl RestoredMachineJoin {
    /// The owner's own act on the enrolment it names: no Grant action names
    /// it and no ask answers it, so only his say-so makes it.
    pub fn validate(&self) -> Result<()> {
        if self.act.act != OwnerActKind::RestoredMachineJoin
            || self.act.by != ActBy::Owner
            || self.act.answer.is_some()
            || self.act.seen != restored_machine_join_seen(&self.enrolment)
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// The entry the record rides: an Ed25519 primary signer alone, with no
    /// cosign. The fold reads the enrolment in its parents' state.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        if entry.signer.suite != AuthoritySignatureSuite::Ed25519
            || !matches!(entry.signer.public_key, AuthorityKey::Ed25519(_))
            || !entry.cosigns.is_empty()
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

pub(super) fn restored_machine_join_value(join: &RestoredMachineJoin) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_RESTORED_MACHINE_JOIN),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&join.act),
        ),
        (
            Value::from("enrolment"),
            super::wire_encode::binary_value(join.enrolment),
        ),
    ])
}

/// Strict: exactly the op's keys; the op's shape check then pins the act's
/// kind, author and `seen`.
pub(super) fn decode_restored_machine_join(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &RESTORED_MACHINE_JOIN_KEYS)?;
    Ok(AuthorityOp::RestoredMachineJoin(RestoredMachineJoin {
        act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        enrolment: super::wire_decode::decode_hash(required(entries, "enrolment")?)?,
    }))
}
