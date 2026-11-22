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
//! Its inline form carries the enrolment itself, the signer's act-free
//! roster revision of the install, in place of naming a held row, and its
//! `seen` is [`restored_machine_join_inline_seen`] of that revision. A kit
//! restore so files and joins the install in one row of its root authority
//! key R, as main's kit restore puts a machine on the roster in one R row:
//! two kit restores of copies of one image stay equal-sequence siblings, and
//! neither floors the other (Engine ANSWER KIT-JOIN-ONE-R-ROW = A).
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
/// The key of an inline join's enrolment: a `machine_profile` op's map.
const ENROLMENT_PROFILE_KEY: &str = "enrolment_profile";
const RESTORED_MACHINE_JOIN_INLINE_KEYS: [&str; 3] =
    [OP_KEY_KIND, OP_KEY_ACT, ENROLMENT_PROFILE_KEY];
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

/// The domain of an inline join's `seen`: BLAKE3 over it and the digest of
/// the enrolment the row carries.
pub const RESTORED_MACHINE_JOIN_INLINE_REVISION_CONTEXT: &[u8] =
    b"oneiron/restored-machine-join-inline-revision/v1";

/// The `seen` an inline join names: the revision of the enrolment it
/// carries, over that profile's wire bytes.
///
/// # Errors
/// A profile the wire encoding refuses.
pub fn restored_machine_join_inline_seen(profile: &MachineProfile) -> Result<[u8; 32]> {
    let bytes =
        super::wire_encode::encode_value(&super::machine_profile::machine_profile_value(profile))?;
    Ok(act_revision(
        RESTORED_MACHINE_JOIN_INLINE_REVISION_CONTEXT,
        [*blake3::hash(&bytes).as_bytes()],
    ))
}

/// The enrolment a restored machine join joins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoredJoinEnrolment {
    /// A held enrolment: an entry in the row's own ancestry.
    Held(AuthorityEntryHash),
    /// The enrolment itself: the signer's act-free roster revision of the
    /// machine, born of a restore, which the fold holds under this row and
    /// joins in the same transition.
    Inline(MachineProfile),
}

/// One owner join of a machine born of a restore, signed by an owner key of
/// the vault alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredMachineJoin {
    /// The owner's act: who decided, from which surface. Its kind is
    /// `restored_machine_join`, its target the joined machine, and its
    /// `seen` [`restored_machine_join_seen`] of a held `enrolment`, or
    /// [`restored_machine_join_inline_seen`] of an inline one.
    pub act: OwnerAct,
    /// The enrolment of the machine born of a restore that the act joins.
    pub enrolment: RestoredJoinEnrolment,
}

impl RestoredMachineJoin {
    /// The owner's own act on the enrolment it names: no Grant action names
    /// it and no ask answers it, so only his say-so makes it.
    /// An inline enrolment is an act-free revision of the act's target for
    /// the act's owner, born of a restore, that is no removal.
    pub fn validate(&self) -> Result<()> {
        let seen = match &self.enrolment {
            RestoredJoinEnrolment::Held(enrolment) => restored_machine_join_seen(enrolment),
            RestoredJoinEnrolment::Inline(profile) => {
                profile.validate()?;
                if profile.machine != self.act.target
                    || profile.owner != self.act.owner
                    || profile.restored_from.is_none()
                    || profile.carrier.is_some()
                    || profile.act.is_some()
                    || profile.role == MachineRole::Removed
                {
                    return Err(invalid_authority());
                }
                restored_machine_join_inline_seen(profile)?
            }
        };
        if self.act.act != OwnerActKind::RestoredMachineJoin
            || self.act.by != ActBy::Owner
            || self.act.answer.is_some()
            || self.act.seen != seen
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
        match &join.enrolment {
            RestoredJoinEnrolment::Held(enrolment) => (
                Value::from("enrolment"),
                super::wire_encode::binary_value(*enrolment),
            ),
            RestoredJoinEnrolment::Inline(profile) => (
                Value::from(ENROLMENT_PROFILE_KEY),
                super::machine_profile::machine_profile_value(profile),
            ),
        },
    ])
}

/// Strict: exactly the keys of one form, held or inline; the op's shape
/// check then pins the act's kind, author and `seen`.
pub(super) fn decode_restored_machine_join(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let inline = entries
        .iter()
        .any(|(key, _)| key.as_str() == Some(ENROLMENT_PROFILE_KEY));
    let enrolment = if inline {
        validate_keys(entries, &RESTORED_MACHINE_JOIN_INLINE_KEYS)?;
        let Value::Map(profile) = required(entries, ENROLMENT_PROFILE_KEY)? else {
            return Err(invalid_authority());
        };
        if required(profile, OP_KEY_KIND)?.as_str()
            != Some(super::machine_profile::OP_KIND_MACHINE_PROFILE)
        {
            return Err(invalid_authority());
        }
        let AuthorityOp::MachineProfile(profile) =
            super::machine_profile::decode_machine_profile(profile)?
        else {
            return Err(invalid_authority());
        };
        RestoredJoinEnrolment::Inline(profile)
    } else {
        validate_keys(entries, &RESTORED_MACHINE_JOIN_KEYS)?;
        RestoredJoinEnrolment::Held(super::wire_decode::decode_hash(required(
            entries,
            "enrolment",
        )?)?)
    };
    Ok(AuthorityOp::RestoredMachineJoin(RestoredMachineJoin {
        act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        enrolment,
    }))
}
