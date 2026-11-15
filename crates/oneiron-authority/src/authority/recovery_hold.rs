//! A box recovery's wait (OPUS-WAYBACK): the hold its door writes and the
//! answers owner devices and the kit sign (Engine RULING
//! WAYBACK-RECOVERY-HOLD-WIRE = A).
//!
//! After a box recovery (sign-in + recovery PIN) the recovered root's
//! authority key R does not vouch at once: the door writes one
//! [`RecoveryHold`] instead, signed by R alone, naming the successor's
//! enrolment input, the lost keys, the owner and the second the wait ends
//! (`lands_at`). The hold's entry hash is the attempt id, and the entry is
//! the owner-visible "recovery started, lands at <time>, cancel?" event
//! every owner device folds.
//!
//! Any other owner device ends the wait early or stops the attempt with one
//! [`RecoveryHoldAnswer`], signed by a live owner key other than the hold's
//! successor (a key the hold lists as lost still answers), and the kit stops
//! it with a `Cancel` the vault's anchor signs beside the hold root's
//! authority key R. R's cosign binds the Cancel to the hold's root: the hold
//! view counts it only for a hold R signed, so a foreign anchor's Cancel is
//! inert. R never answers a hold alone: the box releases R, so an R-signed
//! answer would end the wait for the attacker. The fold judges the signer
//! rules; the hold a door lands is an ordinary `OwnerKeyEnroll` +
//! `RevokeDevice` write at landing time, so a replica whose clock is behind
//! folds it as landed.
//!
//! Here are the rows' shape and signatures only. Whether a hold lands, and
//! what state it is in, is the fold view's judgement in
//! `oneiron::authority`.

use ed25519_dalek::Signature as Ed25519Signature;
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_RECOVERY_HOLD: &str = "recovery_hold";
pub const OP_KIND_RECOVERY_HOLD_ANSWER: &str = "recovery_hold_answer";
const RECOVERY_HOLD_KEYS: [&str; 5] = [OP_KEY_KIND, "owner", "enrolment", "lost", "lands_at"];
const RECOVERY_HOLD_ENROLMENT_KEYS: [&str; 3] = ["machine", "public_key", "proof"];
const RECOVERY_HOLD_ANSWER_KEYS: [&str; 3] = [OP_KEY_KIND, "hold", "answer"];

/// The wire spelling of [`RecoveryHoldAnswerKind::Cancel`].
pub const RECOVERY_HOLD_ANSWER_CANCEL: &str = "cancel";
/// The wire spelling of [`RecoveryHoldAnswerKind::ItIsMe`].
pub const RECOVERY_HOLD_ANSWER_IT_IS_ME: &str = "it_is_me";

/// The successor's enrolment input as the vouch path builds it: the machine
/// that holds the key, the key's Ed25519 bytes, and the key's proof of
/// possession over its challenge for this vault, machine, key and owner. The
/// challenge is time-free, so a held input never goes stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryHoldEnrolment {
    /// The machine that holds the successor key.
    pub machine: EntityId,
    /// The successor key.
    pub public_key: [u8; 32],
    /// The successor key's proof of possession.
    pub proof: Vec<u8>,
}

/// One box recovery's wait, signed by the recovered root's authority key R
/// alone: the enrolment and revocations it holds, and the second they land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryHold {
    /// The owner whose act the landing enrols under: the proof binds them,
    /// and the landing (which runs with no owner proof) rebuilds the act
    /// for them.
    pub owner: EntityId,
    /// The successor's enrolment input, held verbatim until landing.
    pub enrolment: RecoveryHoldEnrolment,
    /// The lost keys the landing revokes, each once, never the successor.
    pub lost: Vec<AuthorityKey>,
    /// Unix seconds the wait ends at, on the door install's clock: its
    /// `instant_in_write_txn` reading at the hold plus the wait.
    pub lands_at: u64,
}

impl RecoveryHold {
    /// The successor key as the roster names it.
    #[must_use]
    pub fn successor_key(&self) -> AuthorityKey {
        AuthorityKey::Ed25519(self.enrolment.public_key)
    }

    /// The fixed shape: a bound owner and machine, a 64-byte proof, a
    /// non-zero landing second, valid lost keys with no repeat and never
    /// the successor.
    pub fn validate(&self) -> Result<()> {
        if *self.owner.as_bytes() == [0; 16]
            || *self.enrolment.machine.as_bytes() == [0; 16]
            || self.enrolment.proof.len() != OWNER_KEY_POSSESSION_PROOF_LEN
            || self.lands_at == 0
        {
            return Err(invalid_authority());
        }
        for key in &self.lost {
            key.validate()?;
        }
        let mut seen = std::collections::BTreeSet::new();
        for key in &self.lost {
            if *key == self.successor_key() || !seen.insert(key.clone()) {
                return Err(invalid_authority());
            }
        }
        Ok(())
    }

    /// The entry the hold rides: an Ed25519 primary signer alone, with no
    /// cosign; and the successor key's proof of possession verifies strictly
    /// over this vault's enrolment challenge for the hold's machine, key
    /// and owner, as the landing's enrolment will check it again.
    pub fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        let vault_id = entry.vault_id.ok_or_else(invalid_authority)?;
        if entry.signer.suite != AuthoritySignatureSuite::Ed25519
            || !matches!(entry.signer.public_key, AuthorityKey::Ed25519(_))
            || !entry.cosigns.is_empty()
        {
            return Err(invalid_authority());
        }
        let challenge = owner_key_enrollment_challenge(
            &vault_id,
            self.enrolment.machine,
            &self.enrolment.public_key,
            self.owner,
        )?;
        let proof: [u8; OWNER_KEY_POSSESSION_PROOF_LEN] = self
            .enrolment
            .proof
            .as_slice()
            .try_into()
            .map_err(|_| invalid_authority())?;
        strong_ed25519_key(&self.enrolment.public_key)?
            .verify_strict(&challenge, &Ed25519Signature::from_bytes(&proof))
            .map_err(|_| invalid_authority())
    }
}

/// What an answer says about the hold it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryHoldAnswerKind {
    /// Stop the attempt: it never lands. Wins over [`Self::ItIsMe`] in
    /// either order, and no later answer revives the hold.
    Cancel,
    /// The owner confirms the attempt: it is due at once and lands at the
    /// seed holder's next call.
    ItIsMe,
}

impl RecoveryHoldAnswerKind {
    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cancel => RECOVERY_HOLD_ANSWER_CANCEL,
            Self::ItIsMe => RECOVERY_HOLD_ANSWER_IT_IS_ME,
        }
    }

    /// The wire spelling read back.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            RECOVERY_HOLD_ANSWER_CANCEL => Some(Self::Cancel),
            RECOVERY_HOLD_ANSWER_IT_IS_ME => Some(Self::ItIsMe),
            _ => None,
        }
    }
}

/// One answer to a recovery hold: `hold`'s attempt id and what the answer
/// says. Signed by a live owner key other than the hold's successor, or, for
/// `Cancel` only, by the vault's anchor beside the hold root's authority key
/// R, whose cosign binds the Cancel to the hold's root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryHoldAnswer {
    /// The hold's entry hash: the attempt id.
    pub hold: AuthorityEntryHash,
    /// What the answer says.
    pub answer: RecoveryHoldAnswerKind,
}

impl RecoveryHoldAnswer {
    /// The fixed shape: the hold names an entry.
    pub fn validate(&self) -> Result<()> {
        if self.hold == [0; 32] {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// The entry the answer rides: an Ed25519 primary signer, with an
    /// `ItIsMe` carrying no cosign and a `Cancel` carrying no cosign (a
    /// roster key's) or exactly one Ed25519 cosign (the kit's: the anchor
    /// signs beside R). Whether the signer may answer (a live
    /// non-successor owner key with no cosign, or the anchor with R's) is
    /// the fold's judgement.
    pub fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        if entry.signer.suite != AuthoritySignatureSuite::Ed25519
            || !matches!(entry.signer.public_key, AuthorityKey::Ed25519(_))
        {
            return Err(invalid_authority());
        }
        match (self.answer, entry.cosigns.as_slice()) {
            (RecoveryHoldAnswerKind::ItIsMe, []) => Ok(()),
            (RecoveryHoldAnswerKind::Cancel, []) => Ok(()),
            (RecoveryHoldAnswerKind::Cancel, [cosign])
                if cosign.suite == AuthoritySignatureSuite::Ed25519
                    && matches!(cosign.public_key, AuthorityKey::Ed25519(_)) =>
            {
                Ok(())
            }
            _ => Err(invalid_authority()),
        }
    }
}

pub(super) fn recovery_hold_value(hold: &RecoveryHold) -> Value {
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(OP_KIND_RECOVERY_HOLD)),
        (Value::from("owner"), Value::from(hold.owner.to_hex())),
        (
            Value::from("enrolment"),
            Value::Map(vec![
                (
                    Value::from("machine"),
                    Value::from(hold.enrolment.machine.to_hex()),
                ),
                (
                    Value::from("public_key"),
                    binary_value(hold.enrolment.public_key),
                ),
                (
                    Value::from("proof"),
                    Value::Binary(hold.enrolment.proof.clone()),
                ),
            ]),
        ),
        (
            Value::from("lost"),
            Value::Array(hold.lost.iter().map(key_value).collect()),
        ),
        (Value::from("lands_at"), Value::from(hold.lands_at)),
    ])
}

/// Strict: exactly the op's keys, and exactly the enrolment's; the op's
/// shape check then pins the fields, and the envelope's canonical re-encode
/// every value's form.
pub(super) fn decode_recovery_hold(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &RECOVERY_HOLD_KEYS)?;
    let enrolment = map_entries(required(entries, "enrolment")?)?;
    validate_keys(enrolment, &RECOVERY_HOLD_ENROLMENT_KEYS)?;
    let lost = match required(entries, "lost")? {
        Value::Array(keys) => keys.iter().map(decode_key).collect::<Result<Vec<_>>>()?,
        _ => return Err(invalid_authority()),
    };
    Ok(AuthorityOp::RecoveryHold(RecoveryHold {
        owner: decode_canonical_id(required(entries, "owner")?)?,
        enrolment: RecoveryHoldEnrolment {
            machine: decode_canonical_id(required(enrolment, "machine")?)?,
            public_key: decode_hash(required(enrolment, "public_key")?)?,
            proof: match required(enrolment, "proof")? {
                Value::Binary(proof) => proof.clone(),
                _ => return Err(invalid_authority()),
            },
        },
        lost,
        lands_at: required(entries, "lands_at")?
            .as_u64()
            .ok_or_else(invalid_authority)?,
    }))
}

pub(super) fn recovery_hold_answer_value(answer: &RecoveryHoldAnswer) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_RECOVERY_HOLD_ANSWER),
        ),
        (Value::from("hold"), binary_value(answer.hold)),
        (Value::from("answer"), Value::from(answer.answer.as_str())),
    ])
}

/// Strict: exactly the op's keys; the op's shape check then pins the hold,
/// and the envelope's canonical re-encode every value's form.
pub(super) fn decode_recovery_hold_answer(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &RECOVERY_HOLD_ANSWER_KEYS)?;
    Ok(AuthorityOp::RecoveryHoldAnswer(RecoveryHoldAnswer {
        hold: decode_hash(required(entries, "hold")?)?,
        answer: required(entries, "answer")?
            .as_str()
            .and_then(RecoveryHoldAnswerKind::parse)
            .ok_or_else(invalid_authority)?,
    }))
}
