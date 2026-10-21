//! The owner's choice of his vault's checkpoint root policy (mesh PR2c, §A
//! 06, K06), and its wire codec.
//!
//! The owner selects which roots attest his authority checkpoint images, and
//! how many of them must, from any surface where he is authenticated, on any
//! host, Hosted included (the owner's ruling, 10-19: "it doesn't matter where
//! you said yes, if you said so"). The install that served him, a live
//! machine of the vault in any role, signs the choice with its install key;
//! the choice carries his act ([`OwnerAct`], kind `checkpoint_policy`, target
//! the vault: [`checkpoint_policy_target`]) and its `seen` is the vault's
//! live choices as the deciding surface showed them
//! ([`checkpoint_policy_revision`]). It is a main-log entry, so every machine
//! the owner admits folds it.
//!
//! The record is shape only: the roots ascending and distinct, a quorum they
//! can meet. Whether each key is an eligible root, and whether the quorum
//! meets the canon floor, is the policy's rule, judged against the roster
//! (`oneiron::authority::CheckpointRootPolicy::from_choice`). The checkpoint
//! root policy is the owner's: no Grant action names it, so an agent's act
//! never selects it.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_CHECKPOINT_POLICY: &str = "checkpoint_policy";
const CHECKPOINT_POLICY_KEYS: [&str; 4] = [OP_KEY_KIND, OP_KEY_ACT, "machine", "choice"];
const CHECKPOINT_CHOICE_KEYS: [&str; 3] = ["roots", "quorum", "hardware"];
/// The domain of a checkpoint policy act's `seen`, beside the grant travel
/// and machine answer ones: BLAKE3 over it and the vault's sorted live
/// choice hashes, in the `PolicyRevision` shape.
pub const CHECKPOINT_POLICY_REVISION_CONTEXT: &[u8] = b"oneiron/checkpoint-policy-revision/v1";

/// A checkpoint policy act's `seen` over the vault's live choices, zero for
/// a vault no choice names.
#[must_use]
pub fn checkpoint_policy_revision(live: impl IntoIterator<Item = AuthorityEntryHash>) -> [u8; 32] {
    super::owner_act::act_revision(CHECKPOINT_POLICY_REVISION_CONTEXT, live)
}

/// The target a checkpoint policy act names: the vault itself, as the
/// content-addressed id of its genesis row (the vault id is that row's
/// hash), so every install names the same target.
pub fn checkpoint_policy_target(vault_id: &AuthorityVaultId) -> Result<EntityId> {
    authority_log_entity_id_from_hash(vault_id)
}

/// The roots the owner chose and how many of them must attest.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRootChoice {
    /// Ascending and distinct, at least one.
    pub roots: Vec<AuthorityKey>,
    /// Distinct chosen roots that must attest: at least one, at most the
    /// roots named.
    pub quorum: u8,
    /// One attesting root must be hardware-backed. The policy also requires
    /// it whenever a chosen root is (`CHECKPOINT_HARDWARE_WHEN_ELIGIBLE`).
    pub hardware: bool,
}

impl CheckpointRootChoice {
    /// Canonical or refused: roots ascending, distinct and well formed, and
    /// a quorum between one and the roots named. However many roots a choice
    /// names, it is never refused for their count (Phase2 A, FIX 7909): the
    /// quorum alone is one byte, and the writer measures the roots.
    pub fn validate(&self) -> Result<()> {
        if self.roots.is_empty()
            || self.quorum == 0
            || usize::from(self.quorum) > self.roots.len()
            || self.roots.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid_authority());
        }
        self.roots.iter().try_for_each(AuthorityKey::validate)
    }
}

/// One owner choice of the vault's checkpoint root policy, signed by the
/// install key of `machine`, a live machine of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointPolicySet {
    /// The owner's act: who decided, from which surface, on which of the
    /// vault's policy revisions. Its kind is `checkpoint_policy` and its
    /// target the vault ([`checkpoint_policy_target`]).
    pub act: OwnerAct,
    /// The carrier: the machine whose install key signed the choice.
    pub machine: EntityId,
    /// The roots and quorum the owner chose. `None` clears his choice: the
    /// policy the vault's hosting posture fixes holds again.
    pub choice: Option<CheckpointRootChoice>,
}

impl CheckpointPolicySet {
    pub fn validate(&self) -> Result<()> {
        if let Some(choice) = &self.choice {
            choice.validate()?;
        }
        // The checkpoint root policy is the owner's own: no Grant action
        // names it, and no ask answers it, so only his say-so selects it.
        if self.act.act != OwnerActKind::CheckpointPolicy
            || self.act.by != ActBy::Owner
            || self.act.answer.is_some()
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// The act names the entry's own vault.
    pub fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        let vault_id = entry.vault_id.ok_or_else(invalid_authority)?;
        self.act.validate_carried(
            OwnerActKind::CheckpointPolicy,
            checkpoint_policy_target(&vault_id)?,
        )
    }
}

pub(super) fn checkpoint_policy_value(set: &CheckpointPolicySet) -> Value {
    let choice = match &set.choice {
        None => Value::Nil,
        Some(choice) => Value::Map(vec![
            (
                Value::from("roots"),
                Value::Array(choice.roots.iter().map(key_value).collect()),
            ),
            (Value::from("quorum"), Value::from(u64::from(choice.quorum))),
            (Value::from("hardware"), Value::from(choice.hardware)),
        ]),
    };
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_CHECKPOINT_POLICY),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&set.act),
        ),
        (Value::from("machine"), Value::from(set.machine.to_hex())),
        (Value::from("choice"), choice),
    ])
}

/// The roots as written, each once; the op's shape check then pins their
/// order and the quorum's range.
pub(super) fn decode_checkpoint_policy(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &CHECKPOINT_POLICY_KEYS)?;
    let choice = match required(entries, "choice")? {
        Value::Nil => None,
        value => {
            let fields = map_entries(value)?;
            validate_keys(fields, &CHECKPOINT_CHOICE_KEYS)?;
            let Value::Array(keys) = required(fields, "roots")? else {
                return Err(invalid_authority());
            };
            let mut seen = BTreeSet::new();
            let mut roots = Vec::with_capacity(keys.len());
            for key in keys {
                let key = decode_key(key)?;
                if !seen.insert(key.clone()) {
                    return Err(invalid_authority());
                }
                roots.push(key);
            }
            let quorum = required(fields, "quorum")?
                .as_u64()
                .and_then(|quorum| u8::try_from(quorum).ok())
                .ok_or_else(invalid_authority)?;
            let hardware = required(fields, "hardware")?
                .as_bool()
                .ok_or_else(invalid_authority)?;
            Some(CheckpointRootChoice {
                roots,
                quorum,
                hardware,
            })
        }
    };
    Ok(AuthorityOp::CheckpointPolicySet(CheckpointPolicySet {
        act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        choice,
    }))
}
