//! One durable step capture's owner witnesses (FIX 6734): the owners an erase takes the
//! capture for, keyed apart from the capture's bytes, so a capture whose row no longer
//! decodes is still taken when its full step key is valid. Prospective only: a capture kept
//! before this table existed has no witness, and none is rebuilt from its body.
//!
//! One row per (owner, role, capture): the key is the witness, the value empty. The capture
//! writer puts the actor and subject rows with the capture; the terminal bind replaces only
//! the claim row; every remover drops all of a deleted capture's rows, every role, in the
//! same writer. No own actor scrub: the capture eraser cleans these rows.

use super::{STEP_KEY_LEN, StepSourceKey};
use crate::attempt_queue::AttemptId;
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::{EntityId, Result};

/// What the witness's owner was to the step: the actor whose call it was, the subject the
/// step was about, or the terminal claim that logged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerRole {
    Actor,
    Subject,
    Claim,
}

impl OwnerRole {
    /// The role's byte in a witness key.
    fn byte(self) -> u8 {
        match self {
            Self::Actor => b'a',
            Self::Subject => b's',
            Self::Claim => b'c',
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'a' => Some(Self::Actor),
            b's' => Some(Self::Subject),
            b'c' => Some(Self::Claim),
            _ => None,
        }
    }
}

/// One owner witness's key: the owner, its role, and the capture's full step key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OwnerKey {
    owner: EntityId,
    role: OwnerRole,
    step: StepSourceKey,
}

/// A witness key's length after the table prefix: the owner, the role byte, and the step key.
const OWNER_KEY_LEN: usize = 16 + 1 + STEP_KEY_LEN;

impl SideKey for OwnerKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.owner.as_bytes());
        out.push(self.role.byte());
        self.step.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != OWNER_KEY_LEN {
            return None;
        }
        let (owner, rest) = bytes.split_at_checked(16)?;
        let (&role, step) = rest.split_first()?;
        Some(Self {
            owner: EntityId::from_bytes(owner.try_into().ok()?).ok()?,
            role: OwnerRole::from_byte(role)?,
            step: StepSourceKey::decode_key(step)?,
        })
    }
}

/// The owner witnesses. Key: [`OwnerKey`]; the value is empty, the key the witness.
const OWNERS: SideTable<OwnerKey, (), Raw> =
    SideTable::new(&side_table::COACH_BLOCKED_SOURCE_OWNER);

/// The actual owner named by a canonical witness's full stored key. Invalid roles or
/// partial step keys prove no owner.
pub(crate) fn blocked_capture_witness_owner(key: &[u8]) -> Option<EntityId> {
    let key = key.strip_prefix(OWNERS.decl().prefix)?;
    OwnerKey::decode_key(key).map(|witness| witness.owner)
}

/// Puts the actor and subject witnesses for the capture kept under `step`, in `wtxn`: the
/// row's actual owners, no claim yet.
pub(super) fn put_capture_owners_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    step: &StepSourceKey,
    actor: EntityId,
    subject: Option<EntityId>,
) -> Result<()> {
    OWNERS.put(
        store,
        wtxn,
        &OwnerKey {
            owner: actor,
            role: OwnerRole::Actor,
            step: *step,
        },
        &(),
    )?;
    if let Some(subject) = subject {
        OWNERS.put(
            store,
            wtxn,
            &OwnerKey {
                owner: subject,
                role: OwnerRole::Subject,
                step: *step,
            },
            &(),
        )?;
    }
    Ok(())
}

/// Replaces the claim witness for the exact capture `step`: drops every prior claim-role row
/// for it, then witnesses `claim`. Actor and subject rows stand, never inferred.
pub(super) fn replace_claim_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    step: &StepSourceKey,
    claim: EntityId,
) -> Result<()> {
    for key in claim_keys_of_in(store, &*wtxn, step)? {
        OWNERS.delete(store, wtxn, &key)?;
    }
    OWNERS.put(
        store,
        wtxn,
        &OwnerKey {
            owner: claim,
            role: OwnerRole::Claim,
            step: *step,
        },
        &(),
    )
}

/// Drops every witness for the exact capture `step`, every role, in `wtxn`.
pub(super) fn remove_capture_owners_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    step: &StepSourceKey,
) -> Result<()> {
    for key in keys_of_in(store, &*wtxn, step)? {
        OWNERS.delete(store, wtxn, &key)?;
    }
    Ok(())
}

/// Drops every witness for every capture of `attempt`'s `step`, each lease and call of it,
/// in `wtxn`.
pub(super) fn remove_step_owners_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    step: &[u8; 32],
) -> Result<()> {
    let mut keys = Vec::new();
    for row in OWNERS.iter_raw_from(store, &*wtxn, &[])? {
        let (key, _) = row?;
        if let Some(witness) = OwnerKey::decode_key(&key)
            && witness.step.attempt == attempt
            && witness.step.step == *step
        {
            keys.push(witness);
        }
    }
    for key in &keys {
        OWNERS.delete(store, wtxn, key)?;
    }
    Ok(())
}

/// Every step key `owner` witnesses, any role: the captures an erase of it takes even when
/// their rows no longer decode.
pub(super) fn steps_of_owner_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    owner: &EntityId,
) -> Result<Vec<StepSourceKey>> {
    let mut steps = Vec::new();
    for row in OWNERS.iter_raw_from(store, txn, owner.as_bytes())? {
        let (key, _) = row?;
        if let Some(witness) = OwnerKey::decode_key(&key) {
            steps.push(witness.step);
        }
    }
    Ok(steps)
}

/// Every owner witnessed for the exact capture `step`, any role, sorted and deduped.
pub(super) fn owners_of_capture_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    step: &StepSourceKey,
) -> Result<Vec<EntityId>> {
    let mut owners = Vec::new();
    for row in OWNERS.iter_raw_from(store, txn, &[])? {
        let (key, _) = row?;
        if let Some(witness) = OwnerKey::decode_key(&key)
            && witness.step == *step
        {
            owners.push(witness.owner);
        }
    }
    owners.sort_unstable();
    owners.dedup();
    Ok(owners)
}

/// Every witness key for the exact capture `step`, any role.
fn keys_of_in(store: &Store, txn: &heed::RoTxn<'_>, step: &StepSourceKey) -> Result<Vec<OwnerKey>> {
    let mut keys = Vec::new();
    for row in OWNERS.iter_raw_from(store, txn, &[])? {
        let (key, _) = row?;
        if let Some(witness) = OwnerKey::decode_key(&key)
            && witness.step == *step
        {
            keys.push(witness);
        }
    }
    Ok(keys)
}

/// Every claim-role witness key for the exact capture `step`.
fn claim_keys_of_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    step: &StepSourceKey,
) -> Result<Vec<OwnerKey>> {
    let mut keys = Vec::new();
    for row in OWNERS.iter_raw_from(store, txn, &[])? {
        let (key, _) = row?;
        if let Some(witness) = OwnerKey::decode_key(&key)
            && witness.role == OwnerRole::Claim
            && witness.step == *step
        {
            keys.push(witness);
        }
    }
    Ok(keys)
}
