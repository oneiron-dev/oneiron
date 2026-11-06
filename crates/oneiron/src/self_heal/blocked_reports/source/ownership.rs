//! One durable capture's owner witnesses (FIX 6734), keyed apart from the capture's
//! bytes so an erase still takes a row whose value no longer decodes. Step captures
//! witness their actor, subject and terminal claim; receipt captures their reporter.
//! Prospective only: no witness is rebuilt from a capture kept before this inventory.
//!
//! One row per (owner, role, capture): the key is the witness, the value empty. The
//! capture writer keeps its witnesses in the same transaction. A replacement drops the
//! exact capture's previous witnesses; an erase drops them even if its row is gone.

use super::StepSourceKey;
use crate::attempt_queue::AttemptId;
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::{EntityId, Result};

/// The owner stamped by the capture: a step's actor, subject or terminal claim,
/// or a receipt's reporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerRole {
    Actor,
    Subject,
    Claim,
    Reporter,
}

impl OwnerRole {
    /// The role's byte in a witness key.
    fn byte(self) -> u8 {
        match self {
            Self::Actor => b'a',
            Self::Subject => b's',
            Self::Claim => b'c',
            Self::Reporter => b'r',
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'a' => Some(Self::Actor),
            b's' => Some(Self::Subject),
            b'c' => Some(Self::Claim),
            b'r' => Some(Self::Reporter),
            _ => None,
        }
    }
}

/// The exact capture named by a witness, never just a step or receipt prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureKey {
    Step(StepSourceKey),
    Receipt(EntityId),
}

/// One owner witness's key: the owner, its role, and the capture's full key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OwnerKey {
    owner: EntityId,
    role: OwnerRole,
    capture: CaptureKey,
}

impl SideKey for OwnerKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.owner.as_bytes());
        out.push(self.role.byte());
        match self.capture {
            CaptureKey::Step(step) => step.encode_into(out),
            CaptureKey::Receipt(receipt) => receipt.encode_into(out),
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (owner, rest) = bytes.split_at_checked(16)?;
        let (&role, capture) = rest.split_first()?;
        let role = OwnerRole::from_byte(role)?;
        let capture = match role {
            OwnerRole::Reporter => CaptureKey::Receipt(EntityId::decode_key(capture)?),
            OwnerRole::Actor | OwnerRole::Subject | OwnerRole::Claim => {
                CaptureKey::Step(StepSourceKey::decode_key(capture)?)
            }
        };
        Some(Self {
            owner: EntityId::from_bytes(owner.try_into().ok()?).ok()?,
            role,
            capture,
        })
    }
}

/// The owner witnesses. Key: [`OwnerKey`]; the value is empty, the key the witness.
const OWNERS: SideTable<OwnerKey, (), Raw> =
    SideTable::new(&side_table::COACH_BLOCKED_SOURCE_OWNER);

/// The actual owner named by a canonical witness's full stored key. Invalid roles or
/// partial capture keys prove no owner. Reporter roles name only receipts; the other
/// roles name only full step keys.
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
            capture: CaptureKey::Step(*step),
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
                capture: CaptureKey::Step(*step),
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
            capture: CaptureKey::Step(*step),
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
            && let CaptureKey::Step(capture) = witness.capture
            && capture.attempt == attempt
            && capture.step == *step
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
        if let Some(witness) = OwnerKey::decode_key(&key)
            && let CaptureKey::Step(step) = witness.capture
        {
            steps.push(step);
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
            && witness.capture == CaptureKey::Step(*step)
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
            && witness.capture == CaptureKey::Step(*step)
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
            && witness.capture == CaptureKey::Step(*step)
        {
            keys.push(witness);
        }
    }
    Ok(keys)
}

/// Replaces the exact receipt's witnesses with its final stored reporter, in the row's
/// own writer. Clearing even an absent row's witnesses prevents orphan inheritance.
pub(super) fn replace_receipt_reporter_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &EntityId,
    reporter: EntityId,
) -> Result<()> {
    remove_receipt_owners_in_txn(store, wtxn, receipt)?;
    OWNERS.put(
        store,
        wtxn,
        &OwnerKey {
            owner: reporter,
            role: OwnerRole::Reporter,
            capture: CaptureKey::Receipt(*receipt),
        },
        &(),
    )
}

/// Drops all witnesses of this exact receipt, including a row already gone.
pub(super) fn remove_receipt_owners_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &EntityId,
) -> Result<()> {
    for key in receipt_keys_in(store, &*wtxn, receipt)? {
        OWNERS.delete(store, wtxn, &key)?;
    }
    Ok(())
}

/// Every receipt whose reporter `owner` witnesses, even if its value no longer decodes.
pub(super) fn receipts_of_owner_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    owner: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut receipts = Vec::new();
    for row in OWNERS.iter_raw_from(store, txn, owner.as_bytes())? {
        let (key, _) = row?;
        if let Some(witness) = OwnerKey::decode_key(&key)
            && let CaptureKey::Receipt(receipt) = witness.capture
        {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

/// The reporters witnessed for this exact receipt, sorted and deduped.
pub(super) fn owners_of_receipt_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipt: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut owners: Vec<_> = receipt_keys_in(store, txn, receipt)?
        .into_iter()
        .map(|key| key.owner)
        .collect();
    owners.sort_unstable();
    owners.dedup();
    Ok(owners)
}

fn receipt_keys_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipt: &EntityId,
) -> Result<Vec<OwnerKey>> {
    let mut keys = Vec::new();
    for row in OWNERS.iter_raw_from(store, txn, &[])? {
        let (key, _) = row?;
        if let Some(witness) = OwnerKey::decode_key(&key)
            && witness.capture == CaptureKey::Receipt(*receipt)
        {
            keys.push(witness);
        }
    }
    Ok(keys)
}
