//! The carried form of a binding and a policy revision (Engine A, 6 Nov
//! 03:46): the keys and the bytes a window's `source_audiences` map and a
//! canonical recovery artifact hold, in canonical lowercase hex and Named
//! MessagePack. A value is taken only in its canonical form: its bytes
//! re-encode to themselves, and a policy's revision is its key's.
//!
//! - `record/<row>`: the policy id the row is bound to;
//! - `policy/<policy>/<revision>`: one revision of a policy, the revision
//!   spelled in sixteen hex digits;
//! - `withheld/<row>`: the row left the window after it travelled, and the
//!   machine that withheld it (none for a vault's founding install);
//! - `event/<policy>/<revision>`: the receipt of the change that made that
//!   revision of the policy (fix list row 17205), the revision spelled as a
//!   policy key spells it.

use super::{SourceAudienceEvent, SourceAudienceKind, SourceAudiencePolicy};
use crate::EntityId;
use crate::error::{Error, Result};

/// A bound row's binding: `record/<row>`.
const RECORD: &str = "record/";
/// One revision of a policy: `policy/<policy>/<revision>`.
const POLICY: &str = "policy/";
/// A row withheld after it travelled: `withheld/<row>`.
const WITHHELD: &str = "withheld/";
/// The receipt of one change to a policy: `event/<policy>/<revision>`.
const EVENT: &str = "event/";
/// The hex digits a revision is spelled in.
const REVISION_DIGITS: usize = 16;

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("source audience carrier refused: {reason}"))
}

/// What a carried key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CarrierKey {
    Record(EntityId),
    Policy(EntityId, u64),
    Withheld(EntityId),
    Event(EntityId, u64),
}

/// `hex` as an id, when it is the id's canonical spelling.
pub(crate) fn named(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

/// What `map_key` names, when it is a key in its canonical spelling.
pub(crate) fn parse_key(map_key: &str) -> Option<CarrierKey> {
    if let Some(row) = map_key.strip_prefix(RECORD) {
        return named(row).map(CarrierKey::Record);
    }
    if let Some(row) = map_key.strip_prefix(WITHHELD) {
        return named(row).map(CarrierKey::Withheld);
    }
    if let Some(rest) = map_key.strip_prefix(EVENT) {
        let (policy, revision) = revision_of(rest)?;
        return Some(CarrierKey::Event(policy, revision));
    }
    let (policy, revision) = revision_of(map_key.strip_prefix(POLICY)?)?;
    Some(CarrierKey::Policy(policy, revision))
}

/// The policy and the revision `rest` spells, `<policy>/<revision>`, when
/// both are in their canonical spelling.
fn revision_of(rest: &str) -> Option<(EntityId, u64)> {
    let (policy, revision) = rest.split_once('/')?;
    if revision.len() != REVISION_DIGITS
        || !revision
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let revision = u64::from_str_radix(revision, 16).ok()?;
    Some((named(policy)?, revision))
}

/// The key of `row`'s binding.
pub(crate) fn record_key(row: &EntityId) -> String {
    format!("{RECORD}{}", row.to_hex())
}

/// The key of `row`'s withholding marker.
pub(crate) fn withheld_key(row: &EntityId) -> String {
    format!("{WITHHELD}{}", row.to_hex())
}

/// The key of one revision of `policy`.
pub(crate) fn policy_key(policy: &EntityId, revision: u64) -> String {
    format!("{}{revision:016x}", policy_prefix(policy))
}

/// The prefix every revision key of `policy` starts with.
pub(crate) fn policy_prefix(policy: &EntityId) -> String {
    format!("{POLICY}{}/", policy.to_hex())
}

/// The key of the receipt of the change that made revision `revision` of
/// `policy`.
pub(crate) fn event_key(policy: &EntityId, revision: u64) -> String {
    format!("{EVENT}{}/{revision:016x}", policy.to_hex())
}

/// A binding's carried bytes.
pub(crate) fn encode_binding(policy: &EntityId) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(policy).map_err(|_| refused("a binding does not encode"))
}

/// A policy revision's carried bytes.
pub(crate) fn encode_policy(policy: &SourceAudiencePolicy) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(policy).map_err(|_| refused("a policy does not encode"))
}

/// A withholding marker's carried bytes: the machine that withheld the row.
pub(crate) fn encode_withheld(by: Option<&EntityId>) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(&by).map_err(|_| refused("a withholding marker does not encode"))
}

/// A change receipt's carried bytes.
pub(crate) fn encode_event(event: &SourceAudienceEvent) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(event).map_err(|_| refused("a change receipt does not encode"))
}

/// One carried entry, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Carrier {
    Record {
        row: EntityId,
        policy: EntityId,
    },
    Policy {
        id: EntityId,
        policy: SourceAudiencePolicy,
    },
    /// The row left the window after it travelled: `by`, the machine that
    /// withheld it, reads it by its own walk, and every other holder reads
    /// it to no one until its carrier comes back.
    Withheld {
        row: EntityId,
        by: Option<EntityId>,
    },
    /// The receipt of the change that made revision `revision` of `policy`:
    /// it rides beside the policy, so a replica knows who shared a thread.
    Event {
        policy: EntityId,
        revision: u64,
        event: SourceAudienceEvent,
    },
}

/// The entry `bytes` filed under `map_key`, when it is its key's canonical
/// form: the bytes re-encode to themselves, a policy's revision is its
/// key's, and a thread policy names a source other than itself.
pub(crate) fn carrier(map_key: &str, bytes: &[u8]) -> Result<Carrier> {
    match parse_key(map_key).ok_or_else(|| refused("a key it does not spell"))? {
        CarrierKey::Record(row) => {
            let policy: EntityId =
                rmp_serde::from_slice(bytes).map_err(|_| refused("a binding does not decode"))?;
            if encode_binding(&policy)? != bytes {
                return Err(refused("a binding not in its canonical form"));
            }
            Ok(Carrier::Record { row, policy })
        }
        CarrierKey::Policy(id, revision) => {
            let policy: SourceAudiencePolicy =
                rmp_serde::from_slice(bytes).map_err(|_| refused("a policy does not decode"))?;
            if encode_policy(&policy)? != bytes {
                return Err(refused("a policy not in its canonical form"));
            }
            if policy.revision != revision {
                return Err(refused("a policy filed under another revision"));
            }
            if matches!(&policy.kind, SourceAudienceKind::Thread { source, .. } if *source == id) {
                return Err(refused("a thread policy of itself"));
            }
            Ok(Carrier::Policy { id, policy })
        }
        CarrierKey::Withheld(row) => {
            let by: Option<EntityId> = rmp_serde::from_slice(bytes)
                .map_err(|_| refused("a withholding marker does not decode"))?;
            if encode_withheld(by.as_ref())? != bytes {
                return Err(refused("a withholding marker not in its canonical form"));
            }
            Ok(Carrier::Withheld { row, by })
        }
        CarrierKey::Event(policy, revision) => {
            let event: SourceAudienceEvent = rmp_serde::from_slice(bytes)
                .map_err(|_| refused("a change receipt does not decode"))?;
            if encode_event(&event)? != bytes {
                return Err(refused("a change receipt not in its canonical form"));
            }
            Ok(Carrier::Event {
                policy,
                revision,
                event,
            })
        }
    }
}
