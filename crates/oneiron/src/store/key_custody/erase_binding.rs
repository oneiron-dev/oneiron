//! The custody retirements one erase owes, bound by name on its receipt (FIX
//! 5844, C-ERASE-FINAL): read in the erase's own transaction once everything
//! it retires is staged, and checked later for having finished everywhere
//! they must. A name is `<kind tag>.<item hex>.<through hex>`: an item's id
//! and a generation, never a key, a wrap or a value's fingerprint. The
//! journal's own obligations and progress stay the evidence; nothing here
//! journals or refuses anything.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use super::identity::{CustodyKind, CustodySubject, hex_decode};
use super::retirement::{RetireCause, retirement_in_txn, retirements_in_txn};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

/// The kinds an erase stages retirements of: its records' claim keys and
/// known-value history, the body instances it retired or owes, the pads of
/// a world it erased or of a pad row it erased, and an erased credential's
/// value and carrier keys (KS-6 part 2), matched by the credential's id as
/// their items' first 16 bytes.
const ERASE_KINDS: [CustodyKind; 7] = [
    CustodyKind::ClaimDecision,
    CustodyKind::KnownValueEntry,
    CustodyKind::BodyInstance,
    CustodyKind::WorldPad,
    CustodyKind::CredentialValue,
    CustodyKind::CustodyTransition,
    CustodyKind::CustodyRequestInput,
];

/// Whether `kind` is one an erased credential's id names (KS-6 part 2):
/// its retirements are one obligation, its credential's whole erase.
fn credential_parent_kind(kind: CustodyKind) -> bool {
    matches!(
        kind,
        CustodyKind::CredentialValue
            | CustodyKind::CustodyTransition
            | CustodyKind::CustodyRequestInput
    )
}

/// The generation an erased credential's value name carries when no intent
/// of its value was bound: the name stands for its whole erase alone.
const PARENT_ONLY: u64 = u64::MAX;

/// `<kind tag>.<item hex>.<through hex>`.
fn retirement_name(subject: &CustodySubject, through: u64) -> String {
    format!(
        "{:02x}.{}.{through:016x}",
        subject.kind().tag(),
        crate::entity_id::bytes_to_hex_lower(subject.item())
    )
}

/// The kind, item and generation a bound retirement's name names; `None`
/// for a name custody would not write: lowercase hex only, an item of its
/// kind's width.
fn retirement_of_name(name: &str) -> Option<(CustodyKind, Vec<u8>, u64)> {
    let mut parts = name.split('.');
    let (tag, item, through) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || through.len() != 16 {
        return None;
    }
    let [tag] = <[u8; 1]>::try_from(hex_decode(tag)?).ok()?;
    let kind = CustodyKind::from_tag(tag)?;
    let item = hex_decode(item)?;
    let through = u64::from_str_radix(through, 16).ok()?;
    let canonical = format!(
        "{tag:02x}.{}.{through:016x}",
        crate::entity_id::bytes_to_hex_lower(&item)
    );
    (item.len() == kind.item_len() && canonical == name).then_some((kind, item, through))
}

/// Whether the pad `item` (its key's full id) is of a world among
/// `records`, or its key's pad row is one of them.
fn pad_of(records: &BTreeSet<&[u8]>, item: &[u8]) -> bool {
    let row = crate::world_keys::pad_row_of_item(item);
    matches!(item.get(..16), Some(world) if records.contains(world))
        || matches!(row, Ok(Some(row)) if records.contains(row.as_bytes().as_slice()))
}

impl Store {
    /// Whether `name` is a bound custody retirement's name, as an erase
    /// receipt carries it: the receipt grammar's check.
    pub(crate) fn erase_retirement_name_valid(name: &str) -> bool {
        retirement_of_name(name).is_some()
    }

    /// The custody retirements an erase of `erased` (its whole scope) owes,
    /// by name, in ascending order, read in the erase's own transaction once
    /// everything it retires is staged: each erase intent standing for a
    /// record's claim key or known-value history, or for a pad of a world or
    /// pad row it erased, and each body instance the erase retired or owes
    /// (one another holder keeps waits on that holder, KS-2A), through the
    /// newest generation it retires. Each credential it fenced owes its
    /// whole erase too, under its value's name, even with no key found yet
    /// (KS-6 part 2): its discovery and every key its id names, as late as
    /// they are found. Empty when the erase owes none here, no custody bound
    /// included: its explicit `not required`.
    ///
    /// # Errors
    ///
    /// Storage and custody faults.
    pub(crate) fn erase_custody_retirements_in_txn(
        &self,
        txn: &RoTxn<'_>,
        erased: &[EntityId],
    ) -> Result<Vec<String>> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(Vec::new());
        };
        let records: BTreeSet<&[u8]> = erased.iter().map(|id| id.as_bytes().as_slice()).collect();
        let mut owed: BTreeMap<CustodySubject, u64> = BTreeMap::new();
        #[cfg(unix)]
        for record in erased {
            for instance in self.erased_body_instances_in_txn(txn, record)? {
                let id = crate::store::instance_id(custody.binding(), &instance)?;
                owed.insert(id.subject().clone(), id.generation());
            }
        }
        #[cfg(not(unix))]
        let _ = custody;
        for kind in ERASE_KINDS {
            for intent in retirements_in_txn(self, txn, kind)? {
                let ours = match kind {
                    CustodyKind::BodyInstance => owed.contains_key(&intent.subject),
                    CustodyKind::WorldPad => pad_of(&records, intent.subject.item()),
                    kind if credential_parent_kind(kind) => intent
                        .subject
                        .item()
                        .get(..16)
                        .is_some_and(|parent| records.contains(parent)),
                    _ => records.contains(intent.subject.item()),
                };
                if ours && intent.cause == RetireCause::Erase {
                    let through = owed.entry(intent.subject).or_insert(intent.through);
                    *through = (*through).max(intent.through);
                }
            }
        }
        // A fenced credential whose value had no intent bound names its
        // whole erase alone, through `PARENT_ONLY`.
        for credential in self.fenced_credentials_in_txn(txn, erased)? {
            let parent = custody
                .binding()
                .subject(CustodyKind::CredentialValue, credential.as_bytes())?;
            owed.entry(parent).or_insert(PARENT_ONLY);
        }
        let names: BTreeSet<String> = owed
            .iter()
            .map(|(subject, through)| retirement_name(subject, *through))
            .collect();
        Ok(names.into_iter().collect())
    }

    /// Whether every custody retirement an erase bound by `names` has
    /// finished: no intent stands for it, no other holder keeps its body,
    /// every generation through the bound one is retired here, and each of
    /// its journal obligations is complete, every required target having
    /// acknowledged it and the anchor advanced past it (with no anchor set,
    /// the acknowledgements alone, rollback not proven). An erased
    /// credential's names stand for its whole erase too (KS-6 part 2): its
    /// fence and discovery complete, no intent of any key its id names, and
    /// every key it names, found then or later, finished so, besides each
    /// bound key's own check. A retirement with no obligation recorded, or
    /// no custody bound to read it, has not: missing proof stays pending,
    /// never `not required`. No names: none is owed.
    ///
    /// # Errors
    ///
    /// Storage and custody faults, and a name custody would not write.
    pub(crate) fn erase_custody_retired_in_txn(
        &self,
        txn: &RoTxn<'_>,
        names: &[String],
    ) -> Result<bool> {
        if names.is_empty() {
            return Ok(true);
        }
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(false);
        };
        let mut credentials = BTreeSet::new();
        for name in names {
            let (kind, item, through) = retirement_of_name(name)
                .ok_or(Error::CorruptedIndex("redaction audit receipt body"))?;
            if credential_parent_kind(kind) {
                let parent = <[u8; 16]>::try_from(item.get(..16).unwrap_or_default())
                    .ok()
                    .map(EntityId::from_bytes)
                    .transpose()?
                    .ok_or(Error::CorruptedIndex("redaction audit receipt body"))?;
                if credentials.insert(parent)
                    && !self.credential_erase_finished_in_txn(txn, &parent)?
                {
                    return Ok(false);
                }
                // A parent-only name proves no more; a bound key's own
                // retirement is checked as any other's.
                if through == PARENT_ONLY {
                    continue;
                }
            }
            let subject = custody.binding().subject(kind, &item)?;
            if retirement_in_txn(self, txn, &subject)?.is_some() {
                return Ok(false);
            }
            #[cfg(unix)]
            if kind == CustodyKind::BodyInstance
                && let Some(Ok(instance)) = item.get(..16).map(<[u8; 16]>::try_from)
                && self.body_erase_waits_on_holder_in_txn(txn, &instance)?
            {
                return Ok(false);
            }
            if custody.first_unretired(&subject)? <= through {
                return Ok(false);
            }
            let obligations = self.custody_obligations_of(&subject)?;
            if obligations.is_empty() || obligations.iter().any(|(_, done)| !done) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
