//! The source audiences a window carries (Engine A, 6 Nov 03:46), through
//! canonical capture and rebuild. A window rebuilt from the artifact alone
//! gets back each final row's binding and its policy closure, so a restored
//! row reads to the people it read to.
//!
//! Capture keeps each binding of a final row the window carries, and every
//! revision of a policy those bindings reach, a thread's source included,
//! except a revision naming an actor this vault erased: a window loaded
//! before the erase can still hold one, and its family's highest revision
//! rides redacted under its own next revision instead. Beside them go this
//! vault's current binding and closure of each final row. A carried value
//! that contradicts this vault's refuses the capture. A derived row's
//! carriers (fix list row 17207) ride as a binding does: each one the window
//! carries for a final row, its policies' revisions reached as a binding's
//! are, and this vault's floor of the row under its own key, joined with
//! what the window carried there, with each policy's published closure.
//! Validation refuses a key or bytes not in their canonical form and keys
//! out of order: a restriction is never dropped. Before a recovery checks,
//! writes or compares anything ([`CanonicalSnapshot::settle_source_audiences_here`]),
//! a policy this vault holds stands in for the artifact's whole family of it
//! at its current revision; one it does not hold keeps the artifact's
//! revisions, none naming an actor this vault erased (the highest one's
//! redaction rides under a revision of its own); a binding this vault
//! holds otherwise refuses the restore; and every set the artifact carries
//! for a derived row joins this vault's floor of it under its own key, as
//! the restore stages them. A closure the artifact does not carry stays
//! unresolved: its rows read to no one, never to all.

use std::collections::{BTreeMap, BTreeSet};

use loro::{LoroDoc, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

use super::{ByteBudget, CanonicalSnapshot, id, insert};
use crate::EntityId;
use crate::error::Result;
use crate::source_audience::carried::{
    Carrier, derived_key, encode_binding, encode_derived, encode_policy, policy_key, record_key,
};
use crate::source_audience::{self, SourceAudienceKind, SourceAudiencePolicy};

/// The window root map of source audiences, as sync files it.
const SOURCE_AUDIENCES: &str = "source_audiences";

/// One carried binding or policy revision: its key and its bytes, as the
/// window map holds them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSourceAudience {
    pub key: String,
    pub value: Vec<u8>,
}

/// Files `value` under `key` in `rows`; a different value under the same key
/// refuses.
fn keep(rows: &mut BTreeMap<String, Vec<u8>>, key: String, value: Vec<u8>) -> Result<()> {
    match rows.get(&key) {
        Some(held) if *held != value => Err(super::invalid(
            "a carried source audience contradicts this vault's",
        )),
        Some(_) => Ok(()),
        None => {
            rows.insert(key, value);
            Ok(())
        }
    }
}

/// Carries, sorted by key, the binding and the derived carriers of each row
/// of the snapshot's final entity set and the revisions of every policy
/// those reach: the window's carriers first, then this vault's current
/// binding and published closure of each row, and its derived floor of the
/// row under its own key with each policy's published closure. Each is
/// measured, never refused, as a birth is: an overrun is logged. It needs
/// no sync feature: the carriers are domain values, and a featureless
/// capture keeps them too.
pub(super) fn capture(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    doc: &LoroDoc,
    snapshot: &mut CanonicalSnapshot,
    budget: &mut ByteBudget,
) -> Result<()> {
    // The root resolves as in `binary_rows`, without creating it.
    let LoroValue::Map(containers) = doc.get_value() else {
        return Err(super::invalid("window root"));
    };
    let map = match containers.get(SOURCE_AUDIENCES) {
        None => None,
        Some(LoroValue::Container(id)) => Some(
            doc.try_get_map(id)
                .ok_or(super::invalid("nonmap Layer-1 carrier"))?,
        ),
        Some(_) => return Err(super::invalid("nonmap Layer-1 carrier")),
    };
    let mut finals = BTreeSet::new();
    for entity in &snapshot.entity_blobs {
        finals.insert(id(entity.id)?);
    }
    let mut rows = BTreeMap::new();
    // The policies each derived carrier of a final row names, by its key
    // (fix list row 17207); this vault's own key joins its floor below.
    let mut derived: BTreeMap<String, BTreeSet<EntityId>> = BTreeMap::new();
    if let Some(map) = &map {
        let mut carried = Vec::new();
        let mut nonbinary = false;
        map.for_each(|key, value| match value {
            ValueOrContainer::Value(LoroValue::Binary(bytes)) => {
                carried.push((key.to_owned(), bytes.to_vec()));
            }
            _ => nonbinary = true,
        });
        if nonbinary {
            return Err(super::invalid("nonbinary Layer-1 carrier"));
        }
        let mut decoded = Vec::with_capacity(carried.len());
        for (key, value) in carried {
            let entry = crate::source_audience::carried::carrier(&key, &value)
                .map_err(|_| super::invalid("source audience carrier"))?;
            decoded.push((key, value, entry));
        }
        let mut bound = BTreeSet::new();
        for (_, _, entry) in &decoded {
            match entry {
                Carrier::Record { row, policy } if finals.contains(row) => {
                    bound.insert(*policy);
                }
                // A derived row's policies bind it as a binding does (fix
                // list row 17207).
                Carrier::Derived { row, policies, .. } if finals.contains(row) => {
                    bound.extend(policies.iter().copied());
                }
                _ => {}
            }
        }
        let mut reached = bound.clone();
        for (_, _, entry) in &decoded {
            if let Carrier::Policy {
                id,
                policy:
                    SourceAudiencePolicy {
                        kind: SourceAudienceKind::Thread { source, .. },
                        ..
                    },
            } = entry
                && bound.contains(id)
            {
                reached.insert(*source);
            }
        }
        let mut families: BTreeMap<EntityId, Vec<(String, Vec<u8>, SourceAudiencePolicy)>> =
            BTreeMap::new();
        for (key, value, entry) in decoded {
            match entry {
                Carrier::Record { row, .. } => {
                    if finals.contains(&row) {
                        keep(&mut rows, key, value)?;
                    }
                }
                Carrier::Policy { id, policy } => {
                    if reached.contains(&id) {
                        families.entry(id).or_default().push((key, value, policy));
                    }
                }
                Carrier::Derived { row, policies, .. } => {
                    if finals.contains(&row) {
                        derived.insert(key, policies);
                    }
                }
                // A withholding marker names a row the window no longer
                // carries; the hold it set lives in the vault, not here. A
                // change receipt rides beside its policy from this vault's
                // own receipts at the window's next export, not in the
                // artifact.
                Carrier::Withheld { .. } | Carrier::Event { .. } => {}
            }
        }
        for (id, revisions) in families {
            erase_scrubbed_family(vault, txn, &mut rows, &id, revisions)?;
        }
    }
    for row in &finals {
        let Some(policy) = source_audience::binding_in(vault, txn, row)? else {
            continue;
        };
        let Some(closure) = source_audience::published_closure_in(vault, txn, &policy)? else {
            continue;
        };
        keep(&mut rows, record_key(row), encode_binding(&policy)?)?;
        for (id, held) in closure {
            keep(
                &mut rows,
                policy_key(&id, held.revision),
                encode_policy(&held)?,
            )?;
        }
    }
    // This vault's derived floor of each final row rides under its own key,
    // joined with what the window carried there: the floor only grows, so a
    // carried set it lacks contradicts nothing. A policy whose closure does
    // not publish keeps its place in the set: the row reads to no one, never
    // to all.
    let me = crate::identity::read_machine_id_in_txn(vault, txn)?;
    for row in &finals {
        let key = derived_key(row, me.as_ref());
        if let Some(floor) = source_audience::derived_policies_in(vault, txn, row)?
            && !floor.is_empty()
        {
            derived.entry(key.clone()).or_default().extend(floor);
        }
        let Some(policies) = derived.get(&key) else {
            continue;
        };
        for policy in policies {
            let Some(closure) = source_audience::published_closure_in(vault, txn, policy)? else {
                continue;
            };
            for (id, held) in closure {
                keep(
                    &mut rows,
                    policy_key(&id, held.revision),
                    encode_policy(&held)?,
                )?;
            }
        }
    }
    for (key, policies) in derived {
        keep(&mut rows, key, encode_derived(&policies)?)?;
    }
    let mut overrun = None;
    for (key, value) in rows {
        if let Some(over) = budget.measure(key.len() + value.len()) {
            overrun = Some(over);
        }
        snapshot
            .source_audiences
            .push(CanonicalSourceAudience { key, value });
    }
    if let Some(overrun) = overrun {
        tracing::warn!(
            required = overrun.required,
            limit = overrun.limit,
            "canonical recovery measured source audiences past its budget"
        );
    }
    Ok(())
}

/// Files the carried revisions of policy `id` that name no actor this vault
/// erased. When the family's highest revision names one, the family still
/// ends at least as high and as narrow: this vault's head stands when it is
/// as high, else that revision's redaction rides under its own next
/// revision, as a stored window's erase writes it.
fn erase_scrubbed_family(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    rows: &mut BTreeMap<String, Vec<u8>>,
    id: &EntityId,
    revisions: Vec<(String, Vec<u8>, SourceAudiencePolicy)>,
) -> Result<()> {
    let Some(top) = revisions
        .iter()
        .map(|(_, _, policy)| policy)
        .max_by_key(|policy| policy.revision)
        .cloned()
    else {
        return Ok(());
    };
    for (key, value, policy) in revisions {
        if !source_audience::names_erased_actor_in(vault, txn, &policy)? {
            keep(rows, key, value)?;
        }
    }
    if !source_audience::names_erased_actor_in(vault, txn, &top)? {
        return Ok(());
    }
    let head = match source_audience::policy_in(vault, txn, id)? {
        Some(held) if held.revision >= top.revision => held,
        _ => top,
    };
    let head = if source_audience::names_erased_actor_in(vault, txn, &head)? {
        source_audience::redacted_successor_in(vault, txn, &head)?
    } else {
        head
    };
    keep(rows, policy_key(id, head.revision), encode_policy(&head)?)
}

/// Each carrier is in its canonical form, and the keys sort strictly: a
/// binding, a revision or a derived row's set is never carried twice. A
/// binding stands only on a carried row whose own bytes carry the
/// source-audience obligation, or on its bodiless erase shell (fix list row
/// 16256); a stamped row the artifact binds to nothing stays unresolved,
/// and nothing here binds it.
pub(super) fn validate(snapshot: &CanonicalSnapshot) -> Result<()> {
    let mut previous: Option<&str> = None;
    for row in &snapshot.source_audiences {
        if previous.is_some_and(|previous| previous >= row.key.as_str()) {
            return Err(super::invalid("source audiences out of key order"));
        }
        let entry = crate::source_audience::carried::carrier(&row.key, &row.value)
            .map_err(|_| super::invalid("source audience carrier"))?;
        if let Carrier::Record { row: bound, .. } = entry
            && !source_audience::binding_stands_on(
                snapshot
                    .entity_blobs
                    .binary_search_by_key(bound.as_bytes(), |entity| entity.id)
                    .ok()
                    .map(|at| snapshot.entity_blobs[at].blob.as_slice()),
            )
        {
            return Err(super::invalid(
                "a source audience binds a row that carries no source_audience_required",
            ));
        }
        previous = Some(&row.key);
    }
    Ok(())
}

/// Files one carrier back in the rebuilt window's map.
pub(super) fn rebuild_row(doc: &LoroDoc, row: &CanonicalSourceAudience) -> Result<()> {
    insert(doc, SOURCE_AUDIENCES, &row.key, &row.value)
}

#[cfg(feature = "sync")]
impl CanonicalSnapshot {
    /// The source audiences as this vault recovers them: a policy it holds
    /// at its current revision, in place of the artifact's whole family of
    /// it; one it does not hold, the artifact's revisions but each naming an
    /// actor this vault erased, the highest one's redaction filed under its
    /// own next revision; each binding as carried, unless this vault binds
    /// the row otherwise, which refuses the restore; each derived carrier as
    /// carried; each final row this vault binds now with its binding and
    /// current closure; and each final row's derived floor here, joined with
    /// every set the artifact carries for it as the restore stages them,
    /// under this vault's own key with each policy's current closure, so a
    /// capture taken after the restore answers the same.
    pub(in crate::recovery) fn settle_source_audiences_here(
        &mut self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        let mut rows = BTreeMap::new();
        let mut held = BTreeMap::new();
        let mut foreign: BTreeMap<EntityId, Vec<(String, Vec<u8>, SourceAudiencePolicy)>> =
            BTreeMap::new();
        // The policies every derived carrier names, by its row (fix list row
        // 17207).
        let mut carried_floors: BTreeMap<EntityId, BTreeSet<EntityId>> = BTreeMap::new();
        for row in std::mem::take(&mut self.source_audiences) {
            let entry = crate::source_audience::carried::carrier(&row.key, &row.value)
                .map_err(|_| super::invalid("source audience carrier"))?;
            match entry {
                Carrier::Record { row: bound, policy } => {
                    if source_audience::binding_in(vault, txn, &bound)?
                        .is_some_and(|here| here != policy)
                    {
                        return Err(super::invalid(
                            "a restored binding contradicts this vault's",
                        ));
                    }
                    rows.insert(row.key, row.value);
                }
                Carrier::Policy { id, policy } => {
                    if let Some(current) = source_audience::policy_in(vault, txn, &id)? {
                        held.insert(id, current);
                    } else {
                        foreign
                            .entry(id)
                            .or_default()
                            .push((row.key, row.value, policy));
                    }
                }
                // A derived carrier stays as carried, and its set joins the
                // row's floor here as the restore stages it: the floor only
                // grows, so no set contradicts this vault's.
                Carrier::Derived {
                    row: derived_row,
                    policies,
                    ..
                } => {
                    carried_floors
                        .entry(derived_row)
                        .or_default()
                        .extend(policies);
                    rows.insert(row.key, row.value);
                }
                // Capture keeps no marker and no receipt; one in an artifact
                // restores none.
                Carrier::Withheld { .. } | Carrier::Event { .. } => {}
            }
        }
        for (id, current) in held {
            // A held head that still names an erased actor restores as its
            // redacted successor, as a carried one does.
            let current = if source_audience::names_erased_actor_in(vault, txn, &current)? {
                source_audience::redacted_successor_in(vault, txn, &current)?
            } else {
                current
            };
            rows.insert(policy_key(&id, current.revision), encode_policy(&current)?);
        }
        for (id, revisions) in foreign {
            let highest = revisions.iter().map(|(_, _, policy)| policy.revision).max();
            for (key, value, policy) in revisions {
                if !source_audience::names_erased_actor_in(vault, txn, &policy)? {
                    rows.insert(key, value);
                } else if Some(policy.revision) == highest {
                    let redacted = source_audience::redacted_successor_in(vault, txn, &policy)?;
                    rows.insert(
                        policy_key(&id, redacted.revision),
                        encode_policy(&redacted)?,
                    );
                }
            }
        }
        // A final row this vault binds now rides with its binding and its
        // current closure, as a capture here would take it.
        for entity in &self.entity_blobs {
            let row = id(entity.id)?;
            let Some(policy) = source_audience::binding_in(vault, txn, &row)? else {
                continue;
            };
            if !source_audience::publishable_in(vault, txn, &policy)? {
                continue;
            }
            let Some(closure) = source_audience::policy_closure_in(vault, txn, &policy)? else {
                continue;
            };
            rows.entry(record_key(&row))
                .or_insert(encode_binding(&policy)?);
            for (family, current) in closure {
                if !rows.contains_key(&policy_key(&family, current.revision)) {
                    rows.insert(
                        policy_key(&family, current.revision),
                        encode_policy(&current)?,
                    );
                }
            }
        }
        // A final row's derived floor, as the restore leaves it (this
        // vault's, joined with every set the artifact carries for the row),
        // rides under this vault's own key with each policy's current
        // closure, as a capture after the restore would take it (fix list
        // row 17207). A policy whose closure does not publish keeps its
        // place in the set: the row reads to no one, never to all.
        let me = crate::identity::read_machine_id_in_txn(vault, txn)?;
        for entity in &self.entity_blobs {
            let row = id(entity.id)?;
            let mut floor = carried_floors.remove(&row).unwrap_or_default();
            if let Some(here) = source_audience::derived_policies_in(vault, txn, &row)? {
                floor.extend(here);
            }
            if floor.is_empty() {
                continue;
            }
            for policy in &floor {
                if !source_audience::publishable_in(vault, txn, policy)? {
                    continue;
                }
                let Some(closure) = source_audience::policy_closure_in(vault, txn, policy)? else {
                    continue;
                };
                for (family, current) in closure {
                    rows.entry(policy_key(&family, current.revision))
                        .or_insert(encode_policy(&current)?);
                }
            }
            rows.insert(derived_key(&row, me.as_ref()), encode_derived(&floor)?);
        }
        self.source_audiences = rows
            .into_iter()
            .map(|(key, value)| CanonicalSourceAudience { key, value })
            .collect();
        Ok(())
    }
}
