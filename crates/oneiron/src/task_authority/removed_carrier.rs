//! A removed machine's TASK facts (row TASK-FACT-REMOVED-CARRIER-NEW-FACTS; lead ruling
//! REMOVED-CARRIER-NEW-FACTS = A, 21 Nov): "a removal does not unmake facts made BEFORE it,
//! and cannot be used to make new ones after".
//!
//! The owner's removal of a machine names, beside the world edits it saw, each TASK fact the
//! machine carried that the removing install held as it wrote the removal, under a carrier
//! signature that proves the fact there ([`carried_fact_acts_in_txn`]), each by its carried
//! act (the digest of its carrier transcript). Holding the signed fact proves the machine
//! made it before its removal; the fold still judges it as any fact (its link to its task,
//! its maker, its actor) at each read. Past the removal the machine's signature proves only a
//! fact every removal of it saw (`fact_proof::carrier_standing`). A fact the machine signed
//! later, or one no remover held, does not count. That loss fails closed and is never silent:
//! the machine's answer says how many such facts arrived and count here by no row
//! ([`Vault::task_facts_not_counted_after_removal`], [`task_facts_not_counted_text`]).

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityFold};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead as _;
use crate::registry::ENTITY_TYPE_TASK;
use crate::scan_check::ScanCount;
use crate::store::EngineScan;

use super::fact_proof::{CarrierStanding, FactProof};
use super::{
    FactCountRule, REFUSED, TaskAuthorityFact, decode_carried_task_authority_fact_body,
    encode_task_authority_fact_body, is_task_authority_fact_body,
};

/// One TASK fact a machine carried, as this install holds it: at its row, or refused at a
/// deleted id.
struct CarriedFact {
    fact_ref: EntityId,
    body: Vec<u8>,
    fact: TaskAuthorityFact,
    /// The fact's carried act: the digest of its carrier transcript.
    act: AuthorityEntryHash,
}

/// The carried acts of the TASK facts `machine` carried that this install holds in `txn`
/// under a carrier signature that names `machine` and proves the fact here: every fact row
/// it holds, linked to its task yet or not, and every fact it keeps refused at a deleted id.
/// A removal of `machine` names them, so they keep counting past it. A fact held here is one
/// the machine made before the removal, whether or not its `ScopedTo` link has arrived: the
/// link only indexes the fact under the task its body names, so it brings no new fact, and a
/// removal that left out a fact whose link is late would unmake it.
pub(crate) fn carried_fact_acts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
) -> Result<BTreeSet<AuthorityEntryHash>> {
    Ok(
        carried_facts_standing_in(vault, txn, machine, CarrierStanding::Counts)?
            .into_iter()
            .map(|carried| carried.act)
            .collect(),
    )
}

/// The facts `machine` carried that this install's fold stands as `standing` in `txn`, at
/// their row or refused at a deleted id. A fact held both ways is listed at each.
fn carried_facts_standing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
    standing: CarrierStanding,
) -> Result<Vec<CarriedFact>> {
    let proof = FactProof::in_txn(&vault.store, txn)?;
    let mut carried_facts = Vec::new();
    let mut judge = |fact_ref: &EntityId, body: &[u8]| {
        let Ok(carried) = decode_carried_task_authority_fact_body(body) else {
            return;
        };
        let Some(carrier) = carried.carrier.filter(|carrier| carrier.machine == machine) else {
            return;
        };
        let unsigned = encode_task_authority_fact_body(&carried.fact);
        if proof.standing(fact_ref, &unsigned, &carrier) == standing
            && let Some(act) = proof.carried_act(fact_ref, &carrier.machine, &unsigned)
        {
            carried_facts.push(CarriedFact {
                fact_ref: *fact_ref,
                body: body.to_vec(),
                fact: carried.fact,
                act,
            });
        }
    };
    let mut scanned = ScanCount::start(
        &vault.store,
        txn,
        EngineScan::TypeIndexRows,
        &[ENTITY_TYPE_TASK],
    )?;
    for id in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_TASK, None)?
    {
        scanned.row();
        let id = id?;
        let Some(raw) = vault.get_raw_in(txn, &id)? else {
            continue;
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_TASK)
        {
            continue;
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if is_task_authority_fact_body(body) {
            judge(&id, body);
        }
    }
    scanned.finish(vault);
    for row in REFUSED.iter_from(&vault.store, txn, &[])? {
        let ((_, fact_ref, _), body) = row?;
        judge(&fact_ref, &body);
    }
    Ok(carried_facts)
}

/// How many TASK facts `machine` carried reached this install after its removal and count
/// here by no row, read in `txn`: a fact the owner's restore landed here (which marks it
/// written here) or one whose signed twin stands counts, so the answer does not name it
/// (blind review round 1 P1, REVIEW-10107). Each fact counts once.
fn facts_not_counted_after_removal_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
) -> Result<u64> {
    let mut count = FactCountRule::default();
    let mut counted = BTreeSet::new();
    let mut not_counted = BTreeSet::new();
    for carried in
        carried_facts_standing_in(vault, txn, machine, CarrierStanding::ArrivedAfterRemoval)?
    {
        if count.counts_by_any_row(vault, txn, &carried.fact_ref, &carried.body, &carried.fact)? {
            counted.insert(carried.act);
        } else {
            not_counted.insert(carried.act);
        }
    }
    Ok(u64::try_from(not_counted.difference(&counted).count()).unwrap_or(u64::MAX))
}

impl Vault {
    /// How many TASK facts `machine` carried reached this install after its removal and do
    /// not count here: each fact row this install holds, or keeps refused at a deleted id,
    /// whose carrier signature names `machine` under the key its roster chain removed it
    /// under and verifies, where not every removal saw the fact, and that counts here by no
    /// other row. Each fact counts once. Zero for a machine no removal took away.
    ///
    /// # Errors
    ///
    /// Storage and fold errors.
    pub fn task_facts_not_counted_after_removal(&self, machine: EntityId) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        facts_not_counted_after_removal_in(self, &txn, machine)
    }

    /// The authority fold, as [`Self::authority_fold`] reads it, and
    /// [`Self::task_facts_not_counted_after_removal`] for `machine`, both read in one
    /// snapshot: a machine's answer never shows the role of one moment beside the facts a
    /// removal of a later one refused (blind review round 1 P1, REVIEW-10107).
    ///
    /// # Errors
    ///
    /// Storage and fold errors.
    pub fn authority_fold_with_task_facts_not_counted(
        &self,
        machine: EntityId,
    ) -> Result<(AuthorityFold, u64)> {
        let txn = self.authority_fold_snapshot()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let not_counted = facts_not_counted_after_removal_in(self, &txn, machine)?;
        Ok(((*fold).clone(), not_counted))
    }
}

/// The words a removed machine's answer shows for
/// [`Vault::task_facts_not_counted_after_removal`], as the lead ruled them
/// (REMOVED-CARRIER-NEW-FACTS = A): "N facts from this machine arrived after its removal and
/// were not counted". `None` when none arrived.
#[must_use]
pub fn task_facts_not_counted_text(count: u64) -> Option<String> {
    match count {
        0 => None,
        1 => Some("1 fact from this machine arrived after its removal and was not counted".into()),
        count => Some(format!(
            "{count} facts from this machine arrived after its removal and were not counted"
        )),
    }
}
