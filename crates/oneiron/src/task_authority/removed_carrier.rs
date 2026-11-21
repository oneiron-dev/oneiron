//! A removed machine's TASK facts (row TASK-FACT-REMOVED-CARRIER-NEW-FACTS; lead ruling
//! REMOVED-CARRIER-NEW-FACTS = A, 21 Nov): "a removal does not unmake facts made BEFORE it,
//! and cannot be used to make new ones after".
//!
//! The owner's removal of a machine names, beside the world edits it saw, each TASK fact the
//! machine carried that the removing install counted as it wrote the removal
//! ([`carried_fact_acts_in_txn`]), each by its carried act (the digest of its carrier
//! transcript). Past the removal the machine's signature proves only a fact every removal of
//! it saw (`fact_proof::carrier_standing`). A fact the machine signed later, or one no
//! remover held, does not count. That loss fails closed and is never silent: the machine's
//! answer says how many such facts arrived ([`Vault::task_facts_not_counted_after_removal`],
//! [`task_facts_not_counted_text`]).

use std::collections::BTreeSet;

use crate::Vault;
use crate::authority::AuthorityEntryHash;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead as _;
use crate::registry::ENTITY_TYPE_TASK;
use crate::scan_check::ScanCount;
use crate::store::EngineScan;

use super::fact_proof::{CarrierStanding, FactProof};
use super::{
    REFUSED, decode_carried_task_authority_fact_body, encode_task_authority_fact_body,
    is_task_authority_fact_body,
};

/// The carried acts of the TASK facts `machine` carried that this install counts in `txn`:
/// every fact row it holds, and every fact it keeps refused at a deleted id, whose carrier
/// signature names `machine` and proves the fact here. A removal of `machine` names them, so
/// they keep counting past it.
pub(crate) fn carried_fact_acts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
) -> Result<BTreeSet<AuthorityEntryHash>> {
    carried_facts_standing_in(vault, txn, machine, CarrierStanding::Counts)
}

/// The carried acts of the facts `machine` carried that `fold` stands as `standing`, each
/// once: a fact held both as a row and refused at a deleted id is one act.
fn carried_facts_standing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
    standing: CarrierStanding,
) -> Result<BTreeSet<AuthorityEntryHash>> {
    let proof = FactProof::in_txn(&vault.store, txn)?;
    let mut acts = BTreeSet::new();
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
            acts.insert(act);
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
    Ok(acts)
}

impl Vault {
    /// How many TASK facts `machine` carried reached this install after its removal and do
    /// not count here: each fact row this install holds, or keeps refused at a deleted id,
    /// whose carrier signature names `machine` under the key its roster chain names and
    /// verifies, where that chain removed the machine and not every removal saw the fact.
    /// Each fact counts once. Zero for a machine no removal took away.
    pub fn task_facts_not_counted_after_removal(&self, machine: EntityId) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        let acts =
            carried_facts_standing_in(self, &txn, machine, CarrierStanding::ArrivedAfterRemoval)?;
        Ok(u64::try_from(acts.len()).unwrap_or(u64::MAX))
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
