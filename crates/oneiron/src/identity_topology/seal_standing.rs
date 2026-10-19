//! A decision seal's causal evidence (FIX 4649, FIX 4652, FIX 5248): the act
//! each decision seal names for [`crate::authority::causal_points_in_txn`],
//! how each stands for the standing digest, the tokens a carrier's removal
//! lists as seen, and the Grants whose delete decides seal standing again.
//! Topology rows stay here, outside the authority fold: the fold judges the
//! acts it is handed, and a removal's writer copies the tokens into the
//! profile it signs.

use std::collections::BTreeSet;

use crate::authority::{
    ActBy, AuthorityEntryHash, AuthorityFold, ExternalAct, ExternalActStanding, OwnerAct,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

use super::act_admission::SealAuthority;
use super::admission_disposition::AdmissionDisposition;
use super::stored_event::StoredIdentityOpAction;

/// Every decision seal this vault holds, in fact-row order. A stored row
/// verified its signature as it decoded.
pub(super) fn decision_seals_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<AdmissionDisposition>> {
    let mut seals = Vec::new();
    for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        store,
        txn,
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        None,
    )? {
        let row = super::store_entity_helpers::identity_topology_event_for_store_in_txn(
            store, txn, &id?,
        )?
        .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        if let StoredIdentityOpAction::AdmissionDisposition(fact) = row.action
            && matches!(fact.authority, SealAuthority::Decision(_))
        {
            seals.push(fact);
        }
    }
    Ok(seals)
}

/// What decision seal `fact`, deciding as `act`, names of its causal point
/// and its carrier.
pub(super) fn external_act(fact: &AdmissionDisposition, act: &OwnerAct) -> Result<ExternalAct> {
    Ok(ExternalAct {
        heads: fact.authority_heads.clone(),
        machine: fact.carrier,
        key: fact.signer_pk,
        owner: act.owner,
        token: fact.act_token()?,
    })
}

/// Every decision seal's act, for one standing pass.
pub(super) fn decision_seal_acts_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<ExternalAct>> {
    decision_seals_in_txn(store, txn)?
        .iter()
        .filter_map(|fact| match &fact.authority {
            SealAuthority::Decision(act) => Some(external_act(fact, act)),
            SealAuthority::Engine(_) => None,
        })
        .collect()
}

/// Each decision seal of `seals` as the standing digest hashes it (FIX
/// 5248): its token, whether every head it signed is held in `fold`, and how
/// its act stands here ([`standing_tag`]), judged on `txn`'s stored log by one
/// causal fold for every seal ([`crate::authority::CausalPoints::standing`]).
/// That judgment runs the full removal race, every revision of the carrier's
/// chains and each one's acknowledged tokens, so a losing concurrent removal
/// that never saw a seal moves its tag while every chain's picked head stays
/// put. Pending is never flattened to Refused, and a fold or storage fault
/// refuses the digest.
pub(super) fn decision_seal_standings_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    seals: &[AdmissionDisposition],
) -> Result<BTreeSet<(AuthorityEntryHash, bool, u8)>> {
    let acts = seals
        .iter()
        .filter_map(|fact| match &fact.authority {
            SealAuthority::Decision(act) => Some(external_act(fact, act).map(|act| (fact, act))),
            SealAuthority::Engine(_) => None,
        })
        .collect::<Result<Vec<_>>>()?;
    if acts.is_empty() {
        return Ok(BTreeSet::new());
    }
    let asked: BTreeSet<ExternalAct> = acts.iter().map(|(_, act)| act.clone()).collect();
    let points = crate::authority::causal_points_in_txn(store, txn, &asked)?;
    let mut standings = BTreeSet::new();
    for (fact, act) in &acts {
        let held = fact
            .authority_heads
            .iter()
            .all(|head| fold.valid_entries.contains(head));
        let standing = points
            .standing(act, fold)
            .ok_or(Error::InvariantViolation("identity topology seal standing digest"))?;
        standings.insert((act.token, held, standing_tag(standing)));
    }
    Ok(standings)
}

/// The digest's tag of how a decision seal stands: Stands, Pending and
/// Refused each distinct.
fn standing_tag(standing: ExternalActStanding) -> u8 {
    match standing {
        ExternalActStanding::Stands => 1,
        ExternalActStanding::Pending => 2,
        ExternalActStanding::Refused => 3,
    }
}

/// The tokens of the decision seals `machine` carried, in fact-row order,
/// each once: what its next profile revision lists as seen, so a removal
/// that saw them keeps them standing (FIX 4649). The writer's cap keeps the
/// earliest; a later one it leaves out retires with the removal (CALLS "FIX
/// 4649 seal causal envelope").
pub(crate) fn carried_seal_tokens_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
) -> Result<Vec<AuthorityEntryHash>> {
    let mut seen = BTreeSet::new();
    let mut tokens = Vec::new();
    for fact in decision_seals_in_txn(store, txn)? {
        if fact.carrier != machine {
            continue;
        }
        let token = fact.act_token()?;
        if seen.insert(token) {
            tokens.push(token);
        }
    }
    Ok(tokens)
}

/// Whether a decision seal names one of `ids` as its agent's Grant (FIX
/// 4652): matched by the referenced id, never by a deleted row's type, which
/// a purge takes with it.
pub(super) fn seal_names_grant_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    ids: &BTreeSet<EntityId>,
) -> Result<bool> {
    Ok(decision_seals_in_txn(store, txn)?.iter().any(|fact| {
        matches!(
            fact.authority,
            SealAuthority::Decision(OwnerAct {
                by: ActBy::Agent { grant, .. },
                ..
            }) if ids.contains(&grant)
        )
    }))
}
