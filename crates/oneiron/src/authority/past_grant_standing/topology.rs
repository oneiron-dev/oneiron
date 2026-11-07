//! Prior Grant standing for signed topology decisions outside the log.
//! The signed Revoke acknowledges the exact seal token, not arbitrary old
//! authority heads. Carrier/owner/removal standing of the seal stays with
//! its original caller; only the NOW-refused Grant can be preserved here.

use super::super::*;
use super::{external_for_grant_act, load_history, transitive_ancestors};
use crate::error::Result;
use crate::store::Store;
use std::collections::BTreeSet;

/// Separate from the main-log WorldPrivacy policy: a topology seal needs
/// the exact token in every counted signed revoke, never log ancestry alone.
const PRESERVE_CAUSAL_OWNER_AGENT_TOPOLOGY_ACTS: bool = true;

/// Positive proof only, in the caller's installed authority context. Missing
/// history or a read/decode fault keeps the old NOW judgment; it adds no
/// history gate. The caller still judges the seal's full removal race.
pub(crate) fn preserved_topology_act_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    external: &ExternalAct,
    act: &OwnerAct,
    at: u64,
) -> bool {
    if !PRESERVE_CAUSAL_OWNER_AGENT_TOPOLOGY_ACTS
        || act.act != OwnerActKind::TopologySeal
        || act.owner != external.owner
    {
        return false;
    }
    match preserves(store, txn, fold, external, act, at) {
        Ok(preserved) => preserved,
        Err(error) => {
            tracing::debug!(%error, "topology past Grant proof unavailable; keeping NOW judgment");
            false
        }
    }
}

fn preserves(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    external: &ExternalAct,
    act: &OwnerAct,
    at: u64,
) -> Result<bool> {
    let ActBy::Agent { agent, grant } = act.by else {
        return Ok(false);
    };
    let loaded = load_history(store, txn)?;
    let mut mints = Vec::new();
    let mut revokes = Vec::new();
    for (hash, entry) in &loaded.bodies {
        if !fold.valid_entries.contains(hash) || fold.held_back_entries().contains(hash) {
            continue;
        }
        match &entry.op {
            AuthorityOp::AgentGrantAct(record) if record.grant == grant => match &record.change {
                AgentGrantChange::Mint { .. } => mints.push((*hash, entry, record)),
                AgentGrantChange::Revoke {
                    acknowledged_topology,
                } => {
                    if !acknowledged_topology.contains(&external.token) {
                        return Ok(false);
                    }
                    revokes.push((*hash, entry, record));
                }
            },
            AuthorityOp::SlipGrantRevoke { grant_ref, .. } if *grant_ref == grant => {
                return Ok(false);
            }
            AuthorityOp::MembershipExecution(record)
                if record.withdrawn_grants.binary_search(&grant).is_ok() =>
            {
                return Ok(false);
            }
            _ => {}
        }
    }
    if mints.len() != 1 || revokes.is_empty() {
        return Ok(false);
    }
    let (mint_hash, mint_entry, mint_record) = mints[0];
    let AgentGrantChange::Mint {
        member,
        scope,
        expires_at,
        grant_kind,
        ..
    } = &mint_record.change
    else {
        return Ok(false);
    };
    if !super::super::owner_act::signed_owner_agent_mint_names_topology_act(
        *member,
        scope,
        *grant_kind,
        *expires_at,
        agent,
        at,
    ) {
        return Ok(false);
    }
    let heads: Vec<_> = external.heads.iter().copied().collect();
    let Ok(past) = transitive_ancestors(&loaded.parents, &heads) else {
        return Ok(false);
    };
    if !past.contains(&mint_hash) {
        return Ok(false);
    }
    let Some(mint_act) = external_for_grant_act(mint_hash, mint_entry, mint_record) else {
        return Ok(false);
    };
    let mut acts = BTreeSet::from([mint_act]);
    for (hash, entry, record) in revokes {
        let Some(revoke_act) = external_for_grant_act(hash, entry, record) else {
            return Ok(false);
        };
        acts.insert(revoke_act);
    }
    let points = super::super::causal_points_in_txn(store, txn, &acts)?;
    Ok(acts
        .iter()
        .all(|signed| points.carrier_and_owner_stood_at_signed_heads(signed) == Some(true)))
}
