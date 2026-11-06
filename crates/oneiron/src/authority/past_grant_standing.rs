//! Prior signed owner-agent standing for main-log WorldPrivacy acts (FIX 4703).
//!
//! A narrow Grant-only loosening of [`super::carried_act::grant_refused_agent_acts`]:
//! a NOW-refused native WorldPrivacy act by an agent is preserved when its
//! exact hash sits in the signed parent ancestry of every counted signed
//! owner-agent revoke of its Grant, with exactly one counted signed Access
//! Mint for that Grant in the act's own ancestry naming the agent, world and
//! time under the exact native [`super::owner_act`] semantics, and with each
//! counted Mint and Revoke admitted (carrier and owner stood) at its own
//! signed heads.
//!
//! Only main-log ancestry counts: a signed Revoke whose parents transitively
//! contain the act's exact hash is the authenticated observation of that act.
//! No topology token, no unsigned family, no new refusal, no new history
//! gate. Any missing parent, body, admission or proof keeps the original
//! NOW judgment; only a storage or decode fault surfaces as an error so the
//! caller keeps the original list and logs it.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

use super::*;

mod topology;
pub(crate) use topology::preserved_topology_act_in_txn;

/// Policy hook (FIX 4703, single owner-call hook): preserve a NOW-refused
/// native WorldPrivacy act by an agent whose exact hash every counted signed
/// revoke of its Grant saw. `false` keeps today's NOW judgment for every act.
pub(super) const PRESERVE_CAUSAL_OWNER_AGENT_WORLD_ACTS: bool = true;

/// The `candidates` hashes (NOW-refused native WorldPrivacy acts) whose Grant
/// standing prior signed history preserves. Only exact hashes from this set
/// are ever returned, to be omitted from the Grant-only refused list; any
/// missing history or proof returns without them, never a refusal.
pub(super) fn preserved_world_acts(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    candidates: &[AuthorityEntryHash],
) -> Result<BTreeSet<AuthorityEntryHash>> {
    let mut preserved = BTreeSet::new();
    if !PRESERVE_CAUSAL_OWNER_AGENT_WORLD_ACTS || candidates.is_empty() {
        return Ok(preserved);
    }
    let loaded = load_history(store, txn)?;
    for candidate in candidates {
        if preserved_one(store, txn, fold, &loaded, *candidate)?.is_some() {
            preserved.insert(*candidate);
        }
    }
    Ok(preserved)
}

/// Held rows plus adopted-covered history: immutable parents for every known
/// row (to walk through unrelated ops) and canonical bodies where carried.
struct LoadedHistory {
    parents: BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
    bodies: BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
}

/// The SAME-txn held authority rows plus ONLY the adopted image's carried
/// bodies ([`VerifiedAuthorityCheckpoint`], the existing trust). Any decode
/// fault or conflicting same-hash metadata fails closed so the caller keeps
/// the original list.
fn load_history(store: &Store, txn: &heed::RoTxn<'_>) -> Result<LoadedHistory> {
    let mut parents: BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>> = BTreeMap::new();
    let mut bodies: BTreeMap<AuthorityEntryHash, AuthorityLogEntry> = BTreeMap::new();
    for (_, body) in authority_log_rows_in_txn(store, txn)? {
        let entry = decode_authority_log_entry_body(&body)?;
        let hash = authority_entry_hash(&entry)?;
        if let Some(prior) = parents.get(&hash) {
            if *prior != entry.parent_hashes {
                return Err(Error::CorruptedIndex(
                    "past grant standing: conflicting held parents for one hash",
                ));
            }
            continue;
        }
        parents.insert(hash, entry.parent_hashes.clone());
        bodies.insert(hash, entry);
    }
    if let Some(adopted) =
        super::checkpoint_adopt::cached_adopted_authority_checkpoint_in_txn(store, txn)?
    {
        let image = adopted.image();
        for (hash, row) in &image.rows {
            if let Some(prior) = parents.get(hash) {
                if *prior != row.parents {
                    return Err(Error::CorruptedIndex(
                        "past grant standing: held parents disagree with adopted image",
                    ));
                }
                if let Some(body) = row.body.as_ref() {
                    let adopted_entry = decode_authority_log_entry_body(body)?;
                    if authority_entry_hash(&adopted_entry)? != *hash
                        || adopted_entry.parent_hashes != row.parents
                    {
                        return Err(Error::CorruptedIndex(
                            "past grant standing: adopted carried body mismatches its row",
                        ));
                    }
                    if let Some(held) = bodies.get(hash) {
                        if held != &adopted_entry {
                            return Err(Error::CorruptedIndex(
                                "past grant standing: held body disagrees with adopted body",
                            ));
                        }
                    }
                }
                continue;
            }
            parents.insert(*hash, row.parents.clone());
            if let Some(body) = row.body.as_ref() {
                let entry = decode_authority_log_entry_body(body)?;
                if authority_entry_hash(&entry)? != *hash || entry.parent_hashes != row.parents {
                    return Err(Error::CorruptedIndex(
                        "past grant standing: adopted carried body mismatches its row",
                    ));
                }
                bodies.insert(*hash, entry);
            }
        }
    }
    Ok(LoadedHistory { parents, bodies })
}

/// `Some(candidate)` when `candidate` is a counted native WorldPrivacy act by
/// an agent with exactly one counted signed Access Mint in its ancestry
/// naming the act and every counted signed revoke of its Grant seeing its
/// exact hash, each admitted at its own signed heads; `None` keeps the NOW
/// judgment (concurrent/unseen/regrant/missing proof included). Only a store
/// or causal-points read fault is an `Err`.
fn preserved_one(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    loaded: &LoadedHistory,
    candidate: AuthorityEntryHash,
) -> Result<Option<AuthorityEntryHash>> {
    if !fold.valid_entries.contains(&candidate) || fold.held_back_entries().contains(&candidate) {
        return Ok(None);
    }
    let action_entry = match loaded.bodies.get(&candidate) {
        Some(entry) => entry,
        None => return Ok(None),
    };
    let AuthorityOp::WorldPrivacy(edit) = &action_entry.op else {
        return Ok(None);
    };
    let ActBy::Agent { agent, grant } = edit.act.by else {
        return Ok(None);
    };
    if edit.act.act != OwnerActKind::WorldPrivacy || edit.act.target != edit.world {
        return Ok(None);
    }
    let world: EntityId = edit.world;
    let at: u64 = action_entry.ts;
    let mut mints: Vec<AuthorityEntryHash> = Vec::new();
    let mut revokes: Vec<AuthorityEntryHash> = Vec::new();
    for (hash, entry) in &loaded.bodies {
        if !fold.valid_entries.contains(hash) || fold.held_back_entries().contains(hash) {
            continue;
        }
        match &entry.op {
            AuthorityOp::AgentGrantAct(record) if record.grant == grant => match &record.change {
                AgentGrantChange::Mint { .. } => mints.push(*hash),
                AgentGrantChange::Revoke { .. } => revokes.push(*hash),
            },
            AuthorityOp::SlipGrantRevoke { grant_ref } if *grant_ref == grant => {
                return Ok(None);
            }
            AuthorityOp::MembershipExecution(record)
                if record.withdrawn_grants.binary_search(&grant).is_ok() =>
            {
                return Ok(None);
            }
            _ => {}
        }
    }
    if mints.len() != 1 || revokes.is_empty() {
        return Ok(None);
    }
    let mint_hash = mints[0];
    let mint_entry = match loaded.bodies.get(&mint_hash) {
        Some(entry) => entry,
        None => return Ok(None),
    };
    let AuthorityOp::AgentGrantAct(mint_record) = &mint_entry.op else {
        return Ok(None);
    };
    let AgentGrantChange::Mint {
        member,
        scope,
        expires_at,
        grant_kind,
        ..
    } = &mint_record.change
    else {
        return Ok(None);
    };
    if !super::owner_act::signed_owner_agent_mint_names_world_act(
        *member,
        scope,
        *grant_kind,
        *expires_at,
        agent,
        world,
        at,
    ) {
        return Ok(None);
    }
    let action_past = match transitive_ancestors(&loaded.parents, &action_entry.parent_hashes) {
        Ok(past) => past,
        Err(_) => return Ok(None),
    };
    if !action_past.contains(&mint_hash) {
        return Ok(None);
    }
    for revoke_hash in &revokes {
        let revoke_entry = match loaded.bodies.get(revoke_hash) {
            Some(entry) => entry,
            None => return Ok(None),
        };
        let revoke_past = match transitive_ancestors(&loaded.parents, &revoke_entry.parent_hashes) {
            Ok(past) => past,
            Err(_) => return Ok(None),
        };
        if !revoke_past.contains(&candidate) {
            return Ok(None);
        }
    }
    let mut acts = BTreeSet::new();
    let Some(mint_act) = external_for_grant_act(mint_hash, mint_entry, mint_record) else {
        return Ok(None);
    };
    acts.insert(mint_act);
    for revoke_hash in &revokes {
        let revoke_entry = match loaded.bodies.get(revoke_hash) {
            Some(entry) => entry,
            None => return Ok(None),
        };
        let AuthorityOp::AgentGrantAct(revoke_record) = &revoke_entry.op else {
            return Ok(None);
        };
        let Some(act) = external_for_grant_act(*revoke_hash, revoke_entry, revoke_record) else {
            return Ok(None);
        };
        acts.insert(act);
    }
    let points = super::causal_points_in_txn(store, txn, &acts)?;
    for act in &acts {
        if points
            .carrier_and_owner_stood_at_signed_heads(act)
            .is_none_or(|stood| !stood)
        {
            return Ok(None);
        }
    }
    Ok(Some(candidate))
}

/// The transitive parents of `start` over `parents`; `Err` names a parent no
/// row carries metadata for (missing history), never an inference.
fn transitive_ancestors(
    parents: &BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>,
    start: &[AuthorityEntryHash],
) -> std::result::Result<BTreeSet<AuthorityEntryHash>, AuthorityEntryHash> {
    let mut past = BTreeSet::new();
    let mut stack: Vec<AuthorityEntryHash> = start.to_vec();
    while let Some(hash) = stack.pop() {
        if !past.insert(hash) {
            continue;
        }
        let Some(next) = parents.get(&hash) else {
            return Err(hash);
        };
        stack.extend(next.iter().copied());
    }
    Ok(past)
}

/// `record` (a counted Mint or Revoke signed as `hash`) at its actual signed
/// parents, for the at-heads admission query; `None` where its signer is no
/// install key (then no positive proof).
fn external_for_grant_act(
    hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
    record: &AgentGrantActRecord,
) -> Option<ExternalAct> {
    let AuthorityKey::Ed25519(key) = entry.signer_key() else {
        return None;
    };
    Some(ExternalAct {
        heads: entry.parent_hashes.iter().copied().collect(),
        machine: record.machine,
        key: *key,
        owner: record.act.owner,
        token: hash,
    })
}
