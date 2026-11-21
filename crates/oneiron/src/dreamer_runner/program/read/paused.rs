//! The armed programs a store holds paused (FIX
//! TURNPROGRAM-OCCURRENCE-ARMINGS-LIVE-ON-A-VAULT-COPY, lead ruling 21 Nov):
//! each timer, feed or idle arming the write that made the store a copy
//! served beside its source paused (`trigger::pause_occurrence_armings_in_txn`).
//! The verified owner reads every one, any other caller its own, as the
//! module's other reads; the pinned SKILL, with its name and description as
//! they read now, is withheld unless it reads on the caller's own lane. The
//! read pauses, resumes and releases nothing.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};

use super::super::ARM;
use super::super::types::TurnProgramArming;
use super::views::{PausedTurnProgramItem, PausedTurnProgramsRequest, PausedTurnProgramsView};
use super::{Caller, class_name, page_limit, readable_on_lane};

/// Reads the paused programs of the store, one page at a time, in actor
/// order, then registration order: each one the caller reads (it is the
/// program's own actor, or the verified owner), with what wakes it, a
/// timer's next due time as it stood, when it was paused, and its pinned
/// SKILL with the name and description that SKILL has now. Every page
/// carries the count of all the caller reads. A store that was never made a
/// copy beside its source holds none.
///
/// # Errors
///
/// A request that does not parse; the caller's read key refused; storage.
pub fn paused_turn_programs(
    memory: &Memory<'_>,
    input: &PausedTurnProgramsRequest,
) -> MemoryResult<PausedTurnProgramsView> {
    let caller = Caller::of(memory)?;
    let cursor = input.cursor.as_deref().map(arming_cursor).transpose()?;
    let limit = page_limit(input.limit)?;
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let prefix: &[u8] = if caller.owner {
        &[]
    } else {
        caller.actor.as_bytes()
    };
    let mut paused = paused_armings_in_txn(vault, &txn, prefix)?;
    drop(txn);
    paused.retain(|(arming, _)| caller.reads(arming.actor, arming.actor_class));
    let count = u64::try_from(paused.len()).unwrap_or(u64::MAX);
    let mut rest = paused
        .into_iter()
        .filter(|(arming, _)| cursor.is_none_or(|after| arming_key(arming) > after));
    let page: Vec<_> = rest.by_ref().take(limit).collect();
    let next_cursor = match (page.last(), rest.next()) {
        (Some((last, _)), Some(_)) => Some(cursor_text(arming_key(last))),
        _ => None,
    };
    let readable = readable_on_lane(
        memory,
        page.iter().map(|(arming, _)| arming.definition.skill),
    )?;
    let skills = skills_now(vault, &readable)?;
    Ok(PausedTurnProgramsView {
        programs: page
            .into_iter()
            .map(|(arming, paused_at)| paused_item(arming, paused_at, &readable, &skills))
            .collect(),
        paused: count,
        next_cursor,
    })
}

impl Vault {
    /// How many armed programs this store holds paused: the count a served
    /// copy shows its owner beside the offer to resume them
    /// (`vault.turn_programs.paused` lists them). It reads no actor's lane
    /// and names no program: the door that serves it admits its caller.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn paused_turn_program_count(&self) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        let paused = paused_armings_in_txn(self, &txn, &[])?;
        Ok(u64::try_from(paused.len()).unwrap_or(u64::MAX))
    }
}

/// The paused armings whose key starts with `prefix` (an actor's id, or
/// nothing for every actor), each with the time it was paused at, in key
/// order, in `txn`. A row that does not decode is passed over: the write
/// that pauses a copy passed it over too, so it is no paused program.
fn paused_armings_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<(TurnProgramArming, u64)>> {
    let mut paused = Vec::new();
    for row in ARM.iter_from(vault, txn, prefix)? {
        let arming = match row {
            Ok((_, arming)) => arming,
            Err(error) if error.kind() == ErrorKind::SideTableRow => continue,
            Err(error) => return Err(error),
        };
        if let Some(paused_at) = arming.paused_at {
            paused.push((arming, paused_at));
        }
    }
    Ok(paused)
}

/// The name and description each SKILL of `ids` has now, read in one
/// snapshot. A SKILL that is gone, or whose record does not decode, has
/// none: it never fails the list.
fn skills_now(
    vault: &Vault,
    ids: &BTreeSet<EntityId>,
) -> Result<BTreeMap<EntityId, (String, String)>> {
    let mut skills = BTreeMap::new();
    if ids.is_empty() {
        return Ok(skills);
    }
    let txn = vault.store.env.read_txn()?;
    for id in ids {
        if let Ok(Some(record)) = vault.get_skill_record_in_txn(&txn, id) {
            skills.insert(*id, (record.skill_id, record.desc));
        }
    }
    Ok(skills)
}

/// One paused arming as the caller reads it: its pin, and the SKILL's name
/// and description, only when the SKILL is among `readable`.
fn paused_item(
    arming: TurnProgramArming,
    paused_at: u64,
    readable: &BTreeSet<EntityId>,
    skills: &BTreeMap<EntityId, (String, String)>,
) -> PausedTurnProgramItem {
    let mut withheld = Vec::new();
    let skill = arming.definition.skill;
    let (definition, name, description) = if readable.contains(&skill) {
        let (name, description) = skills.get(&skill).cloned().unzip();
        (Some(arming.definition), name, description)
    } else {
        withheld.extend(["definition", "skill_name", "skill_description"].map(str::to_owned));
        (None, None, None)
    };
    PausedTurnProgramItem {
        registration: arming.registration,
        actor: arming.actor,
        actor_class: class_name(arming.actor_class),
        trigger: arming.trigger,
        next_due: arming.next_due,
        paused_at,
        definition,
        skill_name: name,
        skill_description: description,
        withheld,
    }
}

/// An arming's key in the arming table: its actor, then its registration.
fn arming_key(arming: &TurnProgramArming) -> (EntityId, EntityId) {
    (arming.actor, arming.registration)
}

/// A page's cursor: the key of its last program, as 64 hex characters.
fn cursor_text((actor, registration): (EntityId, EntityId)) -> String {
    format!("{}{}", actor.to_hex(), registration.to_hex())
}

fn arming_cursor(text: &str) -> MemoryResult<(EntityId, EntityId)> {
    let refusal = || MemoryError::bad_request("cursor must be 64 hex characters");
    let text = text.trim();
    if text.len() != 64 || !text.is_ascii() {
        return Err(refusal());
    }
    let (actor, registration) = text.split_at(32);
    Ok((
        EntityId::from_hex(actor).map_err(|_| refusal())?,
        EntityId::from_hex(registration).map_err(|_| refusal())?,
    ))
}
