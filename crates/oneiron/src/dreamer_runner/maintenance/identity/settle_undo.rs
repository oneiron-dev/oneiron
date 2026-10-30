//! The Dreamer's automatic identity settles, receipted and revertible (FIX
//! 3327, OF-023). A saved hint's pick in the nightly re-check and a
//! decision's choice on an open ask settle a mention at once, as before, and
//! an act-now ask's answer still lets its agent act now. Each settle also
//! records, in its own write, what it changed, before and after: the
//! mention's link and every saved span of a provisional entity the mention
//! named (which the settle may absorb or retire), those provisional
//! entities, the name's context hint, and the distinct assertions a
//! someone-new answer made, under the Dreamer's receipt.
//!
//! The owner's revert counters each change only where it still stands as
//! the settle left it, and never lays the snapshot over newer state: a span
//! a later write moved, a hint a later answer grew or an assertion changed
//! since is left as it is and listed. A person a someone-new answer
//! confirmed stays a person, as a synced record is never unborn, and is
//! listed as left alone. Once the mention links as it did before, the
//! question goes to the owner, as the revert of "keep them separate for
//! now" does.
//!
//! An erase reaches the inverse too (FIX 8707): it takes the copy of the
//! ask, a provisional entity's row or a hint's words that came from the
//! erased turn or message, and keeps the content-free anchors, so the rest
//! still reverts. The revert puts nothing back whose mention, span text or
//! entity no longer stands as the settle saw it, and lists it as left alone.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::super::applied::{self, MaintenanceInverse, MaintenanceRevert, MaintenanceTarget};
use super::erase::{
    SourceAnchor, anchor_in_txn, anchor_reads_in_txn, ask_anchor_in_txn, span_reads_in_txn,
};
use super::hints::{self, HINTS, StoredIdentityHint};
use super::{
    ASKS, Answer, IDENTITY_RECHECK_FACET, IdentityAsk, apply_in_txn, ask_key, escalate_in_txn,
    evidence, index, invalid, key_hex,
};
use crate::claim::ClaimSource;
use crate::identity_topology::TopologySeal;
use crate::ports::EntityStoreRead;
use crate::tagging::{MentionLink, ProvisionalEntity};
use crate::{ClaimLifecycleStatus, EntityId, Result, Vault, WriteActor};

mod erase;

/// The hint row's name in a revert's settings list.
const HINT_ROW: &str = "identity_hint";

/// One saved span a settle changed, or the settled mention itself: its link
/// before and after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MentionChange {
    turn: EntityId,
    message: EntityId,
    start: usize,
    end: usize,
    before: MentionLink,
    after: MentionLink,
}

impl MentionChange {
    /// The span's key, as an ask on it would be keyed.
    fn key(&self) -> [u8; 32] {
        ask_key(&self.turn, &self.message, self.start, self.end)
    }
}

/// One automatic settle's inverse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::dreamer_runner::maintenance) struct SettleInverse {
    /// The ask the settle answered, as it stood: the owner's question once
    /// the revert puts the mention back. None once an erase reached its
    /// mention.
    ask: Option<IdentityAsk>,
    /// Where the ask's mention is, without its text.
    source: SourceAnchor,
    /// The entity the mention was settled as.
    entity: EntityId,
    settled_at: u64,
    /// Each saved span whose link the settle changed.
    mentions: Vec<MentionChange>,
    /// Each provisional entity the mention named, as it stood before.
    provisionals: Vec<HeldProvisional>,
    /// The name's context hint for `entity` before (none: unsaved) and after.
    hint_before: Option<StoredIdentityHint>,
    hint_after: Option<StoredIdentityHint>,
    /// The person a someone-new answer confirmed, when it confirmed one.
    confirmed: Option<EntityId>,
    /// Each distinct assertion a someone-new answer made, at its revision
    /// then.
    distinct: Vec<(EntityId, [u8; 32])>,
}

impl SettleInverse {
    /// Every id whose erase would change this inverse (FIX 10376): the ask
    /// copy's ids while it stands, each held provisional's id, name span
    /// and origin while its row stands, the settled entity, and both hint
    /// copies' spans. The source anchor, the spans' links, the distinct
    /// assertions and the confirmed person are none: the erase never
    /// scrubs them.
    pub(super) fn named_ids(&self) -> BTreeSet<EntityId> {
        let mut ids = BTreeSet::new();
        if let Some(ask) = &self.ask {
            ids.extend(super::index::ask_ids(ask));
        }
        for held in &self.provisionals {
            // While its row stands only: with `entity: None` the scrub
            // returns false even on an id match.
            if let Some(entity) = &held.entity {
                ids.insert(held.id);
                if let Some(source) = &held.source {
                    ids.insert(source.turn);
                    ids.insert(source.message);
                }
                ids.insert(entity.origin);
            }
        }
        ids.insert(self.entity);
        for hint in [&self.hint_before, &self.hint_after].into_iter().flatten() {
            for each in &hint.sources {
                ids.insert(each.source.turn);
                ids.insert(each.source.message);
            }
        }
        ids
    }
}

/// A provisional entity a settle may retire, as it stood before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldProvisional {
    id: EntityId,
    /// The span in its origin turn its name was read from, when one read it.
    source: Option<SourceAnchor>,
    /// Its row; none once an erase reached the entity, its origin turn or
    /// that span.
    entity: Option<ProvisionalEntity>,
}

/// The heads the ask's candidates resolve to now: who a someone-new answer
/// asserts its person distinct from.
fn heads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
) -> Result<BTreeSet<EntityId>> {
    let mut heads = BTreeSet::new();
    for candidate in &ask.candidates {
        heads.extend(vault.resolve_entity_in_txn(txn, candidate)?);
    }
    Ok(heads)
}

/// The effective distinct assertions between `entity` and each of `heads`.
fn distinct_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: EntityId,
    heads: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut claims = BTreeSet::new();
    for head in heads {
        if *head != entity {
            claims.extend(vault.distinct_claims_for_pair_in_txn(txn, &entity, head)?);
        }
    }
    Ok(claims)
}

/// The context hint saved for `ask`'s name and `entity`.
fn hint_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
    entity: EntityId,
) -> Result<Option<StoredIdentityHint>> {
    HINTS.get(&vault.store, txn, &hints::hint_key(ask, entity))
}

/// Settles `ask`'s mention as `answer` for the Dreamer, as an ask's settle
/// does, and records what it changed, before and after, with the Dreamer's
/// receipt in the same write. Returns the entity the mention names.
pub(super) fn settle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ask: &IdentityAsk,
    answer: Answer,
    said: (ClaimSource, &TopologySeal),
    now: u64,
) -> Result<EntityId> {
    let key = ask_key(&ask.turn, &ask.message, ask.start, ask.end);
    let source = ask_anchor_in_txn(vault, txn, ask)?;
    let settled =
        vault.saved_mention_link_in_txn(txn, &ask.turn, (&ask.message, ask.start, ask.end))?;
    // Every span the settle may change: the mention, and each span naming a
    // provisional entity the mention names.
    let mut named: BTreeSet<EntityId> = settled
        .iter()
        .flat_map(|link| link.entities().iter().copied())
        .collect();
    named.extend(ask.provisional);
    let primary = (ask.turn, ask.message, ask.start, ask.end);
    let mut spans = BTreeMap::new();
    if let Some(link) = settled {
        spans.insert(primary, link);
    }
    let mut provisionals = Vec::new();
    for id in named {
        let Some(entity) = crate::tagging::provisional_in_txn(&vault.store, txn, &id)? else {
            continue;
        };
        // The span in its origin turn its name reads from: a revert holds
        // the entity again only while that span still reads so.
        let mut origin = None;
        for (turn, mention) in vault.mentions_naming_in_txn(txn, &id)? {
            let span = (turn, mention.message, mention.start, mention.end);
            if origin.is_none()
                && turn == entity.origin
                && span_reads_in_txn(vault, txn, span, &entity.name)?
            {
                origin = Some(anchor_in_txn(vault, txn, span)?);
            }
            spans.entry(span).or_insert(mention.link);
        }
        provisionals.push(HeldProvisional {
            id,
            source: origin,
            entity: Some(entity),
        });
    }
    let hinted = match answer {
        Answer::Is(chosen) => Some(chosen),
        Answer::SomeoneNew => ask.provisional,
    };
    let hint_before = match hinted {
        Some(entity) => hint_in_txn(vault, txn, ask, entity)?,
        None => None,
    };
    let (heads, distinct_before, was_present) = match (answer, ask.provisional) {
        (Answer::SomeoneNew, Some(own)) => {
            let heads = heads_in_txn(vault, txn, ask)?;
            let distinct = distinct_in_txn(vault, txn, own, &heads)?;
            let present = EntityStoreRead::port_entity_present(&vault.store, txn, &own)?;
            (heads, distinct, present)
        }
        (Answer::SomeoneNew, None) => (heads_in_txn(vault, txn, ask)?, BTreeSet::new(), false),
        (Answer::Is(_), _) => (BTreeSet::new(), BTreeSet::new(), true),
    };
    let entity = apply_in_txn(vault, txn, ask, answer, said, now)?;
    let mut mentions = Vec::new();
    for ((turn, message, start, end), before) in spans {
        let Some(after) = vault.saved_mention_link_in_txn(txn, &turn, (&message, start, end))?
        else {
            continue;
        };
        // The mention itself is kept even when its link did not move (a
        // someone-new answer on its own provisional entity), so its revert
        // still asks the owner.
        if after != before || (turn, message, start, end) == primary {
            mentions.push(MentionChange {
                turn,
                message,
                start,
                end,
                before,
                after,
            });
        }
    }
    let mut distinct = Vec::new();
    for claim in distinct_in_txn(vault, txn, entity, &heads)? {
        if distinct_before.contains(&claim) {
            continue;
        }
        let revision = applied::claim_revision_in_txn(vault, txn, &claim)?
            .ok_or_else(|| invalid("a distinct assertion has no body"))?;
        distinct.push((claim, revision));
    }
    let confirmed = (!was_present
        && EntityStoreRead::port_entity_present(&vault.store, txn, &entity)?)
    .then_some(entity);
    let inverse = SettleInverse {
        ask: Some(ask.clone()),
        source,
        entity,
        settled_at: now,
        mentions,
        provisionals,
        hint_before: hint_before.filter(|_| hinted == Some(entity)),
        hint_after: hint_in_txn(vault, txn, ask, entity)?,
        confirmed,
        distinct,
    };
    let actor = vault.dreamer_authority_in_txn(txn, now)?;
    applied::record_disposition_in_txn(
        vault,
        txn,
        key,
        IDENTITY_RECHECK_FACET,
        actor,
        MaintenanceInverse::IdentitySettle(Box::new(inverse)),
        ask,
        Some(entity),
        now,
    )?;
    Ok(entity)
}

/// The owner's revert of one automatic settle, as `owner`: each provisional
/// entity it retired is held again while its id is free and its name's span
/// reads as it did, each span it changed goes back where it still links as
/// the settle left it and it, its message and the entities it linked stand
/// (a held entity's origin turn first), a held entity no restored span names
/// goes again, the hint and the resolution go back where they still hold
/// what the settle saved, and each distinct assertion it made is retracted
/// where it stands at its revision then. Once the mention links as before,
/// still reads as it did and no ask is open on it, the ask goes to the owner
/// as today's question. What an erase took is listed as left alone.
pub(in crate::dreamer_runner::maintenance) fn revert_settle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    inverse: &SettleInverse,
    owner: WriteActor,
    now: u64,
    out: &mut MaintenanceRevert,
) -> Result<()> {
    let MaintenanceTarget::IdentityAsk(key) = out.target else {
        return Err(invalid("the revert names no ask"));
    };
    let mut held = Vec::new();
    for each in &inverse.provisionals {
        // A row an erase took, or whose name no longer reads as it did, is
        // not held again (FIX 8707).
        let Some(entity) = &each.entity else {
            out.left_alone.push(each.id.to_hex());
            continue;
        };
        if !erase::provisional_reads_in_txn(vault, txn, each, entity)? {
            out.left_alone.push(each.id.to_hex());
            continue;
        }
        if vault.rehold_provisional_in_txn(txn, &each.id, entity)? {
            held.push((each.id, entity.origin));
        }
    }
    let mut changes: Vec<&MentionChange> = inverse.mentions.iter().collect();
    changes.sort_by_key(|change| !held.iter().any(|(_, origin)| *origin == change.turn));
    let mut settled_back = false;
    for change in changes {
        let span = (&change.message, change.start, change.end);
        let back = if !erase::change_stands_in_txn(vault, txn, change)? {
            false
        } else if change.before == change.after {
            vault
                .saved_mention_link_in_txn(txn, &change.turn, span)?
                .as_ref()
                == Some(&change.after)
        } else {
            vault.relink_mention_in_txn(txn, &change.turn, span, &change.after, &change.before)?
        };
        if back {
            settled_back |= change.key() == key;
        } else {
            out.left_alone.push(key_hex(&change.key()));
        }
    }
    for (id, _) in &held {
        vault.settle_provisional_in_txn(txn, id)?;
        if crate::tagging::provisional_in_txn(&vault.store, txn, id)?.is_some() {
            out.restored.push(*id);
        }
    }
    // An erase that reached the ask's mention, or the entity, took the
    // settle's words out of the row and both copies: nothing is left to put
    // back. A word whose mention was deleted since is not put back.
    let hint = inverse
        .ask
        .as_ref()
        .filter(|_| inverse.hint_before.is_some() || inverse.hint_after.is_some())
        .map(|ask| hints::hint_key(ask, inverse.entity));
    let stands = match &hint {
        Some(hint) => HINTS.get(&vault.store, txn, hint)? == inverse.hint_after,
        None => false,
    };
    match hint.filter(|_| stands) {
        Some(hint) => {
            let before = match &inverse.hint_before {
                Some(before) => hints::standing_in_txn(&vault.store, txn, before)?,
                None => None,
            };
            // `stands` read the row as `hint_after`, so the old set is exact
            // without another read (FIX 10376).
            match before {
                Some(before) => {
                    HINTS.put(&vault.store, txn, &hint, &before)?;
                    index::sync_hint_membership(
                        &vault.store,
                        txn,
                        &hint,
                        inverse.hint_after.as_ref(),
                        Some(&before),
                    )?;
                }
                None => {
                    HINTS.delete(&vault.store, txn, &hint)?;
                    index::sync_hint_membership(
                        &vault.store,
                        txn,
                        &hint,
                        inverse.hint_after.as_ref(),
                        None,
                    )?;
                }
            }
            out.settings.push(HINT_ROW.to_owned());
        }
        None => out.left_alone.push(HINT_ROW.to_owned()),
    }
    if let Some(ask) = &inverse.ask {
        evidence::clear_settle_resolution_in_txn(
            vault,
            txn,
            ask,
            inverse.entity,
            inverse.settled_at,
        )?;
    }
    for (claim, revision) in &inverse.distinct {
        let stands = vault
            .get_claim_in_txn(&*txn, claim)?
            .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Active);
        if stands && applied::claim_revision_in_txn(vault, &*txn, claim)? == Some(*revision) {
            vault.retract_claim_in_txn_as(txn, claim, now, Some(owner))?;
            out.closed.push(*claim);
        } else {
            out.left_alone.push(claim.to_hex());
        }
    }
    if let Some(person) = inverse.confirmed {
        out.left_alone.push(person.to_hex());
    }
    if settled_back && !ASKS.contains(&vault.store, &*txn, &key)? {
        // The question goes back only while its mention reads as it did.
        let reads = match &inverse.ask {
            Some(ask) => anchor_reads_in_txn(vault, txn, &inverse.source, &ask.name)?,
            None => false,
        };
        match inverse.ask.as_ref().filter(|_| reads) {
            Some(ask) => {
                let ask = IdentityAsk {
                    kept_separate_at: None,
                    ..ask.clone()
                };
                escalate_in_txn(vault, txn, &key, ask, now)?;
                out.asked.push(key_hex(&key));
            }
            None => out.left_alone.push(key_hex(&key)),
        }
    }
    Ok(())
}
