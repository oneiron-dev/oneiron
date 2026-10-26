//! Saved context hints, one contribution per answered mention (FIX 8707).
//!
//! Every answer saves the words around its mention under the name and the
//! entity it named. Each mention keeps its own contribution, so an erase of
//! one mention's turn or message drops only that mention's words, and a word
//! another live mention gave stays. A read sums the contributions into one
//! [`IdentityHint`]: every contribution for the Dreamer's own pass and the
//! Linker, only those a reader admits for a caller (FIX 8711).
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::admission::Admit;
use super::erase::{SourceAnchor, ask_anchor_in_txn, stands_in_txn};
use super::{IdentityAsk, IdentityHint, context_terms};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// A hint row's key: the kind, the name's identity-hint digest and the
/// entity the answers named.
pub(super) type HintKey = ([u8; 1], [u8; 32], EntityId);

/// Context hints. Key: [`HintKey`].
pub(super) const HINTS: SideTable<HintKey, StoredIdentityHint, Named> =
    SideTable::new(&side_table::DREAMER_IDENTITY_HINT);

/// One answered mention's words for a name and the entity it named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IdentityHintSource {
    /// The mention the words came from.
    pub(super) source: SourceAnchor,
    /// The mention's text.
    pub(super) name: String,
    /// The words around it, as the ask kept them.
    pub(super) terms: Vec<String>,
    pub(super) saved_at: u64,
}

/// A saved context hint: each answered mention's own contribution, in the
/// order they were saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredIdentityHint {
    pub(super) sources: Vec<IdentityHintSource>,
}

impl StoredIdentityHint {
    /// Drops every contribution whose mention is in `id`, a turn or a
    /// message. True when it dropped one.
    fn erase_source(&mut self, id: &EntityId) -> bool {
        let before = self.sources.len();
        self.sources.retain(|each| !each.source.names(id));
        self.sources.len() != before
    }
}

/// The key of the hint for `ask`'s name and `entity`.
pub(super) fn hint_key(ask: &IdentityAsk, entity: EntityId) -> HintKey {
    (
        [ask.kind],
        crate::ingest::identity_hint_digest(&ask.name),
        entity,
    )
}

fn hint_prefix(kind: u8, name: &str) -> Vec<u8> {
    let mut prefix = vec![kind];
    prefix.extend_from_slice(&crate::ingest::identity_hint_digest(name));
    prefix
}

/// One entity's hint for a name, summed over the contributions `admit`
/// reads (every one without a reader), with the mentions it was summed
/// from.
pub(super) type SummedHint = (EntityId, IdentityHint, Vec<SourceAnchor>);

/// The hints saved for a name, by the entity each named, in entity order:
/// each the words of the contributions `admit` reads (every one without a
/// reader), once each, in saved order. An entity none of whose
/// contributions it reads has none.
pub(super) fn hints_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    (kind, name): (u8, &str),
    admit: Option<&Admit<'_, '_>>,
) -> Result<Vec<SummedHint>> {
    let mut summed = Vec::new();
    for ((_, _, entity), stored) in HINTS.scan_from(store, txn, &hint_prefix(kind, name))? {
        let mut hint: Option<IdentityHint> = None;
        let mut sources = Vec::new();
        for each in stored.sources {
            if let Some(admit) = admit
                && !admit.reads_source(txn, &each.source.turn, &each.source.message)?
            {
                continue;
            }
            let hint = hint.get_or_insert_with(|| IdentityHint {
                name: each.name.clone(),
                context: Vec::new(),
                saved_at: each.saved_at,
            });
            for term in each.terms {
                if !hint.context.contains(&term) {
                    hint.context.push(term);
                }
            }
            hint.saved_at = hint.saved_at.max(each.saved_at);
            sources.push(each.source);
        }
        if let Some(hint) = hint {
            summed.push((entity, hint, sources));
        }
    }
    Ok(summed)
}

/// The one of `candidates` whose hint shares the most words with
/// `context`; none on no shared word or a tie.
pub(super) fn pick(
    hints: &BTreeMap<EntityId, IdentityHint>,
    candidates: &[EntityId],
    context: &[String],
) -> Option<EntityId> {
    let mut best: Option<(EntityId, usize)> = None;
    let mut tied = false;
    for (entity, hint) in hints {
        if !candidates.contains(entity) {
            continue;
        }
        let shared = hint
            .context
            .iter()
            .filter(|term| context.contains(term))
            .count();
        if shared == 0 {
            continue;
        }
        match best {
            Some((_, top)) if shared < top => {}
            Some((_, top)) if shared == top => tied = true,
            _ => {
                best = Some((*entity, shared));
                tied = false;
            }
        }
    }
    best.filter(|_| !tied).map(|(entity, _)| entity)
}

/// Every saved hint for a name, summed over the contributions `admit`'s
/// lane reads, or over all of them with none: the Dreamer's own pass reads
/// them through its lane (FIX 10374); the effect doors' unsettled check and
/// the Linker read them whole and return no hint text to a caller.
fn all_hints_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (kind, name): (u8, &str),
    admit: Option<&Admit<'_, '_>>,
) -> Result<BTreeMap<EntityId, IdentityHint>> {
    Ok(hints_in_txn(&vault.store, txn, (kind, name), admit)?
        .into_iter()
        .map(|(entity, hint, _)| (entity, hint))
        .collect())
}

/// The one candidate of `ask` whose hint, as `admit`'s lane reads it (all
/// of it with none), shares the most words with its context; none on no
/// shared word or a tie.
pub(super) fn hinted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &IdentityAsk,
    admit: Option<&Admit<'_, '_>>,
) -> Result<Option<EntityId>> {
    let hints = all_hints_in_txn(vault, txn, (ask.kind, &ask.name), admit)?;
    Ok(pick(&hints, &ask.candidates, &ask.context))
}

/// The one of `candidates` a saved hint picks for a mention of `name` at
/// `start..end` of `text`, as the nightly re-check settles an ask: the
/// candidate whose hint shares the most words with the mention's context;
/// none on no shared word or a tie. The Linker reads it when it saves a
/// turn, so a saved hint settles a mention live.
#[allow(clippy::too_many_arguments)]
pub(crate) fn hinted_mention_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: u8,
    name: &str,
    text: &str,
    start: usize,
    end: usize,
    candidates: &[EntityId],
) -> Result<Option<EntityId>> {
    let context = context_terms(text, start, end, name);
    let hints = all_hints_in_txn(vault, txn, (kind, name), None)?;
    Ok(pick(&hints, candidates, &context))
}

/// Saves the words an answer was given in for its name and entity as the
/// answered mention's own contribution, beside every other mention's (Rule
/// 5: none is cut); an earlier answer on the same mention is replaced.
pub(super) fn put_hint_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ask: &IdentityAsk,
    entity: EntityId,
    now: u64,
) -> Result<()> {
    let key = hint_key(ask, entity);
    let source = ask_anchor_in_txn(vault, txn, ask)?;
    let mut stored = HINTS
        .get(&vault.store, txn, &key)?
        .unwrap_or_else(|| StoredIdentityHint {
            sources: Vec::new(),
        });
    let contribution = IdentityHintSource {
        source,
        name: ask.name.clone(),
        terms: ask.context.clone(),
        saved_at: now,
    };
    match stored
        .sources
        .iter_mut()
        .find(|each| each.source.same_span(&source))
    {
        Some(each) => *each = contribution,
        None => stored.sources.push(contribution),
    }
    HINTS.put(&vault.store, txn, &key, &stored)
}

/// `hint` without the contributions whose turn or message no longer stands
/// (deleted since it was copied); none when none is left. A revert puts back
/// only what still stands.
pub(super) fn standing_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    hint: &StoredIdentityHint,
) -> Result<Option<StoredIdentityHint>> {
    let mut sources = Vec::with_capacity(hint.sources.len());
    for each in &hint.sources {
        if stands_in_txn(store, txn, &each.source.turn)?
            && stands_in_txn(store, txn, &each.source.message)?
        {
            sources.push(each.clone());
        }
    }
    Ok((!sources.is_empty()).then_some(StoredIdentityHint { sources }))
}

/// Drops the erased `id`'s contributions from a kept copy of a hint; a copy
/// left with none is none. True when it changed.
pub(super) fn erase_snapshot(hint: &mut Option<StoredIdentityHint>, id: &EntityId) -> bool {
    let Some(held) = hint.as_mut() else {
        return false;
    };
    let changed = held.erase_source(id);
    if held.sources.is_empty() {
        *hint = None;
    }
    changed
}

/// Drops the erased `id`'s contributions, as a mention's turn or message,
/// from every saved hint, and every hint saved for it as the entity named;
/// a hint left with none goes.
pub(super) fn erase_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    for (key, mut stored) in HINTS.scan(store, txn)? {
        let changed = stored.erase_source(id);
        if key.2 == *id || stored.sources.is_empty() {
            HINTS.delete(store, txn, &key)?;
        } else if changed {
            HINTS.put(store, txn, &key, &stored)?;
        }
    }
    Ok(())
}
