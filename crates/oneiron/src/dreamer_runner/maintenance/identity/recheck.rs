//! The nightly recheck: finds uncertain person mentions and opens their asks.
//! Entry: `run` and `DreamerRunnerStore::enqueue_identity_recheck_in_txn`.
//! Owns `Uncertain` and the context terms; the ask types are in the parent.

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use super::super::MAINTENANCE_QUEUE_KIND;
use super::{
    ASKS, Answer, CURSOR, EXCERPT_BYTES, IDENTITY_RECHECK_FACET, IdentityAsk, IdentityAskReason,
    MAX_OPEN_ASKS, MAX_TERMS, MIN_TERM_CHARS, SCAN_TURNS, STOP_WORDS, ask_key, dreamer_seal,
    entity_of_kind_in_txn, hinted_in_txn, settle_undo,
};
use crate::claim::ClaimSource;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore};
use crate::limit_ask::EngineLimit;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::tagging::MentionLink;
use crate::{EntityId, Result, Vault};

/// An uncertain mention, before it is an ask.
struct Uncertain {
    kind: u8,
    candidates: Vec<EntityId>,
    provisional: Option<EntityId>,
}

fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| word.chars().count() >= MIN_TERM_CHARS)
        .map(str::to_lowercase)
        .filter(|word| !STOP_WORDS.contains(&word.as_str()))
}

/// The words nearest a span, outward from it, once each, without the name's
/// own words.
pub(super) fn context_terms(text: &str, start: usize, end: usize, name: &str) -> Vec<String> {
    let own: BTreeSet<String> = words(name).collect();
    let mut before: Vec<String> = words(text.get(..start).unwrap_or("")).collect();
    before.reverse();
    let after: Vec<String> = words(text.get(end..).unwrap_or("")).collect();
    let mut seen = BTreeSet::new();
    let mut terms = Vec::new();
    for index in 0..before.len().max(after.len()) {
        for word in [before.get(index), after.get(index)].into_iter().flatten() {
            if terms.len() < MAX_TERMS && !own.contains(word) && seen.insert(word.clone()) {
                terms.push(word.clone());
            }
        }
    }
    terms
}

/// The text around a span, cut on character boundaries.
fn excerpt(text: &str, start: usize, end: usize) -> String {
    let half = EXCERPT_BYTES / 2;
    let mut from = start.saturating_sub(half).min(text.len());
    while from > 0 && !text.is_char_boundary(from) {
        from -= 1;
    }
    let mut to = end.saturating_add(half).min(text.len());
    while to < text.len() && !text.is_char_boundary(to) {
        to += 1;
    }
    text.get(from..to).unwrap_or_default().to_owned()
}

/// Whether the link in `turn` is an uncertain person: two or more
/// candidates, or the mention's own provisional entity alone while its name
/// keys to real people now in a world the turn is in, as the Linker filters
/// them.
fn uncertain_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    link: &MentionLink,
    name: &str,
) -> Result<Option<Uncertain>> {
    let (kind, entities) = match link {
        MentionLink::Candidates { kind, entities } => (*kind, entities.clone()),
        MentionLink::Minted { kind, entity } => (*kind, vec![*entity]),
        MentionLink::Tag => return Ok(None),
    };
    if kind != ENTITY_TYPE_PERSON || entities.is_empty() {
        return Ok(None);
    }
    if entities.len() >= 2 {
        return Ok(Some(Uncertain {
            kind,
            candidates: entities,
            provisional: None,
        }));
    }
    let own = entities[0];
    if crate::tagging::provisional_in_txn(&vault.store, txn, &own)?.is_none() {
        return Ok(None);
    }
    let mut real = BTreeSet::new();
    for hit in vault.lookup_identity_key_in_txn(txn, kind, name)? {
        for head in vault.resolve_entity_in_txn(txn, &hit)? {
            if head != own
                && entity_of_kind_in_txn(vault, txn, &head, kind)?
                && crate::tagging::shares_world_in_txn(vault, txn, turn, &head)?
            {
                real.insert(head);
            }
        }
    }
    if real.is_empty() {
        return Ok(None);
    }
    let mut candidates: Vec<EntityId> = real.into_iter().collect();
    candidates.push(own);
    Ok(Some(Uncertain {
        kind,
        candidates,
        provisional: Some(own),
    }))
}

/// Whether two asks put one question: one name, one candidate set.
fn same_question(left: &IdentityAsk, right: &IdentityAsk) -> bool {
    let set = |ask: &IdentityAsk| ask.candidates.iter().copied().collect::<BTreeSet<_>>();
    left.kind == right.kind
        && crate::ingest::identity_hint_digest(&left.name)
            == crate::ingest::identity_hint_digest(&right.name)
        && set(left) == set(right)
}

/// Measures a new ask's name and candidates against the engine's rows; the
/// ask keeps both whole either way.
pub(super) fn measure_ask(vault: &Vault, ask: &IdentityAsk) {
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, ask.name.len() as u64);
    let items = ask.candidates.len();
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
}

/// The ask a saved mention would open, when it is uncertain.
pub(super) fn ask_for_mention_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    mention: &crate::tagging::TaggedMention,
    text: &str,
    reason: IdentityAskReason,
    now: u64,
) -> Result<Option<IdentityAsk>> {
    let Some(name) = text
        .get(mention.start..mention.end)
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        return Ok(None);
    };
    let Some(found) = uncertain_in_txn(vault, txn, *turn, &mention.link, name)? else {
        return Ok(None);
    };
    Ok(Some(IdentityAsk {
        kind: found.kind,
        name: name.to_owned(),
        turn: *turn,
        message: mention.message,
        start: mention.start,
        end: mention.end,
        candidates: found.candidates,
        provisional: found.provisional,
        context: context_terms(text, mention.start, mention.end, name),
        excerpt: excerpt(text, mention.start, mention.end),
        reason,
        opened_at: now,
        retry_at: 0,
        escalated_at: None,
        surfaced_turn: None,
        kept_separate_at: None,
    }))
}

/// Checks each mention of one turn again: a hint settles it, else it opens
/// an ask unless one is open for it or for its question. A kept-separate
/// ask whose candidates changed opens afresh, to be decided again. `false`
/// when a mention would open an ask past [`MAX_OPEN_ASKS`]: the turn is not
/// handled, and a later pass checks it again whole.
fn recheck_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    open: &mut Vec<([u8; 32], IdentityAsk)>,
    now: u64,
) -> Result<bool> {
    let Some(tags) = crate::tagging::readable_view_in_txn(&vault.store, txn, turn)? else {
        return Ok(true);
    };
    let mut texts: BTreeMap<EntityId, Option<String>> = BTreeMap::new();
    for mention in &tags.mentions {
        if !texts.contains_key(&mention.message) {
            let text = crate::tagging::message_text_in_txn(vault, txn, turn, &mention.message)?;
            texts.insert(mention.message, text);
        }
        let Some(Some(text)) = texts.get(&mention.message) else {
            continue;
        };
        let key = ask_key(turn, &mention.message, mention.start, mention.end);
        if let Some((_, held)) = open.iter_mut().find(|(held, _)| *held == key) {
            if held.kept_separate_at.is_some()
                && let Some(fresh) = ask_for_mention_in_txn(
                    vault,
                    txn,
                    turn,
                    mention,
                    text,
                    IdentityAskReason::Unsettled,
                    now,
                )?
                && fresh.candidates != held.candidates
            {
                measure_ask(vault, &fresh);
                ASKS.put(&vault.store, txn, &key, &fresh)?;
                *held = fresh;
            }
            continue;
        }
        let Some(ask) = ask_for_mention_in_txn(
            vault,
            txn,
            turn,
            mention,
            text,
            IdentityAskReason::Unsettled,
            now,
        )?
        else {
            continue;
        };
        if let Some(entity) = hinted_in_txn(vault, txn, &ask)? {
            settle_undo::settle_in_txn(
                vault,
                txn,
                &ask,
                Answer::Is(entity),
                (ClaimSource::Inferred, &dreamer_seal()),
                now,
            )?;
            continue;
        }
        if open.iter().any(|(_, held)| same_question(held, &ask)) {
            continue;
        }
        let waiting = open
            .iter()
            .filter(|(_, held)| held.kept_separate_at.is_none())
            .count();
        if waiting >= MAX_OPEN_ASKS {
            return Ok(false);
        }
        measure_ask(vault, &ask);
        ASKS.put(&vault.store, txn, &key, &ask)?;
        open.push((key, ask));
    }
    Ok(true)
}

impl DreamerRunnerStore<'_> {
    /// The nightly identity re-check, one per wake key, while the vault
    /// tags its turns.
    pub(in crate::dreamer_runner::maintenance) fn enqueue_identity_recheck_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<crate::attempt_queue::AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<()> {
        if self.vault.config.tagging.is_none() {
            return Ok(());
        }
        self.enqueue_kind_in_txn(
            txn,
            MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: IDENTITY_RECHECK_FACET.into(),
                input: Value::Nil,
                parent_attempt,
            },
            wake_key.map(|key| {
                format!(
                    "{IDENTITY_RECHECK_FACET}:{}",
                    blake3::hash(key.as_bytes()).to_hex()
                )
            }),
            run_id,
            now,
        )?;
        Ok(())
    }
}

/// One nightly page: each uncertain mention of the page's turns is settled
/// by a hint or opens an ask. The cursor moves past the page, and starts
/// over once a page comes back short. A turn that would open an ask past a
/// full tray stops the page: the cursor stays at the last turn handled, so
/// the next pass starts at the one that waited.
pub(in crate::dreamer_runner::maintenance) fn run(
    vault: &Vault,
    _attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let after = CURSOR.get(&vault.store, txn, &())?;
        let (page, last) =
            crate::tagging::readable_page_in_txn(&vault.store, txn, after.as_ref(), SCAN_TURNS)?;
        let mut open = ASKS.scan(&vault.store, txn)?;
        let mut handled = None;
        for tags in &page {
            if !recheck_turn_in_txn(vault, txn, &tags.turn, &mut open, now)? {
                // The page reads after the cursor, so the next pass starts at
                // the turn that waited; before the page's first turn the
                // cursor stays where it was.
                if let Some(turn) = handled {
                    CURSOR.put(&vault.store, txn, &(), &turn)?;
                }
                return Ok(());
            }
            handled = Some(tags.turn);
        }
        match last {
            Some(last) if page.len() == SCAN_TURNS => CURSOR.put(&vault.store, txn, &(), &last)?,
            _ => {
                CURSOR.delete(&vault.store, txn, &())?;
            }
        }
        Ok(())
    })
}
