//! Assembles one digest in one write: select, mark seen, store, notify.
//! Entry: `Vault::assemble_proactivity_digest`, for timer and urgent digests.
//! The digest types, tables and load helpers are in the parent.

use std::collections::BTreeMap;

use super::super::agent_health;
use super::{
    DIGEST, DIGEST_NOTIFICATION_PRODUCER, DigestApplied, DigestAudience, DigestCleanup,
    DigestNoteTombstones, DigestOffer, DigestProposal, DigestState, JUDGE_ASK_MARK,
    ProactivityDigest, ProactivityPresentation, STATE, after_notice, load_ask_mark, load_cadence,
    load_presentation, load_state, pending_proposals, private_sources, unseen_cleanup,
    unseen_note_tombstones, unseen_offers, view,
};
use crate::{EntityId, Result, Vault};

impl Vault {
    pub(super) fn assemble_proactivity_digest(
        &self,
        audience: DigestAudience<'_>,
        now: u64,
    ) -> Result<Option<ProactivityDigest>> {
        let authority = self.dreamer_authority()?.entity_ref();
        let pending_offers = crate::skill_optimize::pending_training_offers(self)?;
        self.with_write_txn_grouped(|txn| {
            // A witnessed answer whose intent or owner moved delivers nothing.
            let Some(recipient) = audience.recipient_in(self, txn)? else {
                return Ok(None);
            };
            let cadence = load_cadence(self, &*txn)?;
            let presentation = load_presentation(self, &*txn)?;
            let state = load_state(self, &*txn)?;
            let next = state
                .last_regular
                .map(|last| last.saturating_add(cadence.period_secs));
            // A witnessed urgent delivery never runs the regular cadence, so
            // it never moves `last_regular` (OF-194).
            let due = audience.regular() && next.is_none_or(|next| now >= next);
            // Judge and eval label asks spend one human's funded minutes, so
            // each recipient keeps its own mark on the shared vault cadence:
            // one person's digest never consumes another's.
            let asks_due = match &recipient {
                Some(actor) if audience.regular() => load_ask_mark(self, &*txn, actor)?
                    .is_none_or(|last| now >= last.saturating_add(cadence.period_secs)),
                _ => false,
            };
            let breakthrough =
                audience.breaks_through_in(self, txn, recipient, next, now, &cadence)?;
            if !due && !breakthrough && !asks_due {
                return Ok(None);
            }
            let mut groups: BTreeMap<String, Vec<DigestProposal>> = BTreeMap::new();
            for (group, mut proposal) in
                pending_proposals(self, txn, authority, &state, &cadence, recipient)?
            {
                if !due
                    && (!breakthrough
                        || !presentation.urgent_groups.contains(&group)
                        || !audience.carries(&proposal))
                {
                    continue;
                }
                // FIX 6411: the private thread turns its words come from are
                // pinned on it. A recipient's own digest carries only what
                // they read; the rest stays unseen for the timer digest,
                // which every owner reads screened.
                match private_sources::digest_private_sources_in(self, txn, proposal.claim_ref) {
                    Some(pins) => proposal.private_sources = pins,
                    None => proposal.unverified = true,
                }
                if let Some(actor) = recipient
                    && !private_sources::digest_item_readable_by_in(self, txn, &proposal, actor)
                {
                    continue;
                }
                let display_group = presentation
                    .group_aliases
                    .get(&group)
                    .cloned()
                    .unwrap_or(group);
                groups.entry(display_group).or_default().push(proposal);
            }
            // Judge asks are paid first; eval label asks spend what remains.
            let (judge_asks, eval_label_asks) = match recipient {
                Some(actor) if asks_due => (
                    crate::skill_optimize::take_digest_asks_in_txn(self, txn, actor, now)?,
                    crate::skill_optimize::take_digest_eval_asks_in_txn(self, txn, actor, now)?,
                ),
                _ => (Vec::new(), Vec::new()),
            };
            // Offers ride the regular cadence; an urgent wake is about its intent.
            let offers = if due {
                unseen_offers(&pending_offers, &state)
            } else {
                Vec::new()
            };
            // So do the cleanup after-notice and the NOTE tombstone line:
            // neither is urgent.
            let cleanup = if due {
                unseen_cleanup(self, &*txn, &state)?
            } else {
                None
            };
            let note_tombstones = if due {
                unseen_note_tombstones(self, &*txn, &state)?
            } else {
                None
            };
            // So does the applied-maintenance after-notice.
            let applied = if due {
                after_notice::unseen_in_txn(self, &*txn, &state.applied_seen)?
            } else {
                None
            };
            // So do the health cards: each one opened, updated or settled in
            // the period `[from, now)`, read in this write's own snapshot by
            // the test the public period reader keeps (FIX 1979).
            let health_cards: Vec<_> = if due {
                let from = state.last_regular.unwrap_or(0);
                agent_health::agent_health_cards_in_txn(self, &*txn)?
                    .iter()
                    .filter(|card| agent_health::card_touched_in(card, from, now).is_some())
                    .map(agent_health::ConcernCardSummary::of)
                    .collect()
            } else {
                Vec::new()
            };
            if groups.is_empty()
                && judge_asks.is_empty()
                && eval_label_asks.is_empty()
                && offers.is_empty()
                && cleanup.is_none()
                && note_tombstones.is_none()
                && applied.is_none()
                && health_cards.is_empty()
            {
                return Ok(None);
            }
            // A host-built urgent delivery names the witness its own
            // assembly enqueued (FIX 10942); every other audience keeps
            // `witness()`.
            let witness = match &audience {
                DigestAudience::Owner(_, Some(assessment))
                    if !due && breakthrough && !groups.is_empty() =>
                {
                    Some(super::urgent::enqueue_host_witness_in_txn(
                        self, txn, assessment, now,
                    )?)
                }
                _ => audience.witness(),
            };
            self.finish_digest_in_txn(
                txn,
                DigestParts {
                    state,
                    groups,
                    judge_asks,
                    eval_label_asks,
                    offers,
                    cleanup,
                    note_tombstones,
                    applied,
                    health_cards,
                    presentation,
                    recipient,
                    witness,
                    due,
                    breakthrough,
                    now,
                },
            )
        })
    }

    /// The tail of one assembly, in its write: marks what the digest carries
    /// seen, renders, admits and stores it, notifies its readers, and moves
    /// the vault state, the board pointer and the recipient's ask mark.
    fn finish_digest_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parts: DigestParts,
    ) -> Result<Option<ProactivityDigest>> {
        let DigestParts {
            mut state,
            mut groups,
            judge_asks,
            eval_label_asks,
            offers,
            cleanup,
            note_tombstones,
            applied,
            health_cards,
            presentation,
            recipient,
            witness,
            due,
            breakthrough,
            now,
        } = parts;
        let is_urgent = !due && breakthrough && !groups.is_empty();
        // What this digest carries is marked seen; its text follows,
        // under the presentation it keeps. An urgent digest marks it seen
        // for its one owner alone (FIX 8952).
        let seen = match recipient {
            Some(owner) if is_urgent => state.urgent_seen.entry(owner.to_hex()).or_default(),
            _ => &mut state.seen,
        };
        for proposals in groups.values_mut() {
            proposals.sort_by_key(|p| p.claim_ref);
            for proposal in proposals.iter() {
                seen.insert(proposal.claim_ref.to_hex(), proposal.revision);
            }
        }
        state
            .offers_seen
            .extend(offers.iter().map(|offer| offer.offer.to_hex()));
        if let Some(line) = &cleanup {
            state.cleanup_seen.extend(line.decisions.iter().cloned());
            state.cleanup_seen.extend(line.proposals.iter().cloned());
        }
        if let Some(line) = &note_tombstones {
            state
                .note_tombstones_seen
                .extend(line.proposals.iter().cloned());
        }
        if let Some(line) = &applied {
            line.mark_seen(&mut state.applied_seen);
        }
        let mut digest = ProactivityDigest {
            id: [0; 32],
            content_hash: [0; 32],
            created_at: now,
            recipient,
            urgent: is_urgent,
            groups,
            judge_asks,
            eval_label_asks,
            offers,
            cleanup,
            note_tombstones,
            applied,
            health_cards,
            rendered: String::new(),
            voice_style: presentation.voice_style.clone(),
            presentation,
            witness,
        };
        let rendered = view::render(&digest, &digest.groups);
        digest.rendered = rendered;
        // FIX 2332 (OF-067): the id is the digest's stable locator, the
        // hash of the digest as assembled. The side-row wall admits it
        // under that id and the table stores it under the same one, so a
        // mask's origin names the row it masked; the content hash, over
        // the digest as admitted, is its integrity check.
        let locator = view::digest_id(&digest)?;
        digest.id = locator;
        DIGEST.admit(self, txn, &locator, &mut digest)?;
        digest.content_hash = view::content_hash(&digest)?;
        DIGEST.put(&self.store, txn, &locator, &digest)?;
        // Delivery is the reader's inbox, in this same write: one
        // NOTIFICATION per reader, keyed by digest, whose seen and acked
        // marks are the reader's own and never this digest's `seen`. The
        // timer digest has no reader of its own, so every owner gets it.
        let id = crate::entity_id::bytes_to_hex_lower(&digest.id);
        let readers = match recipient {
            Some(actor) => vec![actor],
            None => crate::policy_model::owners_in_txn(self, &*txn)?,
        };
        for reader in readers {
            // FIX 6411: each reader is told of the digest as they read
            // it, and one whose view carries nothing is not told: a
            // shared timer digest is no shared authorization.
            if view::digest_view_for_in(self, txn, &digest, reader).is_empty() {
                continue;
            }
            self.record_notification_in_txn(
                txn,
                &crate::inbox::NotificationEvent {
                    kind: crate::inbox::NotificationKind::Digest,
                    source: crate::inbox::NotificationSource {
                        producer: DIGEST_NOTIFICATION_PRODUCER.to_owned(),
                        event: format!("{id}:{}", reader.to_hex()),
                        result: Some(id.clone()),
                        ..crate::inbox::NotificationSource::default()
                    },
                    subject_refs: Vec::new(),
                    recipient: Some(reader),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
        }
        // The vault state and board pointer follow the shared news, health
        // cards included; an asks-only digest is the recipient's and
        // moves only its mark.
        if !digest.groups.is_empty()
            || !digest.offers.is_empty()
            || digest.cleanup.is_some()
            || digest.note_tombstones.is_some()
            || digest.applied.is_some()
            || !digest.health_cards.is_empty()
        {
            if due {
                state.last_regular = Some(now);
            }
            state.last_digest_id = Some(digest.id);
            STATE.put(&self.store, txn, &(), &state)?;
        }
        let asked = !digest.judge_asks.is_empty() || !digest.eval_label_asks.is_empty();
        if let Some(actor) = recipient.filter(|_| asked) {
            JUDGE_ASK_MARK.put(&self.store, txn, &actor, &now)?;
        }
        Ok(Some(digest))
    }
}

/// What an assembly found, carried into the write's tail.
struct DigestParts {
    state: DigestState,
    groups: BTreeMap<String, Vec<DigestProposal>>,
    judge_asks: Vec<crate::skill_optimize::JudgeAsk>,
    eval_label_asks: Vec<crate::skill_optimize::EvalLabelAsk>,
    offers: Vec<DigestOffer>,
    cleanup: Option<DigestCleanup>,
    note_tombstones: Option<DigestNoteTombstones>,
    applied: Option<DigestApplied>,
    health_cards: Vec<agent_health::ConcernCardSummary>,
    presentation: ProactivityPresentation,
    recipient: Option<EntityId>,
    witness: Option<crate::attempt_queue::AttemptId>,
    due: bool,
    breakthrough: bool,
    now: u64,
}
