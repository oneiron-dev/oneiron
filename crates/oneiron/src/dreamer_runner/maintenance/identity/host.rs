//! Identity doors on `Vault`: list, render, decide, resurface, answer asks.
//! Entry: `Vault::decide_identity_ask` and the ask list and answer doors.
//! Each door reads through its caller's lane; settlement is in `settlement`.

use serde_json::json;

use super::{
    ASKS, Answer, IdentityAsk, IdentityAskReason, IdentityAskView, IdentityCardCopy,
    IdentityDecisions, IdentityRuling, IdentitySettled, RETRY_SECS, SOMEONE_NEW, admission,
    ask_answer_id, card, dreamer_seal, escalate_in_txn, evidence, invalid, keep_separate_in_txn,
    key_hex, listed_candidates, notify_in_txn, options_in_txn, parse_choice, parse_key,
    settle_ask_in_txn, settle_undo, view_in_txn,
};
use crate::authority::{ActAuthority, ActSurface};
use crate::claim::{ClaimSource, ScopedRead};
use crate::consent::AuthenticatedOwner;
use crate::identity_topology::TopologySeal;
use crate::lens::GeneratedUiCard;
use crate::llm::decision::catalogue::IDENTITY_SETTLE;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, MAX_DECISION_STATE_BYTES, Reversibility, cut_text, fit_state,
};
use crate::{Result, Vault};

impl Vault {
    /// Open asks the host decides now, act-now ones first, up to `limit`,
    /// as 64 hex: none sent to the person yet, none kept separate, none
    /// waiting on a retry, and only those `read` reads whole (FIX 8711): one
    /// with a candidate or a span it does not read waits for the owner.
    pub fn identity_asks_due(
        &self,
        read: &ScopedRead<'_>,
        now: u64,
        limit: usize,
    ) -> Result<Vec<String>> {
        let txn = self.store.env.read_txn()?;
        let admit = admission::Admit::in_txn(read, &txn)?;
        let mut due: Vec<(bool, u64, [u8; 32])> = Vec::new();
        for (key, ask) in ASKS.scan(&self.store, &txn)? {
            if ask.escalated_at.is_some() || ask.kept_separate_at.is_some() || ask.retry_at > now {
                continue;
            }
            let later = !matches!(ask.reason, IdentityAskReason::ActNow { .. });
            let opened_at = ask.opened_at;
            if admission::admitted_in_txn(self, &admit, &txn, ask)?.is_some_and(|seen| seen.whole())
            {
                due.push((later, opened_at, key));
            }
        }
        due.sort_unstable();
        Ok(due
            .into_iter()
            .take(limit)
            .map(|(_, _, key)| key_hex(&key))
            .collect())
    }

    /// Every open ask `read` reads, as the owner reads it: only the
    /// candidates it reads are options (FIX 8711).
    pub fn identity_asks(&self, read: &ScopedRead<'_>) -> Result<Vec<IdentityAskView>> {
        let txn = self.store.env.read_txn()?;
        let admit = admission::Admit::in_txn(read, &txn)?;
        let mut views = Vec::new();
        for (key, ask) in ASKS.scan(&self.store, &txn)? {
            if let Some(seen) = admission::admitted_in_txn(self, &admit, &txn, ask)? {
                views.push(view_in_txn(self, &txn, &key, &seen.ask)?);
            }
        }
        Ok(views)
    }

    /// One open ask's choice card, worded by `copy`, with a button for each
    /// candidate `read` reads; an ask it does not read is no such open ask.
    pub fn identity_card(
        &self,
        read: &ScopedRead<'_>,
        ask: &str,
        copy: &IdentityCardCopy,
    ) -> Result<GeneratedUiCard> {
        let key = parse_key(ask).ok_or_else(|| invalid("the ask is 64 hex"))?;
        let txn = self.store.env.read_txn()?;
        let held = admission::open_ask_in_txn(self, read, &txn, &key, false)?
            .ok_or_else(|| invalid("no such open ask"))?
            .ask;
        let options = options_in_txn(self, &txn, &held)?;
        card(&key, &held, &options, copy)
    }

    /// Asks one open ask on the host's ladder: a Choice over its listed
    /// candidates ([`MAX_CANDIDATES`], its own provisional entity among them)
    /// and [`SOMEONE_NEW`]. Every candidate rides in the state by id, listed
    /// or not; past the ladder's state bound each still does, with its texts
    /// cut to fit, and an ask whose ids alone pass it is not called. Only a
    /// listed candidate can be chosen. A choice settles the mention and saves
    /// the hint.
    /// Anything else keeps a nightly ask's names separate for now, with the
    /// Dreamer's receipt, and sends an act-now ask to the person. A failed
    /// call waits [`RETRY_SECS`]. An act-now ask is an outbound effect's
    /// question; a nightly one a reversible read's, as a later answer can
    /// move it.
    ///
    /// [`MAX_CANDIDATES`]: super::MAX_CANDIDATES
    pub fn decide_identity_ask(
        &self,
        read: &ScopedRead<'_>,
        decisions: &IdentityDecisions<'_>,
        ask: &str,
        now: u64,
    ) -> Result<IdentityRuling> {
        let key = parse_key(ask).ok_or_else(|| invalid("the ask is 64 hex"))?;
        let txn = self.store.env.read_txn()?;
        // Only an ask `read` reads whole is decided, from the hint words it
        // reads (FIX 8711); any other is gone to it and waits for the owner.
        let Some(admitted) = admission::open_ask_in_txn(self, read, &txn, &key, true)? else {
            return Ok(IdentityRuling::Gone);
        };
        let admission::AdmittedIdentityAsk {
            stored,
            ask: held,
            hints,
            evidence,
        } = admitted;
        let options = options_in_txn(self, &txn, &held)?;
        drop(txn);
        let listed = listed_candidates(&held);
        // Each candidate as its id, its option when listed, its row and the
        // words its saved hint was given in; the options hold each candidate
        // in order, then someone new.
        let rows: Vec<_> = held
            .candidates
            .iter()
            .zip(&options)
            .map(|(id, option)| {
                let token = listed.contains(id).then_some(option.choice.as_str());
                let known = hints.get(id).map(|hint| hint.context.join(" "));
                (id.to_hex(), token, option, hints.get(id), known)
            })
            .collect();
        let effect = match held.reason {
            IdentityAskReason::ActNow { effect } => Some(effect),
            IdentityAskReason::Unsettled => None,
        };
        // Whole, each candidate rides with its name and hint words; past the
        // bound, by id with its texts cut to fit, never one left out.
        let candidates: Vec<serde_json::Value> = rows
            .iter()
            .map(|(id, token, option, hint, _)| {
                json!({
                    "id": id,
                    "option": token,
                    "name": option.label,
                    "provisional": option.provisional,
                    "known_context": hint.map(|hint| &hint.context),
                })
            })
            .collect();
        let whole = json!({
            "name": held.name,
            "excerpt": held.excerpt,
            "context": held.context,
            "act_now": effect,
            "someone_new": SOMEONE_NEW,
            "candidates": candidates,
        });
        let context = held.context.join(" ");
        let longest = rows
            .iter()
            .map(|(_, _, option, _, known)| {
                let known = known.as_ref().map_or(0, String::len);
                option.label.len().max(known)
            })
            .chain([held.name.len(), held.excerpt.len(), context.len()])
            .max()
            .unwrap_or(0);
        let state = fit_state(longest, |cut| {
            if cut.is_none() {
                return whole.clone();
            }
            let candidates: Vec<serde_json::Value> = rows
                .iter()
                .map(|(id, token, option, _, known)| {
                    json!({
                        "id": id,
                        "option": token,
                        "name": cut_text(&option.label, cut),
                        "provisional": option.provisional,
                        "known_context": known.as_deref().map(|words| cut_text(words, cut)),
                    })
                })
                .collect();
            json!({
                "name": cut_text(&held.name, cut),
                "excerpt": cut_text(&held.excerpt, cut),
                "context": cut_text(&context, cut),
                "act_now": effect,
                "someone_new": SOMEONE_NEW,
                "candidates": candidates,
                "cut_at_bytes": cut,
            })
        });
        let fits = |state: &serde_json::Value| {
            serde_json::to_vec(state).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES)
        };
        let mut choices: Vec<String> = rows
            .iter()
            .filter_map(|(_, token, ..)| token.map(str::to_owned))
            .collect();
        choices.push(SOMEONE_NEW.to_owned());
        let kind = [held.kind];
        let question = IDENTITY_SETTLE.question(
            &[kind.as_slice()],
            decisions.wording.clone(),
            AnswerContract::Choice { options: choices },
        )?;
        let reversibility = if effect.is_some() {
            Reversibility::OutboundEffect
        } else {
            Reversibility::ReversibleRead
        };
        let answer = if fits(&state) {
            match decisions.ladder.run(
                &question,
                decisions.principal,
                &evidence,
                &state,
                decisions.dial,
                &decisions.bands,
                reversibility,
                decisions.deadline,
            ) {
                Ok(decision) => match &decision.answer {
                    DecisionAnswer::Choice(choice) => {
                        parse_choice(&held, choice).filter(|answer| match answer {
                            Answer::Is(id) => listed.contains(id),
                            Answer::SomeoneNew => true,
                        })
                    }
                    _ => None,
                },
                Err(_) => {
                    self.with_write_txn_grouped(|txn| {
                        if let Some(mut row) = ASKS.get(&self.store, txn, &key)? {
                            row.retry_at = now.saturating_add(RETRY_SECS);
                            ASKS.put(&self.store, txn, &key, &row)?;
                        }
                        Ok(())
                    })?;
                    return Ok(IdentityRuling::Retry);
                }
            }
        } else {
            None
        };
        self.with_write_txn_grouped(|txn| {
            // Against the ask as stored, not as `read` saw it, and only while
            // `read` still reads it whole under its policy now.
            let Some(current) = admission::open_ask_in_txn(self, read, txn, &key, true)? else {
                return Ok(IdentityRuling::Gone);
            };
            let current = current.stored;
            if current.candidates != stored.candidates
                || current.escalated_at.is_some()
                || current.kept_separate_at.is_some()
            {
                return Ok(IdentityRuling::Gone);
            }
            match answer {
                Some(answer) => {
                    let entity = settle_undo::settle_in_txn(
                        self,
                        txn,
                        &current,
                        answer,
                        (ClaimSource::Inferred, &dreamer_seal()),
                        now,
                    )?;
                    ASKS.delete(&self.store, txn, &key)?;
                    Ok(IdentityRuling::Settled(entity))
                }
                None if current.reason == IdentityAskReason::Unsettled => {
                    keep_separate_in_txn(self, txn, &key, current, now)?;
                    Ok(IdentityRuling::KeptSeparate)
                }
                None => {
                    escalate_in_txn(self, txn, &key, current, now)?;
                    Ok(IdentityRuling::NeedsPerson)
                }
            }
        })
    }

    /// Sends each ask that waits on the person again where its name was
    /// said since: one more inbox Ask in the conversation of the newest turn
    /// that mentions the name. Returns how many went. Only asks and newer
    /// mentions `read` reads count (FIX 8711).
    pub fn resurface_identity_asks(&self, read: &ScopedRead<'_>, now: u64) -> Result<usize> {
        let waiting: Vec<([u8; 32], IdentityAsk)> = {
            let txn = self.store.env.read_txn()?;
            let admit = admission::Admit::in_txn(read, &txn)?;
            let mut waiting = Vec::new();
            for (key, ask) in ASKS.scan(&self.store, &txn)? {
                if ask.escalated_at.is_some()
                    && let Some(seen) = admission::admitted_in_txn(self, &admit, &txn, ask)?
                {
                    waiting.push((key, seen.stored));
                }
            }
            waiting
        };
        let mut sent = 0;
        for (key, ask) in waiting {
            let since = ask.surfaced_turn.unwrap_or(ask.turn);
            // The hits open their own read; the lane judges them in another.
            let hits = self.tagged_mentions_of_name(ask.kind, &ask.name)?;
            let txn = self.store.env.read_txn()?;
            let admit = admission::Admit::in_txn(read, &txn)?;
            let mut newest = None;
            for hit in hits {
                if hit.turn > since
                    && newest.is_none_or(|held| hit.turn > held)
                    && admit.reads_source(&txn, &hit.turn, &hit.mention.message)?
                {
                    newest = Some(hit.turn);
                }
            }
            drop(txn);
            let Some(newest) = newest else {
                continue;
            };
            let moved = self.with_write_txn_grouped(|txn| {
                let Some(mut current) = ASKS.get(&self.store, txn, &key)? else {
                    return Ok(false);
                };
                if current.surfaced_turn.is_some_and(|turn| turn >= newest) {
                    return Ok(false);
                }
                current.surfaced_turn = Some(newest);
                ASKS.put(&self.store, txn, &key, &current)?;
                notify_in_txn(self, txn, &key, &newest, now)?;
                Ok(true)
            })?;
            sent += usize::from(moved);
        }
        Ok(sent)
    }

    /// The owner's answer to one open ask, from the needs-you strip, as
    /// [`Self::answer_identity_ask_as`] on this install's own surface.
    pub fn answer_identity_ask(
        &self,
        read: &ScopedRead<'_>,
        owner: &AuthenticatedOwner,
        ask: &str,
        choice: &str,
        now: u64,
    ) -> Result<IdentitySettled> {
        self.answer_identity_ask_as(read, owner, ActSurface::ThisInstall, ask, choice, now)
    }

    /// The owner's answer to one open ask, from the needs-you strip, which
    /// reached this install from `surface` (audit only). A someone-new
    /// answer's distinct assertions are his decision, bound to the ask (mesh
    /// PR2-topology): their seals carry his act and hold on every replica.
    /// `read` is the lane his request reads under (FIX 8711): an ask it does
    /// not read is no such open ask, and a candidate it does not read is no
    /// option.
    pub fn answer_identity_ask_as(
        &self,
        read: &ScopedRead<'_>,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        ask: &str,
        choice: &str,
        now: u64,
    ) -> Result<IdentitySettled> {
        let key = parse_key(ask).ok_or_else(|| invalid("the ask is 64 hex"))?;
        let seal = TopologySeal::decision(ActAuthority::Owner(owner.clone(), surface))
            .answering(ask_answer_id(&key)?);
        self.with_write_txn_grouped(|txn| {
            super::super::validate_owner_in_txn(self, txn, owner)?;
            let seen = admission::open_ask_in_txn(self, read, txn, &key, false)?
                .ok_or_else(|| invalid("no such open ask"))?;
            let answer = parse_choice(&seen.ask, choice)
                .ok_or_else(|| invalid("not one of the ask's options"))?;
            let held = seen.stored;
            let entity = settle_ask_in_txn(
                self,
                txn,
                &key,
                &held,
                answer,
                (ClaimSource::UserStated, &seal),
                now,
            )?;
            evidence::prove_owner_in_txn(self, txn, owner, &held, &[])?;
            Ok(IdentitySettled {
                ask: key_hex(&key),
                entity: entity.to_hex(),
            })
        })
    }
}
