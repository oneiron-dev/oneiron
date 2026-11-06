//! One replayed body run (ARCH-0080 §6 Replay): on a run's memo, on a
//! verb run's saved copy, or live on an entry no run pinned.

use crate::claim::{PointRead, ScopedRead};
use crate::runtime_hooks::body::{HookBudgetOverrun, HookRunContext};
use crate::runtime_hooks::filter;
use crate::runtime_hooks::read::{self, HistoryAdmission, grant_view::shows_row};
use crate::runtime_hooks::runner::{Verdict, ask_verdict, input_json, judge, verdict_context};
use crate::runtime_hooks::source::FactEntry;
use crate::runtime_hooks::store::{self, HookRunRecord, HookRunState};
use crate::runtime_hooks::verb::{HookVerbRunRecord, admit_verb_outcome, merge_withheld};
use crate::skill_hub::pack_catalog::HookPhase;
use crate::{EntityId, Error, Result};

use super::{HookReplayResult, PinnedReads, PinnedVerdicts, Replay, input_too_large, ran};

impl Replay<'_> {
    /// `None` when the exact dependency is shown under the current grant;
    /// otherwise the truthful replay result, before any saved text runs.
    fn history_failure(
        &self,
        lane: &ScopedRead<'_>,
        id: EntityId,
        revision: Option<crate::vault::RevisionRef>,
        body_hash: Option<[u8; 32]>,
    ) -> Option<HookReplayResult> {
        match read::history_admission(lane, self.grant, id, revision, body_hash) {
            Ok(HistoryAdmission::Shown) => None,
            Ok(HistoryAdmission::Withheld) => Some(HookReplayResult::Withheld {
                reason: "a saved dependency is not shown to this hook now".to_owned(),
            }),
            Ok(HistoryAdmission::Missing) => Some(HookReplayResult::MissingHistory {
                reason: "a saved dependency's history is gone".to_owned(),
            }),
            Err(error) => Some(HookReplayResult::MissingHistory {
                reason: error.to_string(),
            }),
        }
    }

    /// Authorizes one verdict evidence row against the exact dependency the
    /// run recorded. An unknown old revision never falls back to live bytes.
    fn evidence_failure(
        &self,
        lane: &ScopedRead<'_>,
        memo: &HookRunRecord,
        id: EntityId,
    ) -> Option<HookReplayResult> {
        let Some(dependency) = memo
            .derivation
            .dependencies
            .iter()
            .find(|dependency| dependency.id == id)
        else {
            return Some(HookReplayResult::MissingHistory {
                reason: "a verdict's evidence dependency was not recorded".to_owned(),
            });
        };
        if let Some(revision) = dependency.revision {
            return self.history_failure(lane, id, Some(revision), dependency.body_hash);
        }
        if let Some(body_hash) = dependency.body_hash {
            let resolved = (|| -> Result<_> {
                let txn = self.vault.store.env.read_txn()?;
                crate::vault::entity_revision::revision_for_body_hash_in_txn(
                    self.vault, &txn, &id, &body_hash,
                )
            })();
            match resolved {
                Ok(Some(revision)) => {
                    return self.history_failure(lane, id, Some(revision), Some(body_hash));
                }
                Ok(None) => {
                    return Some(HookReplayResult::MissingHistory {
                        reason: "a verdict's evidence revision is gone".to_owned(),
                    });
                }
                Err(error) => {
                    return Some(HookReplayResult::MissingHistory {
                        reason: error.to_string(),
                    });
                }
            }
        }
        if memo.derivation.grant_hash != self.grant.digest() {
            return Some(HookReplayResult::MissingHistory {
                reason: "a verdict's evidence has no revision under the changed grant".to_owned(),
            });
        }
        self.history_failure(lane, id, None, None)
    }

    /// A run pinned this entry: its input as it was, each read only when it
    /// answers what it answered then, and each verdict as the run heard it.
    pub(super) fn from_memo(
        &self,
        lane: &ScopedRead<'_>,
        memo: &HookRunRecord,
    ) -> HookReplayResult {
        if memo.history_erased {
            return HookReplayResult::MissingHistory {
                reason: "the run's source history was erased".to_owned(),
            };
        }
        if let Some(body_hash) = memo.derivation.event_body_hash {
            let Some(revision) = memo.derivation.event_revision else {
                return HookReplayResult::MissingHistory {
                    reason: "the triggering event's exact revision is gone".to_owned(),
                };
            };
            if let Some(failure) =
                self.history_failure(lane, memo.entity, Some(revision), Some(body_hash))
            {
                return failure;
            }
        }
        for pin in &memo.verdicts {
            let Some(evidence) = pin.evidence.as_deref() else {
                return HookReplayResult::MissingHistory {
                    reason: "a verdict's evidence rows are not known".to_owned(),
                };
            };
            for id in evidence {
                if let Some(failure) = self.evidence_failure(lane, memo, *id) {
                    return failure;
                }
            }
        }
        let Some(input) = memo.input_json.as_deref() else {
            return input_too_large();
        };
        if !memo.verdicts_complete {
            return HookReplayResult::MissingHistory {
                reason: "the run's verdicts were too large to pin".to_owned(),
            };
        }
        let mut reads = PinnedReads::new(&memo.reads);
        let mut verdicts = PinnedVerdicts::new(&memo.verdicts);
        let mut context = HookRunContext::new(self.binding.selector.budget_ms);
        let result = match &self.body {
            Ok(body) => {
                // Unavailable until the runtime reports it (FIX 9332).
                context.body_starts();
                self.runtime.run_fact_hook(
                    body,
                    input,
                    &mut context,
                    &mut |request: &str| reads.answer(lane, self.grant, request),
                    &mut |request: &str| {
                        let (reply, evidence) = verdicts.answer(request);
                        self.heard(evidence);
                        reply
                    },
                )
            }
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        let overrun = self.overrun(&context);
        self.served(&memo.reads);
        self.served(&reads.scratch);
        if let Some(reason) = reads.missing.or(verdicts.missing) {
            return HookReplayResult::MissingHistory { reason };
        }
        ran(
            judge(self.binding, result, overrun, &context),
            Some(memo.outcome.as_str()),
            memo.outcome_json.as_deref(),
            true,
            false,
        )
    }

    /// A verb run saved this case: its input as it was, a post-hook's view
    /// of the result in it, and each read only when it answers what it
    /// answered then. A verb hook calls no model. The saved input runs again
    /// only while the hook's current grant still shows every row whose
    /// content it holds (FIX 10084); else its history is named gone, never
    /// run on content the hook may no longer read.
    pub(super) fn verb_run(
        &self,
        lane: &ScopedRead<'_>,
        saved: &HookVerbRunRecord,
    ) -> HookReplayResult {
        if saved.history_erased {
            return HookReplayResult::MissingHistory {
                reason: "the run's source history was erased".to_owned(),
            };
        }
        let Some(input) = saved.input_json.as_deref() else {
            return input_too_large();
        };
        if !saved
            .dependencies
            .iter()
            .all(|id| self.still_shown(lane, *id))
        {
            return HookReplayResult::MissingHistory {
                reason: "a row the saved input held is not shown to this hook now".to_owned(),
            };
        }
        if saved.unattributed && saved.grant != self.grant.digest() {
            return HookReplayResult::MissingHistory {
                reason: "the saved input holds content its hook's grant has changed for since"
                    .to_owned(),
            };
        }
        let mut reads = PinnedReads::new(&saved.reads);
        let mut context = HookRunContext::new(self.binding.selector.budget_ms);
        let result = match &self.body {
            Ok(body) => {
                context.body_starts();
                self.runtime
                    .run_hook(body, input, &mut context, &mut |request: &str| {
                        reads.answer_verb(lane, self.grant, request)
                    })
            }
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        let overrun = self.overrun(&context);
        self.served(&saved.reads);
        self.served(&reads.scratch);
        if let Some(reason) = reads.missing {
            return HookReplayResult::MissingHistory { reason };
        }
        let mut verdict = judge(self.binding, result, overrun, &context);
        // The chain's own checks beside the judge (FIX 2393), as the live
        // run applied them: a Rewrite the checks refuse, a host.compact
        // Skip or an empty Redact reads `refused` here too, so the token
        // stands beside the recorded one. The Rewrite check replay can
        // run is the static half — the host doors' add-only rules over
        // the args the saved input showed the hook, and the row's own
        // input shape for a verb the SDK table knows; a door's own
        // rewrite admission was never saved, so replay stays more
        // accepting than that door was, never less.
        if let Some(reason) = verdict.outcome.as_ref().and_then(|outcome| {
            let before = serde_json::from_str::<serde_json::Value>(input)
                .ok()
                .and_then(|shown| shown.get("args").cloned());
            let check = |next: &serde_json::Value| {
                // Restrictive verbs pin what they act on (FIX 5076): a hook's
                // changed pin that fails the door's parse never ran — the live
                // chain repaired it to the caller's own before admission
                // (Landing::select). Repair the rewrite the same way before
                // the static checks below; static rows only, as the saved
                // input shows them.
                // The landing the live chain repaired against was judged on
                // the caller's own args (FIX 2393): the run records whether
                // it had one. With none, replay skips the repair instead of
                // inventing a landing from later seen args; without the
                // record (older saves) it infers a held-call landing as
                // before. A kept landing rebuilds from the saved original —
                // held-call rows and the vault-free polymorphic rows alike —
                // and repairs against the seen args as live did; an
                // unavailable snapshot (oversize original, or a vault-read
                // row) skips the repair.
                let repaired;
                let merged;
                let next = match &before {
                    Some(before) => {
                        repaired = match saved.had_landing {
                            Some(true) => {
                                let base: Option<serde_json::Value> = saved
                                    .landing_original
                                    .as_deref()
                                    .and_then(|original| serde_json::from_str(original).ok());
                                match base.and_then(|base| {
                                    crate::task_verb::revoke_lands::Landing::from_recorded(
                                        &saved.verb,
                                        base,
                                    )
                                }) {
                                    Some(mut landing) => {
                                        landing.select(before, next.clone(), &|_| Ok(())).0
                                    }
                                    None => next.clone(),
                                }
                            }
                            None => {
                                let base = saved
                                    .landing_original
                                    .as_deref()
                                    .and_then(|original| serde_json::from_str(original).ok())
                                    .unwrap_or_else(|| before.clone());
                                match crate::task_verb::revoke_lands::Landing::from_snapshot(
                                    &saved.verb,
                                    base,
                                    Vec::new(),
                                ) {
                                    Some(mut landing) => {
                                        landing.select(before, next.clone(), &|_| Ok(())).0
                                    }
                                    None => next.clone(),
                                }
                            }
                            Some(false) => next.clone(),
                        };
                        // A narrowed hook's Rewrite keeps withheld markers
                        // where its grant hid values: the live chain merged
                        // them against the seen args before admission, so
                        // replay merges against the saved seen args when the
                        // recorded condition held — and checks the raw
                        // rewrite when it did not, as live did. Records saved
                        // before the condition existed keep the earlier
                        // merge.
                        if saved.args_withheld || saved.had_landing.is_none() {
                            merged = merge_withheld(before, repaired);
                        } else {
                            merged = repaired;
                        }
                        &merged
                    }
                    None => next,
                };
                // Whether the saved host.compact window holds placeholders,
                // not text, where the hook's grant withheld content (an
                // object where the text stood): the live chain admitted
                // against the restored window, which replay cannot rebuild,
                // so the typed content validation below cannot run on those
                // markers — the immutable fields and the append-only keep
                // list still apply, through the unverified-window check.
                let withheld = before.as_ref().is_some_and(|before| {
                    saved.verb == "host.compact"
                        && before
                            .get("window")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(|window| {
                                window.iter().any(|message| {
                                    !message
                                        .get("content")
                                        .and_then(serde_json::Value::as_str)
                                        .is_some()
                                })
                            })
                });
                if let Some(before) = &before {
                    if withheld {
                        crate::compaction::check_host_compact_rewrite_unverified_window(
                            before, next,
                        )?;
                    } else {
                        crate::runtime_hooks::host_doors::check_rewrite(&saved.verb, before, next)?;
                    }
                }
                if withheld {
                    return Ok(());
                }
                // Automatic host-hook runs never wore the facade shape (FIX
                // 2393): a compaction pass runs its pre chain on
                // {window, keep_list, token_ceiling} with no session_ref, a
                // wake pass on {kind, scope, queue_head{queued, head}} —
                // neither decodes as its facade row, whose live validator was
                // the door's own check, not the table shape. Recognize these
                // two shapes before the facade fallback below claims them.
                // (An invalid SDK call mimicking a hook shape stays admitted;
                // pathological, and the door refuses the call itself.)
                let hook_flavor = before
                    .as_ref()
                    .is_some_and(|before| match saved.verb.as_str() {
                        "host.compact" => {
                            before.get("session_ref").is_none()
                                && before
                                    .get("window")
                                    .and_then(serde_json::Value::as_array)
                                    .is_some()
                                && before
                                    .get("keep_list")
                                    .and_then(serde_json::Value::as_array)
                                    .is_some()
                                && before.get("token_ceiling").is_some()
                        }
                        "host.wake" => {
                            before
                                .get("kind")
                                .and_then(serde_json::Value::as_str)
                                .is_some()
                                && before
                                    .get("scope")
                                    .and_then(serde_json::Value::as_str)
                                    .is_some()
                                && before
                                    .get("queue_head")
                                    .and_then(serde_json::Value::as_object)
                                    .is_some()
                        }
                        _ => false,
                    });
                // The SDK table knows every SDK verb's facade shape, and the
                // browser table its browser shape. Each shape governs the
                // flavor the call ran: the facade shape when the saved args
                // validate under it, else the browser shape when they validate
                // under that — or, when the caller's own args were already
                // invalid, the verb's own tables (facade rows via
                // input_schema, the browser/desktop surfaces), since
                // sdk::invoke runs hooks before decoding and still refused
                // the rewrite. Only an actual host-hook flavor, recognized
                // above or in neither table, runs on the host-door rules
                // alone.
                let probe_facade = before.as_ref().is_some_and(|before| {
                    crate::task_verb::sdk::validate_input(&saved.verb, before).is_ok()
                });
                let probe_browser = !probe_facade
                    && before.as_ref().is_some_and(|before| {
                        crate::task_verb::sdk::validate_browser_input(&saved.verb, before).is_ok()
                    });
                let unprobed = !probe_facade && !probe_browser;
                let facade_known = crate::task_verb::sdk::input_schema(&saved.verb).is_some();
                let browser_known = saved.verb.starts_with("self.browser.")
                    || saved.verb.starts_with("self.desktop.");
                let facade = !hook_flavor && (probe_facade || (unprobed && facade_known));
                let browser =
                    !hook_flavor && !facade && (probe_browser || (unprobed && browser_known));
                if facade
                    && let Err(error) = crate::task_verb::sdk::validate_input(&saved.verb, next)
                {
                    // A browser row's run checked its rewrites against the
                    // browser shape, not the live-run wrapper: the saved
                    // record does not say which ran, so the browser check
                    // gets its say before the row's refuses.
                    crate::task_verb::sdk::validate_browser_input(&saved.verb, next)
                        .map_err(|_| error.to_string())?;
                } else if browser {
                    crate::task_verb::sdk::validate_browser_input(&saved.verb, next)
                        .map_err(|error| error.to_string())?;
                }
                Ok(())
            };
            // The live post chain gives a Rewrite nothing to check its
            // args with, as a pre chain gives it its door's check.
            let check = (saved.phase == HookPhase::Pre)
                .then_some(&check as crate::runtime_hooks::verb::VerbArgsCheck<'_>);
            admit_verb_outcome(&saved.verb, outcome, check).err()
        }) {
            verdict = Verdict {
                state: HookRunState::Refused,
                outcome: None,
                token: "refused".to_owned(),
                reason: Some(reason),
                ..verdict
            };
        }
        ran(
            verdict,
            Some(saved.outcome.as_str()),
            saved.outcome_json.as_deref(),
            true,
            false,
        )
    }

    /// No run pinned this entry. The source's exact live or retained revision
    /// supplies the body the entry wrote; a generative hook's verdicts ask
    /// the live ladder, as the runner would.
    pub(super) fn live(
        &self,
        lane: &ScopedRead<'_>,
        entry: &FactEntry,
    ) -> Result<Option<HookReplayResult>> {
        let Some(seen) = read::fact_row(lane, self.grant, entry)? else {
            return Ok(None);
        };
        let actor = filter::actor_class(self.vault, entry.actor)?;
        if !filter::fact_matches(
            self.vault,
            &self.binding.selector,
            entry.kind,
            entry.entity,
            seen.claim.as_ref(),
            actor,
        )? {
            return Ok(None);
        }
        if entry.body_hash != Some(seen.body_hash) {
            return Ok(Some(HookReplayResult::MissingHistory {
                reason: "the entity changed after this entry and no run pinned its input"
                    .to_owned(),
            }));
        }
        self.rows.borrow_mut().push(entry.actor);
        let now = self
            .vault
            .store
            .clock
            .now_recorded_at()
            .saturating_mul(1_000);
        let input = input_json(
            self.binding_id,
            self.binding,
            entry,
            actor,
            &seen.claim_json,
            now,
        )?;
        // A live replay is an execution of its own: its verdicts ask under
        // the entry's run key, and nothing keeps what they settled.
        let key = store::run_key(self.binding_id, self.binding, entry)?;
        let mut context = HookRunContext::new(self.binding.selector.budget_ms);
        let deadline = context.deadline();
        let mut pins = Vec::new();
        let mut asked = 0_u32;
        let result = match &self.body {
            Ok(body) => {
                let mut answer = |request: &str| read::answer(lane, self.grant, request, &mut pins);
                let mut verdict = |request: &str| {
                    let trusted = verdict_context(
                        self.binding_id,
                        self.binding,
                        self.grant,
                        &key,
                        asked,
                        deadline,
                    );
                    asked = asked.saturating_add(1);
                    let answer = ask_verdict(self.binding, self.verdict, &trusted, request);
                    self.heard(&answer.evidence);
                    answer.reply
                };
                context.body_starts();
                self.runtime
                    .run_fact_hook(body, &input, &mut context, &mut answer, &mut verdict)
            }
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        let overrun = self.overrun(&context);
        self.served(&pins);
        Ok(Some(ran(
            judge(self.binding, result, overrun, &context),
            None,
            None,
            false,
            true,
        )))
    }

    /// Whether the hook's current grant still shows the row `id` through
    /// `lane`; a read that fails shows nothing.
    fn still_shown(&self, lane: &ScopedRead<'_>, id: crate::EntityId) -> bool {
        lane.read(&[PointRead::id(id)], None)
            .ok()
            .and_then(|read| read.value.into_iter().next().flatten())
            .is_some_and(|row| shows_row(self.grant, &row).unwrap_or(false))
    }

    /// A replayed body's overrun, read once it has ended, on the fresh
    /// clock its replay ran on (FIX 8842): a runtime observation only. The
    /// run it replays keeps the timing it saved, and the replay answer
    /// carries none.
    fn overrun(&self, context: &HookRunContext) -> Option<HookBudgetOverrun> {
        let overrun = context.finish();
        if let Some(overrun) = &overrun {
            tracing::info!(
                binding = %self.binding_id.to_hex(),
                budget_ms = overrun.budget_ms,
                elapsed_ms = overrun.elapsed_ms,
                overrun_ms = overrun.overrun_ms,
                callback_ms = overrun.callback_ms,
                read_overruns = overrun.read_overruns,
                verdict_overruns = overrun.verdict_overruns,
                "a replayed hook body ran past its budget"
            );
        }
        overrun
    }
}
