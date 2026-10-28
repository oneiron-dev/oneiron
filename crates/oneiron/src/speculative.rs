//! EMB-5 speculative retrieval over ASR partials (ONE-EMBED E7).
//!
//! A thin per-utterance session: the host feeds ASR-partial observations in
//! ([`SpeculativePartial`]); the session fires a reduced-limit, prefix-only
//! (EMB-2 skip-rescore hot lane) retrieval whenever the partial's MEANING
//! changes — the entity-label ∪ salient-term signature differs from the last
//! FIRED signature — capped at [`SpeculativeSessionConfig::max_fires`] per
//! utterance. At end of utterance [`SpeculativeSession::finalize`] either
//! promotes the last warm pack verbatim (zero additional retrieval) or runs
//! one full-quality pass and warm-fills the shortfall.
//!
//! The engine runs no ASR and no entity-spot model: labels, terms, and query
//! vectors are host-supplied. Every speculative fire is tagged
//! [`RetrievalAction::Speculative`] in telemetry; the finalize pass logs as
//! `Pipeline` — only the fires are the measurable wasted-retrieval budget.
//!
//! Accepted E7 latency-for-quality tradeoff (RATIFY-20260710 R0): the
//! promote path returns fire-shaped results (`fire_limit`-capped,
//! prefix-quality) while the finalize path returns `final_limit`
//! full-dim-rescored results — see [`SpeculativeFinal`]. A host can set
//! `fire_limit == final_limit` to erase the count half.
//!
//! Call mode (retrieval hub #call-mode, ARCH-0061 §6): with
//! [`SpeculativeSessionConfig::deadline`] set, every fire and the finalize
//! pass run under that hard deadline, on a thread of their own, so the voice
//! loop never waits past it. A fire that misses it changes nothing but its
//! budget ([`SpeculativeFireDecision::MissedDeadline`]); a finalize that
//! misses it answers with the warm pack, the best results ready. A vault
//! runs such passes on at most a quarter of its reader slots at once; a pass
//! past that misses its deadline without starting.
//!
//! Snapshot posture (recorded deviation from E7's literal "one
//! read-snapshot" wording, designer-resolved): per-fire LMDB snapshot
//! isolation + a session-owned warm pack, NOT one read txn held across the
//! utterance — a multi-second-held `RoTxn` would pin LMDB free-page
//! reclamation exactly while the voice path is writing. Each fire is
//! internally consistent, refires only happen on meaning change where
//! fresher data is strictly better, and the promote path returns the stored
//! warm pack verbatim.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::retrieval_depth::RetrievalDeadline;
use crate::store::{RetrievalAction, RetrievalRunId};

pub(crate) mod scoped;

/// Max speculative fires per utterance (E7: cap ~4 fires/utterance).
pub const SPECULATIVE_FIRE_CAP_DEFAULT: u8 = 4;
/// Reduced per-fire result limit (E7 "fast lane, reduced limit").
pub const SPECULATIVE_FIRE_LIMIT_DEFAULT: usize = 8;

pub struct SpeculativeSessionConfig {
    /// Max speculative fires per utterance (host-tunable, E7).
    pub max_fires: u8,
    /// `result_limit` for speculative fires.
    pub fire_limit: usize,
    /// `result_limit` for the end-of-utterance full-quality pass.
    pub final_limit: usize,
    /// The hard deadline of each fire and of the finalize pass, from when it
    /// is asked for; `None` waits for them to finish. A voice host sets the
    /// vault's call-mode deadline ([`crate::Vault::call_mode_deadline`]).
    pub deadline: Option<Duration>,
    /// Where a pass that misses its deadline is kept while it runs on, for
    /// the call it belongs to to join before that call's write admission
    /// drops (FIX 3814); `None` lets it run on detached.
    pub threads: Option<SpeculativeThreads>,
}

impl Default for SpeculativeSessionConfig {
    fn default() -> Self {
        Self {
            max_fires: SPECULATIVE_FIRE_CAP_DEFAULT,
            fire_limit: SPECULATIVE_FIRE_LIMIT_DEFAULT,
            final_limit: crate::pipeline::DEFAULT_RESULT_LIMIT,
            deadline: None,
            threads: None,
        }
    }
}

/// The passes of one call that missed their deadline and still run on
/// threads of their own. Such a pass writes its telemetry and embedding jobs
/// when its query ends, so the call joins them before its write admission
/// drops (FIX 3814). Clones share one list.
#[derive(Clone, Default)]
pub struct SpeculativeThreads(Arc<Mutex<Vec<JoinHandle<()>>>>);

impl SpeculativeThreads {
    fn lock(&self) -> MutexGuard<'_, Vec<JoinHandle<()>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps `thread` until it is joined; the ones already ended go.
    fn keep(&self, thread: JoinHandle<()>) {
        let mut threads = self.lock();
        threads.retain(|kept| !kept.is_finished());
        threads.push(thread);
    }

    /// Whether every kept pass has ended.
    #[must_use]
    pub fn at_rest(&self) -> bool {
        self.lock().iter().all(JoinHandle::is_finished)
    }

    /// Blocks until every kept pass has ended. Each stops at its next
    /// deadline checkpoint and writes what its query ended with.
    pub fn join(&self) {
        let threads = std::mem::take(&mut *self.lock());
        for thread in threads {
            // A pass that panicked has ended all the same.
            let _ = thread.join();
        }
    }
}

/// One ASR-partial observation. The engine runs no models: entity labels
/// come from the host's TINY entity-spot pass, salient terms from the
/// host's extraction; `query_vector` (if any) is host-embedded (full-length
/// or `fast_dims`-length per EMB-2).
pub struct SpeculativePartial<'a> {
    pub text: &'a str,
    pub query_vector: Option<&'a [f32]>,
    pub entity_labels: &'a [String],
    pub salient_terms: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpeculativeFireDecision {
    Fired {
        run_id: Option<RetrievalRunId>,
        /// The fire's deadline cut retrieval short: the warm pack holds the
        /// stages that finished.
        partial: bool,
    },
    /// The fire was not done by its deadline, or did not start because the
    /// vault already ran as many passes as it lets run. The warm pack and
    /// signature stay those of the last fire that landed; the fire still
    /// counts against `max_fires`.
    MissedDeadline,
    /// Signature identical to the last fired signature.
    SkippedUnchanged,
    /// No entities/terms spotted yet — nothing meaningful.
    SkippedEmptySignature,
    /// `max_fires` reached.
    SkippedCapExhausted,
}

/// End-of-utterance outcome.
///
/// The `Promoted`/`Finalized` count+quality asymmetry is ACCEPTED and
/// intentional (E7 latency-for-quality tradeoff, RATIFY-20260710 R0):
/// `Promoted` returns at most `fire_limit` prefix-quality (skip-rescore)
/// candidates with zero additional retrieval; `Finalized` returns up to
/// `final_limit` full-dim-rescored candidates from one fresh pass. Setting
/// `fire_limit == final_limit` erases the count half of the asymmetry.
pub enum SpeculativeFinal {
    /// Diff empty at end-of-utterance: the last warm pack is promoted
    /// verbatim — zero additional retrieval (E7 promote path). `run_id` is
    /// the promoted fire's run id; no new telemetry row is written.
    Promoted {
        scores: Vec<ScoredEntity>,
        run_id: Option<RetrievalRunId>,
        /// The promoted fire's deadline cut it short.
        partial: bool,
    },
    /// Diff non-empty: one full-quality pass ran; warm candidates absent
    /// from the fresh results were appended (in warm order) up to
    /// `final_limit`, counted in `warm_appended`.
    ///
    /// Warm-appended entries keep their fire-time scores (prefix-space,
    /// since fires skip the rescore) behind full-dim fresh scores — score
    /// VALUES are NOT cross-comparable across the fresh/warm boundary;
    /// order is the contract, not score scale.
    Finalized {
        scores: Vec<ScoredEntity>,
        run_id: Option<RetrievalRunId>,
        warm_appended: usize,
        /// The pass's deadline cut it short, or it was not done by then and
        /// only warm candidates came back (`run_id` is then `None`).
        partial: bool,
    },
}

struct WarmPack {
    scores: Vec<ScoredEntity>,
    run_id: Option<RetrievalRunId>,
    partial: bool,
}

/// Per-utterance speculative-retrieval session (see the module docs).
///
/// Owns an `Arc<Vault>` (the `PendingEmbeddingReconciler` precedent): the
/// session outlives individual call frames in a host voice loop.
pub struct SpeculativeSession {
    vault: std::sync::Arc<crate::Vault>,
    config: SpeculativeSessionConfig,
    last_signature: BTreeSet<String>,
    fires_used: u8,
    warm: Option<WarmPack>,
    scope: Option<scoped::SpeculativeReadScope>,
}

impl SpeculativeSession {
    #[must_use]
    pub fn new(vault: std::sync::Arc<crate::Vault>, config: SpeculativeSessionConfig) -> Self {
        Self {
            vault,
            config,
            last_signature: BTreeSet::new(),
            fires_used: 0,
            warm: None,
            scope: None,
        }
    }

    /// Observes one ASR partial; fires a speculative retrieval when its
    /// signature differs from the last FIRED signature (never per-token).
    /// A fire error propagates and leaves the session state un-advanced —
    /// the next partial may retry within the cap.
    pub fn observe_partial(
        &mut self,
        partial: SpeculativePartial<'_>,
    ) -> Result<SpeculativeFireDecision> {
        let signature = partial_signature(&partial);
        if signature.is_empty() {
            return Ok(SpeculativeFireDecision::SkippedEmptySignature);
        }
        if signature == self.last_signature {
            return Ok(SpeculativeFireDecision::SkippedUnchanged);
        }
        if self.fires_used >= self.config.max_fires {
            return Ok(SpeculativeFireDecision::SkippedCapExhausted);
        }

        if self.config.fire_limit == 0 {
            return Err(crate::error::Error::InvalidConfig(
                "speculative limits must be greater than zero".to_owned(),
            ));
        }
        let pass = SpeculativePass {
            text: partial.text.to_owned(),
            query_vector: partial.query_vector.map(<[f32]>::to_vec),
            limit: self.config.fire_limit,
            fire: true,
        };
        let Some(fired) = self.run(pass)? else {
            self.fires_used += 1;
            return Ok(SpeculativeFireDecision::MissedDeadline);
        };

        self.warm = Some(WarmPack {
            scores: fired.scores,
            run_id: fired.run_id,
            partial: fired.partial,
        });
        self.last_signature = signature;
        self.fires_used += 1;
        Ok(SpeculativeFireDecision::Fired {
            run_id: fired.run_id,
            partial: fired.partial,
        })
    }

    /// Runs one pass, under the session's deadline when it has one. `None`
    /// when the pass was not done by then: it ran on a thread of its own,
    /// which stops at its next checkpoint, and its result is dropped; the
    /// thread goes to the session's [`SpeculativeThreads`], when it has
    /// them, until its call joins it. Also `None`, at once, while the vault
    /// already runs as many passes as it lets run.
    fn run(&self, pass: SpeculativePass) -> Result<Option<PassOutput>> {
        let Some(budget) = self.config.deadline else {
            return pass.run(&self.vault, None, self.scope.as_ref()).map(Some);
        };
        let started = Instant::now();
        let Some(running) = RunningPass::admit(&self.vault) else {
            return Ok(None);
        };
        let vault = Arc::clone(&self.vault);
        let scope = self.scope.clone();
        let (sender, answer) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("oneiron-speculative".to_owned())
            .spawn(move || {
                let _running = running;
                let deadline = RetrievalDeadline::hard(started, budget);
                // The caller may have stopped waiting; a closed slot is moot.
                let _ = sender.send(pass.run(&vault, Some(&deadline), scope.as_ref()));
            })?;
        // A pass that answered has written all it writes; one that did not
        // still writes when its query ends, so its call keeps it to join.
        match answer.recv_timeout(budget.saturating_sub(started.elapsed())) {
            Ok(output) => output.map(Some),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Some(threads) = &self.config.threads {
                    threads.keep(thread);
                }
                Ok(None)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(Error::InvariantViolation(
                "speculative pass ended without an answer",
            )),
        }
    }

    /// The last fired warm pack (empty before the first fire).
    #[must_use]
    pub fn warm_candidates(&self) -> &[ScoredEntity] {
        self.warm
            .as_ref()
            .map_or(&[], |warm| warm.scores.as_slice())
    }

    #[must_use]
    pub fn fires_used(&self) -> u8 {
        self.fires_used
    }

    /// End-of-utterance: promote the warm pack verbatim when the final
    /// signature matches the last fired one, else run ONE full-quality pass
    /// (logged as `RetrievalAction::Pipeline`; it IS a real retrieval) and
    /// warm-fill the shortfall. Never counts against `max_fires`.
    pub fn finalize(self, final_partial: SpeculativePartial<'_>) -> Result<SpeculativeFinal> {
        let signature = partial_signature(&final_partial);
        if signature == self.last_signature
            && let Some(warm) = self.warm
        {
            return Ok(SpeculativeFinal::Promoted {
                scores: warm.scores,
                run_id: warm.run_id,
                partial: warm.partial,
            });
        }

        if self.config.final_limit == 0 {
            return Err(crate::error::Error::InvalidConfig(
                "speculative limits must be greater than zero".to_owned(),
            ));
        }
        let pass = SpeculativePass {
            text: final_partial.text.to_owned(),
            query_vector: final_partial.query_vector.map(<[f32]>::to_vec),
            limit: self.config.final_limit,
            fire: false,
        };
        // A pass not done by its deadline leaves only the warm candidates:
        // the best results ready.
        let fresh = self.run(pass)?.unwrap_or(PassOutput {
            scores: Vec::new(),
            run_id: None,
            partial: true,
        });

        let mut scores = fresh.scores;
        // Dedupe against fresh results AND already-appended warm entries:
        // a warm-internal repeat must not double-append.
        let mut seen: BTreeSet<crate::entity_id::EntityId> =
            scores.iter().map(|scored| scored.id).collect();
        let mut warm_appended = 0;
        if let Some(warm) = self.warm {
            for candidate in warm.scores {
                if scores.len() >= self.config.final_limit {
                    break;
                }
                if !seen.insert(candidate.id) {
                    continue;
                }
                scores.push(candidate);
                warm_appended += 1;
            }
        }

        Ok(SpeculativeFinal::Finalized {
            scores,
            run_id: fresh.run_id,
            warm_appended,
            partial: fresh.partial,
        })
    }
}

/// The share of a vault's LMDB reader slots its speculative passes may hold
/// at once: one in this many.
const READER_SLOT_SHARE: u32 = 4;

/// The speculative passes running on threads of their own in one vault. A
/// pass past its deadline keeps its read snapshot, and with it a reader
/// slot, until its next checkpoint, so fires that keep missing a stalled
/// stage would otherwise take every slot the vault has.
#[derive(Default)]
pub(crate) struct SpeculativePasses(AtomicUsize);

/// One admitted pass; the vault counts it until its thread lets it go.
struct RunningPass(Arc<crate::Vault>);

impl RunningPass {
    fn admit(vault: &Arc<crate::Vault>) -> Option<Self> {
        // The table LMDB gave, which another process may have kept smaller
        // than the config asked for.
        let cap = usize::try_from((vault.reader_slots() / READER_SLOT_SHARE).max(1))
            .unwrap_or(usize::MAX);
        vault
            .speculative_passes
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |running| {
                (running < cap).then_some(running + 1)
            })
            .ok()?;
        Some(Self(Arc::clone(vault)))
    }
}

impl Drop for RunningPass {
    fn drop(&mut self) {
        self.0.speculative_passes.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One fire or finalize pass, owned so it can run on a thread of its own.
struct SpeculativePass {
    text: String,
    query_vector: Option<Vec<f32>>,
    limit: usize,
    /// A fire (prefix-only hot lane, logged `Speculative`) or the finalize
    /// pass (full-dim, logged `Pipeline`).
    fire: bool,
}

struct PassOutput {
    scores: Vec<ScoredEntity>,
    run_id: Option<RetrievalRunId>,
    partial: bool,
}

impl SpeculativePass {
    fn run(
        &self,
        vault: &crate::Vault,
        deadline: Option<&RetrievalDeadline>,
        scope: Option<&scoped::SpeculativeReadScope>,
    ) -> Result<PassOutput> {
        match scope {
            Some(scope) => scope.run(vault, self, deadline),
            None => self.execute(self.builder(vault, deadline), deadline),
        }
    }

    fn builder<'a>(
        &'a self,
        vault: &'a crate::Vault,
        deadline: Option<&'a RetrievalDeadline>,
    ) -> crate::pipeline::PipelineBuilder<'a> {
        let mut builder = vault.query().search_text(&self.text, self.limit);
        if let Some(vector) = self.query_vector.as_deref() {
            builder = builder.search_vector(vector, self.limit);
            if self.fire {
                // EMB-2 voice hot lane: prefix-only, no full-dim rescore.
                builder = builder.skip_vector_rescore(true);
            }
        }
        if let Some(deadline) = deadline {
            builder = builder.deadline(deadline);
        }
        builder
    }

    fn execute(
        &self,
        builder: crate::pipeline::PipelineBuilder<'_>,
        deadline: Option<&RetrievalDeadline>,
    ) -> Result<PassOutput> {
        let ran = builder
            .limit(self.limit)
            .telemetry_action(if self.fire {
                RetrievalAction::Speculative
            } else {
                RetrievalAction::Pipeline
            })
            // Deliberately this run variant: surfaced-pending claims get the
            // EMB-1 priority-0 hot bump.
            .run_with_pending_vectors()?;
        Ok(PassOutput {
            scores: ran.value,
            run_id: ran.run_id,
            partial: deadline.is_some_and(RetrievalDeadline::was_cut_short),
        })
    }
}

/// Normalized meaning signature: `entity_labels ∪ salient_terms`, each
/// trimmed and Unicode-lowercased, empties dropped.
fn partial_signature(partial: &SpeculativePartial<'_>) -> BTreeSet<String> {
    partial
        .entity_labels
        .iter()
        .chain(partial.salient_terms.iter())
        .map(|term| term.trim().to_lowercase())
        .filter(|term| !term.is_empty())
        .collect()
}
