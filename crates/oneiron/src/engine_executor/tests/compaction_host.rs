//! The compaction host end to end (agent-runtime-v1 §d7 done-means): a run
//! past its threshold compacts by itself, the swapped window passes the six
//! checks, and the next step continues from the summary. A forced failure of
//! each check stops the swap and leaves the run whole; a run whose window
//! fills parks with the typed reason instead of truncating.
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::agent_def::{CompactionOwnership, MemoryProfile};
use crate::code_run::{SelfMemorySearchCall, SelfSpeechCall};
use crate::compaction::output::OutputDecayPolicy;
use crate::compaction::{
    CompactionBackend, CompactionBackendRegistry, CompactionCheck, CompactionDriver,
    CompactionGatePolicy, CompactionProduct, CompactionRefusal, CompactionRequest,
    CompactionSuppression, CompactionTierClass,
};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY};

const RUN_REF: &str = "run-compaction-host";
const SUMMARY_FACT: &str = "the project status is green";
const NOTE_WORD: &str = "fixturenote";

/// Every pass runs on the step thread, so it lands at the next boundary.
struct InlineSpawn;

impl CompactionSpawn for InlineSpawn {
    fn spawn(&self, pass: Box<dyn FnOnce() + Send + 'static>) {
        pass();
    }
}

/// The fixture compaction model: answers the schema, or fails one check on
/// every try. Records each request and the retry each try was told about.
#[derive(Default)]
struct Compactor {
    fail: Mutex<Option<CompactionCheck>>,
    tries: Mutex<Vec<Option<CompactionCheck>>>,
    requests: Mutex<Vec<CompactionRequest>>,
    /// The rendered input one call takes whole; `None` takes any.
    limit: Option<u64>,
    /// A door each pass shuts as it runs, as a credential revoked mid-pass.
    shuts: Mutex<Option<Arc<ShutDoor>>>,
}

/// A host door that admits the run's own calls until it is shut, as a
/// connector credential stops admitting them once revoked.
#[derive(Default)]
struct ShutDoor(std::sync::atomic::AtomicBool);

impl ShutDoor {
    fn shut(&self, shut: bool) {
        self.0.store(shut, std::sync::atomic::Ordering::SeqCst);
    }
}

impl crate::code_run::AgentVerbDoor for ShutDoor {
    fn call(
        &self,
        _: &crate::code_run::SelfAgentVerbCall,
        _: &crate::memory::HostWriteOrigin,
        _: crate::runtime_hooks::InvocationId,
    ) -> crate::Result<
        std::result::Result<crate::code_run::AgentVerbAnswer, crate::code_run::AgentVerbRefusal>,
    > {
        Ok(Err(crate::code_run::AgentVerbRefusal {
            code: crate::code_run::AGENT_VERB_DOOR_UNBOUND.to_owned(),
        }))
    }

    fn admit_run_call(
        &self,
        _: crate::code_run::RunCall,
    ) -> std::result::Result<
        Option<crate::claim::ScopedReadActorKey>,
        crate::code_run::AgentVerbRefusal,
    > {
        if self.0.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(crate::code_run::AgentVerbRefusal {
                code: "door_shut".to_owned(),
            });
        }
        Ok(None)
    }
}

struct CompactorSeat(Arc<Compactor>);

impl CompactionBackend for CompactorSeat {
    fn backend_key(&self) -> &str {
        "fixture-compactor"
    }

    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }

    fn input_token_limit(&self, _summary_token_budget: u64) -> Option<u64> {
        self.0.limit
    }

    fn compact(
        &self,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> std::result::Result<CompactionProduct, CompactionRefusal> {
        self.0.tries.lock().expect("tries").push(retry);
        self.0
            .requests
            .lock()
            .expect("requests")
            .push(request.clone());
        if let Some(door) = self.0.shuts.lock().expect("shuts").as_ref() {
            door.shut(true);
        }
        let from = request.turn_start;
        let through = request.window.last().map_or(from, |message| message.turn);
        let lead = format!(
            "Steps {from} to {through} searched the fixture notes and kept what the run needs \
             next: {SUMMARY_FACT}, and the deploy checklist has four items."
        );
        let kept = std::iter::once(lead.clone())
            .chain(request.pins.iter().cloned())
            .collect::<Vec<_>>()
            .join("\n");
        let reply = |summary: &str, through: u64| {
            serde_json::json!({"from": from, "through": through, "summary": summary}).to_string()
        };
        let fail = *self.0.fail.lock().expect("fail");
        let (text, finish) = match fail {
            None => (reply(&kept, through), FinishReason::Stop),
            Some(CompactionCheck::NaturalStop) => (reply(&kept, through), FinishReason::Length),
            Some(CompactionCheck::Schema) => (kept, FinishReason::Stop),
            Some(CompactionCheck::Size) => (reply("noted.", through), FinishReason::Stop),
            Some(CompactionCheck::Pins) => (reply(&lead, through), FinishReason::Stop),
            Some(CompactionCheck::Degeneracy) => {
                let looped = format!(
                    "{}{}",
                    "the same line again\n".repeat(30),
                    request.pins.join("\n")
                );
                (reply(&looped, through), FinishReason::Stop)
            }
            Some(CompactionCheck::Coverage) => (reply(&kept, through + 1), FinishReason::Stop),
        };
        Ok(CompactionProduct {
            summary_text: text,
            finish,
            latency: Duration::from_secs(30),
        })
    }
}

/// Step 1's failure line: 376 bytes, its diagnostic at the end, past where
/// a pin cut at 240 bytes would stop.
fn failed_line() -> String {
    let dirs = (0..66)
        .map(|index| format!("d{index:02}"))
        .collect::<Vec<_>>()
        .join("/");
    let line = format!(
        "Host bridge call failed: fixture quota exceeded while writing /srv/fixtures/{dirs}: \
         the last diagnostic names the quota"
    );
    assert_eq!(line.len(), 376);
    line
}

fn console(seq: usize) -> String {
    let lead = if seq == 1 {
        failed_line()
    } else {
        format!("console-marker-{seq}")
    };
    format!("{lead}\n{}", "alpha beta gamma delta ".repeat(400))
}

fn program(seq: usize) -> String {
    format!("const step{seq} = {seq};")
}

fn no_decay() -> OutputDecayPolicy {
    OutputDecayPolicy {
        overview_after_turns: u64::MAX,
        stub_after_turns: u64::MAX,
    }
}

fn one(id: EntityId) -> crate::federation::ScopeAxis<crate::federation::ScopeId> {
    crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
        crate::federation::ScopeId(id),
    ]))
}

fn transcript(request: &LlmRequest) -> String {
    request
        .messages
        .iter()
        .map(text_message)
        .collect::<Vec<_>>()
        .join("\n")
}

/// A run's vault: a searchable note the run's first step reads, and the
/// sizes of its base request and of one step, measured on its first two
/// steps (no seat yet).
struct LongRun {
    _dir: tempfile::TempDir,
    vault: Vault,
    note: EntityId,
    lease: BudgetLease,
    run_id: EntityId,
    base_tokens: u64,
    step_tokens: u64,
}

impl LongRun {
    fn start(hard_steps: u32) -> Self {
        let (dir, vault) = open_test_vault();
        let note = seed_person(&vault, 0x51);
        vault
            .batch()
            .text(&note, &[("body", "fixturenote alpha")])
            .commit()
            .expect("searchable note");
        let lease = BudgetLease::for_test("compaction-host-lease");
        let run_id = entity(0x84);
        // Seeds the run's actor; later calls bind the same one.
        let gated_write = gated_actor_write(&vault, RUN_REF);
        let backend = FixtureBackend::new([program(0), program(1)]);
        let mut runtime = FixtureRuntime::new([
            JsCodeModeStepOutcome::pending(console(0)),
            JsCodeModeStepOutcome::pending(console(1)),
        ])
        .with_calls([vec![SelfCall::MemorySearch(SelfMemorySearchCall::new(
            NOTE_WORD, 4,
        ))]]);
        let config = executor_config(
            run_id,
            EngineExecutorLimits {
                soft_steps: 2,
                hard_steps,
            },
        );
        let outcome = block_on_ready(
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write)
                .with_output_decay(no_decay())
                .run(&config),
        )
        .expect("first two steps");
        assert_eq!(
            outcome.status,
            EngineExecutorStatus::Yielded { next_step_seq: 2 }
        );
        let requests = backend.requests.lock().expect("requests");
        let base_tokens = crate::engine_executor::compaction::request_tokens(&requests[0]);
        let step_tokens =
            crate::engine_executor::compaction::request_tokens(&requests[1]) - base_tokens;
        drop(requests);
        Self {
            _dir: dir,
            vault,
            note,
            lease,
            run_id,
            base_tokens,
            step_tokens,
        }
    }

    /// A seat whose threshold is `compact_at` tokens: the margin law is
    /// pinned past half the budget, so the threshold is its floor.
    fn seat(&self, compact_at: u64, compactor: &Arc<Compactor>) -> RunCompaction {
        let mut registry = CompactionBackendRegistry::new();
        registry
            .register(Arc::new(CompactorSeat(Arc::clone(compactor))))
            .expect("cheap backend");
        let profile = MemoryProfile::new(
            compact_at * 2,
            ModelTierRef("fixture-compactor".into()),
            CompactionOwnership::Engine,
        );
        let mut driver = CompactionDriver::for_profile(&profile, &registry)
            .expect("driver")
            .expect("engine-owned");
        driver.observe_velocity(1e12);
        RunCompaction::live(
            driver,
            CompactionGatePolicy::default(),
            WriteActor::new(entity(0xA0), EdgeActorClass::Agent),
            1,
            Arc::new(InlineSpawn),
        )
    }

    /// Steps `first..last` (the last completes the run) in one call that
    /// yields after `soft_steps`. Returns the outcome and every request.
    fn call(
        &self,
        seat: &mut RunCompaction,
        steps: std::ops::Range<usize>,
        soft_steps: u32,
        hard_steps: u32,
    ) -> (EngineExecutorOutcome, Vec<String>) {
        self.call_with(seat, steps, soft_steps, hard_steps, Vec::new())
    }

    /// [`Self::call`], each of its first steps making `calls`.
    fn call_with(
        &self,
        seat: &mut RunCompaction,
        steps: std::ops::Range<usize>,
        soft_steps: u32,
        hard_steps: u32,
        calls: Vec<Vec<SelfCall>>,
    ) -> (EngineExecutorOutcome, Vec<String>) {
        let (outcome, requests) = self.try_call(seat, steps, soft_steps, hard_steps, calls, None);
        (outcome.expect("the run continues"), requests)
    }

    /// [`Self::call_with`] behind `door`, as the run's host binds it, with the
    /// call's own result.
    fn try_call(
        &self,
        seat: &mut RunCompaction,
        steps: std::ops::Range<usize>,
        soft_steps: u32,
        hard_steps: u32,
        calls: Vec<Vec<SelfCall>>,
        door: Option<Arc<ShutDoor>>,
    ) -> (EngineExecutorResult<EngineExecutorOutcome>, Vec<String>) {
        let mut gated_write = GatedActorWrite::new(
            &self.vault,
            WriteActor::new(entity(0xA0), EdgeActorClass::Agent),
            RUN_REF,
        )
        .expect("gated actor write");
        if let Some(door) = door {
            gated_write = gated_write.with_agent_verb_door(door);
        }
        let backend = FixtureBackend::new(steps.clone().map(program));
        let last = steps.end.saturating_sub(1);
        let mut runtime = FixtureRuntime::new(steps.map(|seq| {
            if seq == last && last + 1 == hard_steps as usize {
                JsCodeModeStepOutcome::complete(console(seq))
            } else {
                JsCodeModeStepOutcome::pending(console(seq))
            }
        }))
        .with_calls(calls);
        let config = executor_config(
            self.run_id,
            EngineExecutorLimits {
                soft_steps,
                hard_steps,
            },
        );
        let outcome = block_on_ready(
            EngineNativeExecutor::new(
                &self.vault,
                &backend,
                &self.lease,
                &mut runtime,
                &gated_write,
            )
            .with_output_decay(no_decay())
            .with_compaction(seat)
            .run(&config),
        );
        let requests = backend
            .requests
            .lock()
            .expect("requests")
            .iter()
            .map(transcript)
            .collect();
        (outcome, requests)
    }

    fn summaries(&self) -> usize {
        self.vault
            .entities_by_type(ENTITY_TYPE_SUMMARY)
            .expect("summaries")
            .len()
    }
}

/// Canon §d7: past `compact_at` the run compacts the steps behind its hot
/// window by itself; the next request holds the summary in place of those
/// steps (failures kept word for word, every output still reachable by
/// handle) and the run goes on. Erasing a record the run was served retires
/// the summary's words, the steps stay covered, and a summary written after
/// the erasure is born withdrawn.
#[test]
fn a_long_run_compacts_by_itself_and_continues_from_the_summary() {
    let run = LongRun::start(10);
    let compactor = Arc::new(Compactor::default());
    // Crosses at four steps: the hot step is step 3, so steps 0-2 compact.
    let compact_at = run.base_tokens + run.step_tokens * 7 / 2;
    let mut seat = run.seat(compact_at, &compactor);
    let (outcome, requests) = run.call(&mut seat, 2..6, 4, 10);
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 6 }
    );
    assert_eq!(
        *compactor.tries.lock().expect("tries"),
        vec![None],
        "one pass, accepted on its first try"
    );
    let report = outcome.compaction.expect("the run's compaction report");
    assert_eq!(report.last_swap, Some((1, 0, 2)));
    assert_eq!(report.suppressed, None);
    // Steps 2-4 ran on the raw window; the request for step 5 is the first
    // after the swap.
    for request in &requests[..3] {
        assert!(!request.contains("<compacted"));
        assert!(request.contains("console-marker-0"));
    }
    let swapped = &requests[3];
    assert!(swapped.contains("<compacted epoch=\"1\" steps=\"0-2\">"));
    assert!(swapped.contains(SUMMARY_FACT));
    assert!(
        swapped.contains(&failed_line()),
        "a failure is never compacted away, nor cut"
    );
    for covered in ["console-marker-0", "console-marker-2"] {
        assert!(!swapped.contains(covered), "{covered} left the window");
    }
    for hot in ["console-marker-3", "console-marker-4"] {
        assert!(swapped.contains(hot), "{hot} stays raw");
    }
    for step in 0..=2 {
        assert!(
            swapped.contains(&format!("\"step\":{step}")),
            "step {step} keeps a handle"
        );
    }
    assert!(swapped.contains("sandbox.fs.read_file"));

    let epochs = run
        .vault
        .code_run_compaction_epochs(run.run_id)
        .expect("epochs");
    assert_eq!(epochs.len(), 1);
    assert_eq!(run.summaries(), 1);
    let summary = epochs[0].0.summary_id();
    assert!(
        run.vault
            .edges_out(&summary)
            .expect("edges")
            .into_iter()
            .any(|edge| edge.kind == EdgeKind::DerivedFrom && edge.target == run.note),
        "the served note is a source"
    );
    // A vault-wide run's summary is born where its other records are: base
    // reality, the vault's default facet.
    let born = run
        .vault
        .record_scope(&summary)
        .expect("scope")
        .expect("stamped");
    assert_eq!(born.worlds, one(crate::claim::base_world_id()));
    assert_eq!(born.facets, one(run.vault.default_facet().expect("facet")));

    // Erasing a record the summary was written from withdraws its words.
    assert!(run.vault.delete_entity(&run.note).expect("delete the note"));
    let epochs = run
        .vault
        .code_run_compaction_epochs(run.run_id)
        .expect("epochs");
    assert_eq!(epochs.len(), 1, "the steps stay covered");
    assert_eq!(epochs[0].1, None, "the summary is withdrawn");
    // Erasing the summary itself leaves the run's lineage in its coverage.
    assert!(
        run.vault
            .delete_entity(&summary)
            .expect("erase the summary")
    );
    // Step 7's boundary crosses again: steps 3-5 compact, from a window
    // whose run was served the erased note.
    let (outcome, requests) = run.call(&mut seat, 6..8, 2, 10);
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 8 }
    );
    let resumed = &requests[0];
    assert!(resumed.contains("<compacted epoch=\"1\" steps=\"0-2\">"));
    assert!(!resumed.contains(SUMMARY_FACT));
    assert!(!resumed.contains("console-marker-0"));
    assert!(resumed.contains("sandbox.fs.read_file"));
    let (outcome, requests) = run.call(&mut seat, 8..10, 2, 10);
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert!(requests[0].contains("<compacted epoch=\"2\" steps=\"3-5\">"));
    assert!(!requests[0].contains("console-marker-3"));
    assert!(!requests[0].contains(SUMMARY_FACT), "born withdrawn");
    let epochs = run
        .vault
        .code_run_compaction_epochs(run.run_id)
        .expect("epochs");
    assert_eq!(
        epochs
            .iter()
            .map(|(_, text)| text.is_some())
            .collect::<Vec<_>>(),
        vec![false, false]
    );
    // The erased summary is a source of the next: its shell no longer says
    // where it sat, so the summary born from it is withdrawn for an unknown
    // world, which keeps it home while any world is device-only (Sol round 18).
    let rtxn = run.vault.store.env.read_txn().expect("txn");
    assert!(
        crate::ports::withdrawn_worlds_in(&run.vault.store, &rtxn, &epochs[1].0.summary_id())
            .expect("record")
            .is_some_and(|withdrawn| withdrawn.unknown),
        "a summary minted from an erased summary"
    );
}

/// #1405 on the compaction host (Sol round 19): the run's door rules on what
/// compaction reads of the run, as on a read of its recorded output. While
/// it is shut no pass seals the run's steps for a model, a pass that finished
/// as the door shut does not land, and no request renders a summary; each
/// stops the run with the door's refusal. Opened again, the run lands the
/// kept pass and goes on.
#[test]
fn a_shut_door_stops_the_compaction_host_until_it_opens() {
    let run = LongRun::start(10);
    let compactor = Arc::new(Compactor::default());
    let door = Arc::new(ShutDoor::default());
    let compact_at = run.base_tokens + run.step_tokens * 7 / 2;
    let mut seat = run.seat(compact_at, &compactor);
    let refused = |outcome: &EngineExecutorResult<EngineExecutorOutcome>| {
        matches!(
            outcome,
            Err(EngineExecutorError::HostRefused { code }) if code == "door_shut"
        )
    };
    // Steps 2-3 stay under the threshold; step 4's request crosses it.
    let (outcome, _) = run.try_call(&mut seat, 2..4, 2, 10, Vec::new(), Some(door.clone()));
    assert!(outcome.is_ok());
    door.shut(true);
    let (outcome, requests) = run.try_call(&mut seat, 4..6, 4, 10, Vec::new(), Some(door.clone()));
    assert!(
        refused(&outcome),
        "a crossing behind a shut door: {outcome:?}"
    );
    assert!(
        compactor.tries.lock().expect("tries").is_empty(),
        "no pass reads the run while the door is shut"
    );
    assert!(requests.is_empty());

    // The pass shuts the door as it runs: step 4 goes on, and the next
    // boundary refuses to land it.
    door.shut(false);
    *compactor.shuts.lock().expect("shuts") = Some(door.clone());
    let (outcome, requests) = run.try_call(&mut seat, 4..6, 4, 10, Vec::new(), Some(door.clone()));
    assert!(
        refused(&outcome),
        "a finished pass behind a shut door: {outcome:?}"
    );
    assert_eq!(compactor.tries.lock().expect("tries").len(), 1);
    assert_eq!(requests.len(), 1);
    assert_eq!(
        run.summaries(),
        0,
        "the pass does not land while the door is shut"
    );

    // Open again: the kept pass lands, and the run goes on from it.
    *compactor.shuts.lock().expect("shuts") = None;
    door.shut(false);
    let (outcome, requests) = run.try_call(&mut seat, 5..7, 2, 10, Vec::new(), Some(door.clone()));
    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(
        compactor.tries.lock().expect("tries").len(),
        1,
        "the kept pass, not a new one"
    );
    assert_eq!(run.summaries(), 1);
    assert!(requests[0].contains("<compacted epoch=\"1\" steps=\"0-2\">"));

    // Shut once a summary exists: a request that would render it is never
    // assembled, with or without a seat.
    door.shut(true);
    let mut off = RunCompaction::off(crate::compaction::CompactionOff::Disabled);
    let (outcome, requests) = run.try_call(&mut off, 7..9, 2, 10, Vec::new(), Some(door));
    assert!(
        refused(&outcome),
        "a shut door renders no summary: {outcome:?}"
    );
    assert!(requests.is_empty());
}

/// An epoch holds words the host itself fed the run, not only what its calls
/// returned: the epochs its requests rendered and the run's speech. Each is
/// a source, so erasing one alone withdraws the epoch: S1 takes S2 with it,
/// and the speech MESSAGE M takes every epoch whose window could quote it.
#[test]
fn an_epoch_goes_with_the_host_words_it_holds() {
    for erased in [
        "the first epoch",
        "the speech message",
        "an unspoken position",
    ] {
        let run = LongRun::start(12);
        // Bridge position 0 is the run's memory search, not speech: a record
        // a caller stores at that position's MESSAGE id is none of its words.
        let unspoken = crate::code_run::executor_speech_message_id_in_run(RUN_REF, run.run_id, 0)
            .expect("position id");
        run.vault
            .put_entity(
                &unspoken,
                crate::registry::ENTITY_TYPE_PERSON,
                crate::TimeRange { start: 1, end: 1 },
                1,
                b"a caller's person",
            )
            .expect("a caller's record");
        let compactor = Arc::new(Compactor::default());
        let compact_at = run.base_tokens + run.step_tokens * 7 / 2;
        let mut seat = run.seat(compact_at, &compactor);
        // Step 2 speaks; steps 0-2 become epoch 1 at step 5's boundary.
        run.call_with(
            &mut seat,
            2..6,
            4,
            12,
            vec![vec![SelfCall::Speak(SelfSpeechCall::new(
                "fixture words said aloud",
            ))]],
        );
        // Steps 3-5, written while epoch 1 was rendered, become epoch 2.
        run.call(&mut seat, 6..8, 2, 12);
        // The run stays open: a completed run also speaks its trailing line.
        let (outcome, _) = run.call(&mut seat, 8..10, 2, 12);
        assert_eq!(
            outcome.status,
            EngineExecutorStatus::Yielded { next_step_seq: 10 }
        );
        let epochs = run
            .vault
            .code_run_compaction_epochs(run.run_id)
            .expect("epochs");
        assert_eq!(
            epochs
                .iter()
                .map(|(row, text)| (row.epoch(), text.is_some()))
                .collect::<Vec<_>>(),
            vec![(1, true), (2, true)],
            "{erased}: both epochs are live"
        );
        let first = epochs[0].0.summary_id();
        let messages = run
            .vault
            .entities_by_type(ENTITY_TYPE_MESSAGE)
            .expect("messages");
        let [message] = messages.as_slice() else {
            panic!("{erased}: one speech MESSAGE, got {messages:?}");
        };
        match erased {
            "the first epoch" => {
                assert!(run.vault.delete_entity(&first).expect("erase the epoch"));
            }
            // A MESSAGE leaves through its room's door, as its author.
            "the speech message" => {
                run.vault
                    .delete_own_room_record(*message, crate::DeleteReason::UserDelete)
                    .expect("erase the MESSAGE");
            }
            _ => assert!(run.vault.delete_entity(&unspoken).expect("erase it")),
        }
        let epochs = run
            .vault
            .code_run_compaction_epochs(run.run_id)
            .expect("epochs");
        assert_eq!(epochs.len(), 2, "{erased}: the steps stay covered");
        let withdrawn = erased != "an unspoken position";
        assert!(
            epochs.iter().all(|(_, text)| text.is_none() == withdrawn),
            "{erased}: every epoch holding its words is withdrawn, and no other"
        );
    }
}

/// The compactor's input bounds what one pass seals, not the run's decayed
/// request: a window longer than the backend takes whole compacts as the
/// contiguous prefixes it can take, each its own epoch.
#[test]
fn a_window_the_compactor_cannot_take_whole_compacts_in_prefixes() {
    let run = LongRun::start(10);
    let compactor = Arc::new(Compactor {
        limit: Some(run.step_tokens * 3 / 2),
        ..Compactor::default()
    });
    let compact_at = run.base_tokens + run.step_tokens * 7 / 2;
    let mut seat = run.seat(compact_at, &compactor);
    // A narrowed run's summaries are born in its world and facet.
    let (world, facet) = (entity(0xB1), entity(0xB2));
    seat.place(Some(world), Some(facet));
    let (outcome, _) = run.call(&mut seat, 2..8, 6, 10);
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 8 }
    );
    let report = outcome.compaction.expect("report");
    assert_eq!(report.suppressed, None);
    let spans = run
        .vault
        .code_run_compaction_coverage(run.run_id)
        .expect("coverage")
        .iter()
        .map(|row| (row.epoch(), row.first(), row.last()))
        .collect::<Vec<_>>();
    assert!(spans.len() >= 2, "{spans:?}");
    for (index, span) in spans.iter().enumerate() {
        let step = index as u64;
        assert_eq!(*span, (step + 1, step, step), "one step per pass");
    }
    for row in run
        .vault
        .code_run_compaction_coverage(run.run_id)
        .expect("coverage")
    {
        let born = run
            .vault
            .record_scope(&row.summary_id())
            .expect("scope")
            .expect("stamped");
        assert_eq!((born.worlds, born.facets), (one(world), one(facet)));
    }
}

/// Sol and Wonder on the input-size fix: counted by parts (the envelope
/// beside each step's frame alone), a lone step's input runs a token or so
/// over its rendered whole, so a first step whose input fitted the seat to
/// the token was refused as unable to fit, on every call. Measured on the
/// same run with no limit, step 0's rendered input is the seat's whole room
/// here, and it compacts.
#[test]
fn a_step_whose_input_fits_the_seat_to_the_token_compacts() {
    let probe = LongRun::start(10);
    let measuring = Arc::new(Compactor::default());
    let compact_at = probe.base_tokens + probe.step_tokens * 7 / 2;
    let mut seat = probe.seat(compact_at, &measuring);
    probe.call(&mut seat, 2..8, 6, 10);
    let request = measuring.requests.lock().expect("requests")[0].clone();
    let first = &request.window[..1];
    assert_eq!(first[0].turn, 0, "the first pass starts at step 0");
    let room = crate::compaction::compaction_input_tokens(
        request.turn_start,
        first,
        &first
            .iter()
            .filter_map(|message| crate::engine_executor::compaction::failure_pin(&message.content))
            .collect::<Vec<_>>(),
        request.summary_token_budget,
    );

    let run = LongRun::start(10);
    let compactor = Arc::new(Compactor {
        limit: Some(room),
        ..Compactor::default()
    });
    let mut seat = run.seat(compact_at, &compactor);
    run.call(&mut seat, 2..8, 6, 10);
    let first_span = run
        .vault
        .code_run_compaction_coverage(run.run_id)
        .expect("coverage")
        .iter()
        .map(|row| (row.epoch(), row.first(), row.last()))
        .next();
    assert_eq!(
        first_span,
        Some((1, 0, 0)),
        "step 0 fits the seat to the token and compacts alone"
    );
}

/// Canon §d7: every check fails closed. A pass that fails one check on every
/// try (each retry naming it) swaps nothing: no SUMMARY, no coverage, and
/// the next request still holds every raw step. The reason is typed.
#[test]
fn each_failed_check_stops_the_swap_and_leaves_the_run_whole() {
    for check in [
        CompactionCheck::NaturalStop,
        CompactionCheck::Schema,
        CompactionCheck::Size,
        CompactionCheck::Pins,
        CompactionCheck::Degeneracy,
        CompactionCheck::Coverage,
    ] {
        let run = LongRun::start(8);
        let compactor = Arc::new(Compactor::default());
        *compactor.fail.lock().expect("fail") = Some(check);
        let compact_at = run.base_tokens + run.step_tokens * 7 / 2;
        let mut seat = run.seat(compact_at, &compactor);
        let (outcome, requests) = run.call(&mut seat, 2..8, 8, 8);
        assert_eq!(outcome.status, EngineExecutorStatus::Complete, "{check:?}");
        assert_eq!(
            *compactor.tries.lock().expect("tries"),
            vec![None, Some(check), Some(check)],
            "each retry names the failed check"
        );
        let report = outcome.compaction.expect("report");
        assert_eq!(report.last_swap, None, "{check:?}");
        assert_eq!(
            report.suppressed,
            Some(CompactionSuppression::TurnScoped { check: Some(check) })
        );
        assert_eq!(run.summaries(), 0, "{check:?} minted no SUMMARY");
        assert!(
            run.vault
                .code_run_compaction_epochs(run.run_id)
                .expect("epochs")
                .is_empty(),
            "{check:?} wrote no coverage"
        );
        let last = requests.last().expect("a request");
        assert!(!last.contains("<compacted"), "{check:?}");
        for step in 0..7 {
            if step != 1 {
                assert!(
                    last.contains(&format!("console-marker-{step}")),
                    "{check:?}"
                );
            }
        }
        assert!(last.contains(&failed_line()));
    }
}

/// Canon §d7: reaching the window budget with no accepted swap parks the run
/// with the typed reason instead of truncating; the same run goes on once a
/// swap lands.
#[test]
fn a_full_window_parks_with_its_reason_and_resumes_after_the_swap() {
    let run = LongRun::start(12);
    let compactor = Arc::new(Compactor::default());
    *compactor.fail.lock().expect("fail") = Some(CompactionCheck::Size);
    // Budget = base + 6 steps: the call parks at its sixth step boundary.
    let budget = run.base_tokens + run.step_tokens * 6;
    let mut seat = run.seat(budget / 2, &compactor);
    let (outcome, requests) = run.call(&mut seat, 2..12, 12, 12);
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::WindowFull {
            next_step_seq: 6,
            reason: WindowFullReason::Suppressed(CompactionSuppression::TurnScoped {
                check: Some(CompactionCheck::Size),
            }),
        }
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("<compacted"))
    );

    // A new call is a new turn: the pass runs again, now accepted, and the
    // run parks only while it is in flight.
    *compactor.fail.lock().expect("fail") = None;
    let (outcome, _) = run.call(&mut seat, 6..12, 12, 12);
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::WindowFull {
            next_step_seq: 6,
            reason: WindowFullReason::InFlight,
        }
    );
    let (outcome, requests) = run.call(&mut seat, 6..12, 12, 12);
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert!(requests[0].contains("<compacted epoch=\"1\""));
    assert!(requests[0].contains(SUMMARY_FACT));
}
