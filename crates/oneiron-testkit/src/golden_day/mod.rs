//! The golden day: one scripted day on a fresh vault, and the normalised
//! dump of what it leaves behind (Fable's review of verdict 52, 2026-11-10,
//! section 4 idea 2; the lead's task of 12 Nov 06:50 and its 06:55
//! amendment: a regression signal, not a merge block).
//!
//! The day runs in one fixed order on the fake clock, every act through a
//! public door, the clock moving [`STEP_SECS`] after each step:
//! 1. the seed: the owner, the kit's test host, extraction allowed on the
//!    scripted backend, and one owner turn ([`SAID`], `vault.witness`);
//! 2. the vault opened as its process owner, and a Dreamer turn wake over the
//!    turn, its model calls answered by [`TURN_WAKE_CALLS`]: the extraction
//!    lands one claim;
//! 3. the owner remembers a claim (`vault.remember`);
//! 4. the owner makes an agent and grants it reads (`vault.agents.create`,
//!    `vault.agents.grants.mint`);
//! 5. the owner and the agent read: `vault.recall`, `vault.search.bm25`,
//!    `vault.claims.list` and `vault.get` of the remembered claim;
//! 6. the owner revokes the agent's Grant twice
//!    (`vault.agents.grants.revoke`; the second changes nothing);
//! 7. the agent reads again.
//!
//! The dump then holds every step's input and answer (or refusal), the model
//! calls the backend saw, the gate ledger and the receipt family
//! (`vault.receipts`, every page, all 13 kinds) and the authority audit
//! (`vault.authority.audit`, every page), all read as the owner.
//!
//! [`GoldenDayRun::normalise`] turns the dump into its golden form under
//! [`manifest::MANIFEST`]: refs the day binds by scenario name, refs a run
//! mints by first-seen index (steps first, in scenario order), readings of
//! real time masked, and the receipt rows sorted by a key no run-minted id
//! decides ([`Normaliser::sort_rows`]). Two fresh runs leave the same golden
//! form, and a PR that changes no behaviour leaves the committed golden file
//! ([`GOLDEN_FILE`]) unchanged.
//!
//! This is a normalised semantic trace, not a byte-identical attestation.
//! Some engine paths still read real time or draw ids from it
//! (`EntityId::now`, wall-clock stamps on `vault.agents.create`): the
//! normaliser maps those ids, but a change they cause in allocation order or
//! in an outcome shows as a difference, as it should.

pub mod manifest;
pub mod normalise;

use std::fmt;

use oneiron::memory::{Memory, MemoryResult};
use oneiron::{DreamerAttemptExecution, EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

use crate::clock::FakeClock;
use crate::door;
use crate::dreamer::{
    DreamerPassError, DreamerPassReport, allow_scripted_extraction, attach_test_host,
    scripted_backend,
};
use crate::fixture::{SeedError, TestVault};
use crate::provider::{ScriptedBackend, SeenCall};
use crate::receipt::ReceiptReader;

pub use manifest::{FieldClass, MANIFEST, SCHEMA_VERSION};
pub use normalise::{MEASURED, NormaliseError, Normaliser, UnknownKey, render};

/// The script's name, in the dump and in the golden file's name.
pub const SCRIPT: &str = "golden-day-1";

/// The committed golden form of [`SCRIPT`], from the crate root.
pub const GOLDEN_FILE: &str = "tests/golden/golden-day-1.json";

/// The owner's one turn. The same words, seed and order as
/// `tests/dreamer.rs`, so the turn wake asks the same prompts.
pub const SAID: &str = "I moved to Lisbon last March, and my sister Ana lives two streets away.";

/// The turn wake's model calls, `(prompt digest, reply)`: the reading of
/// the turn's two name spans, then the extraction, which proposes one claim
/// about the owner (`P1` in the prompt) quoting the turn (`T1`).
pub const TURN_WAKE_CALLS: &[(&str, &str)] = &[
    (
        "68ab6de1d6a827b746eec1d062ce4cdc857fa3b6ae5270e169bbf23b1c4f8629",
        r#"{"readings":[{"span":1,"kind":"name","novel":true,"confidence":90,"entity":null},{"span":2,"kind":"name","novel":true,"confidence":90,"entity":null}]}"#,
    ),
    (
        "78d9143fe540c8d87f9f1c3807d66bd8622baf605aaa7e445e123a51655ea334",
        r#"{"candidates":[{"subject":"P1","predicate":"residence.city","value":"Lisbon","confidence":0.9,"evidence_refs":[{"source":"T1","quote":"I moved to Lisbon last March"}]}],"persons":[]}"#,
    ),
];

/// The claim the owner remembers in step 3.
pub const REMEMBERED: &str = "The harbour survey is due on Friday.";

/// Every receipt kind `vault.receipts` accepts: the family dump asks for
/// all of them (an empty list reads the gate ledger instead).
pub const RECEIPT_KINDS: &[&str] = &[
    "outbound",
    "gate",
    "identity_lifecycle",
    "scoped_read",
    "share",
    "artifact_settle",
    "proposal_outcome",
    "commitment_lifecycle",
    "extraction",
    "served_form",
    "hook",
    "reference_refusal",
    "task_lifecycle",
];

/// The fake seconds between two steps of the day.
pub const STEP_SECS: u64 = 60;

/// The page size the dump reads with.
const PAGE: usize = 100;

/// The most pages one stream is read to: the day is small, so more means a
/// cursor that does not move.
const MAX_PAGES: usize = 50;

/// The Dreamer pass's run id (the one `tests/dreamer.rs` uses).
const PASS_RUN_ID: &str = "turn-wake";

/// Why the day could not be run at all. A verb that refuses during the day
/// is not one: its refusal is part of the trace.
#[derive(Debug)]
pub struct GoldenDayError(String);

impl fmt::Display for GoldenDayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the golden day did not run: {}", self.0)
    }
}

impl std::error::Error for GoldenDayError {}

fn failed(what: &str, error: impl fmt::Display) -> GoldenDayError {
    GoldenDayError(format!("{what}: {error}"))
}

/// One run of the day: the raw dump, and the raw refs it bound to scenario
/// names.
#[derive(Debug, Clone)]
pub struct GoldenDayRun {
    raw: Value,
    bindings: Vec<(String, String)>,
}

impl GoldenDayRun {
    /// The raw dump, as read: ids, cursors and the temp dir as they were.
    #[must_use]
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// The raw refs the day bound to scenario names, in binding order.
    #[must_use]
    pub fn bindings(&self) -> &[(String, String)] {
        &self.bindings
    }

    /// One step's answer by its step name, as read (`None` when the step
    /// refused or did not run).
    #[must_use]
    pub fn answer(&self, step: &str) -> Option<&Value> {
        self.step(step).and_then(|row| row.get("answer"))
    }

    /// One step's refusal by its step name, as read.
    #[must_use]
    pub fn refusal(&self, step: &str) -> Option<&str> {
        self.step(step)
            .and_then(|row| row.get("refused"))
            .and_then(Value::as_str)
    }

    /// One receipt stream's rows, as read (`gate_ledger` or `family`).
    #[must_use]
    pub fn stream_rows(&self, stream: &str) -> &[Value] {
        self.raw
            .pointer(&format!("/streams/{stream}/rows"))
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }

    fn step(&self, step: &str) -> Option<&Value> {
        self.raw
            .get("steps")
            .and_then(Value::as_array)?
            .iter()
            .find(|row| row.get("step").and_then(Value::as_str) == Some(step))
    }

    /// The golden form: the steps and the model calls named first, in
    /// scenario order; then each receipt stream's rows sorted
    /// ([`Normaliser::sort_rows`]) and named; then every bound ref replaced
    /// inside strings.
    ///
    /// # Errors
    /// A key the manifest does not classify, or a value its class does not
    /// allow: classify it in [`manifest`] and bump [`SCHEMA_VERSION`].
    pub fn normalise(&self) -> Result<Value, NormaliseError> {
        let mut normaliser = Normaliser::new();
        for (raw, name) in &self.bindings {
            normaliser.bind(raw, name);
        }
        let steps = normaliser.name_refs(&self.raw["steps"], "$.steps");
        let provider_seen = normaliser.name_refs(&self.raw["provider_seen"], "$.provider_seen");
        let mut streams = serde_json::Map::new();
        for stream in ["gate_ledger", "family", "authority_audit"] {
            let mut part = self.raw["streams"][stream].clone();
            if let Some(Value::Array(rows)) = part.get_mut("rows") {
                let sorted = normaliser.sort_rows(std::mem::take(rows));
                *rows = sorted;
            }
            let walked = normaliser.name_refs(&part, &format!("$.streams.{stream}"));
            streams.insert(stream.to_owned(), walked);
        }
        normaliser.finish(json!({
            "schema_version": SCHEMA_VERSION,
            "script": SCRIPT,
            "steps": steps,
            "provider_seen": provider_seen,
            "streams": streams,
        }))
    }
}

/// The scripted backend the day's Dreamer pass runs on: a fresh one per run
/// (each step answers once).
#[must_use]
pub fn backend() -> ScriptedBackend {
    scripted_backend(SCRIPT, TURN_WAKE_CALLS)
}

/// Runs the day once on a fresh vault, its model calls answered by
/// `backend` ([`backend`]). Call `backend.finish()` afterwards: an
/// unscripted model call fails there, with its prompt and digest.
///
/// # Errors
/// The seed, the open or the owner failed: the day did not run. A step that
/// refuses is recorded, not returned.
pub fn run(backend: &ScriptedBackend) -> Result<GoldenDayRun, GoldenDayError> {
    let mut day = Day::default();
    let test_vault = TestVault::seeded(SCRIPT, |vault, clock| day.seed(vault, clock))
        .map_err(|error| failed("the seed", error))?;
    day.bind(&test_vault.temp_dir().display().to_string(), "$TEMP");
    let clock = test_vault.clock();
    let vault = test_vault
        .open_owned()
        .map_err(|error| failed("the open", error))?;
    attach_test_host(&vault).map_err(|error| failed("the test host", error))?;

    // 2. The Dreamer reads the turn.
    let pass = crate::dreamer::DreamerPass::new(backend)
        .with_run_id(PASS_RUN_ID)
        .run_turn_wake(&vault, clock);
    day.record_pass(clock, pass);
    clock.advance(STEP_SECS);

    let owner_id = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| failed("the owner", error))?;
    day.bind(&owner_id.to_hex(), "owner");
    let owner_memory = vault.memory(owner_id, EdgeActorClass::Human);
    let owner = ("owner", &owner_memory);
    if let Ok(dreamer) = vault.dreamer_authority() {
        day.bind(&dreamer.entity_ref().to_hex(), "dreamer");
    }

    // 3. The owner remembers a claim.
    let remembered = day.call(
        clock,
        owner,
        "remember",
        "vault.remember",
        json!({
            "predicate": "project.deadline",
            "subject_ref": owner_id.to_hex(),
            "value": REMEMBERED,
            "confidence": 0.9,
            "source": "user_stated",
            "occurred_at": clock.now(),
            "learned_at": clock.now(),
        }),
    );
    let claim = remembered.as_ref().and_then(claim_ref_of);
    if let Some(claim) = &claim {
        day.bind(claim, "claim:remembered");
    }

    // 4. The owner makes an agent and grants it reads.
    let agent_id = vault
        .new_entity_id()
        .map_err(|error| failed("an agent id", error))?;
    day.bind(&agent_id.to_hex(), "agent");
    day.call(
        clock,
        owner,
        "agent-create",
        "vault.agents.create",
        json!({
            "agent_def_ref": agent_id.to_hex(),
            "definition": {
                "agent_id": "golden-day-reader",
                "desc": "the reader the golden day grants and revokes",
                "version": "1",
            },
        }),
    );
    let minted = day.call(
        clock,
        owner,
        "grant-mint",
        "vault.agents.grants.mint",
        json!({
            "agent": agent_id.to_hex(),
            "authority_scope": {
                "worlds": {"kind": "all"},
                "facets": {"kind": "all"},
                "bands": {"kind": "all"},
                "audience": {"kind": "all"},
                "verbs": {"kind": "some", "values": ["read"]},
                "sensitivity": {"kind": "all"},
            },
        }),
    );
    let grant = minted
        .as_ref()
        .and_then(|answer| answer.pointer("/grant/grant_ref"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(grant) = &grant {
        day.bind(grant, "grant");
    }
    let agent_memory = vault.memory(agent_id, EdgeActorClass::Agent);
    let agent = ("agent", &agent_memory);

    // 5. The owner and the agent read.
    day.reads(clock, owner, "owner", claim.as_deref());
    day.reads(clock, agent, "agent", claim.as_deref());

    // 6. The owner revokes the Grant, twice.
    let revoke = json!({"grant_ref": grant.as_deref().unwrap_or_default()});
    day.call(
        clock,
        owner,
        "grant-revoke",
        "vault.agents.grants.revoke",
        revoke.clone(),
    );
    day.call(
        clock,
        owner,
        "grant-revoke-again",
        "vault.agents.grants.revoke",
        revoke,
    );

    // 7. The agent reads again.
    day.reads(clock, agent, "agent-after-revoke", claim.as_deref());

    // The dump, read as the owner.
    let reader = ReceiptReader::new(&owner_memory);
    let streams = json!({
        "gate_ledger": receipt_stream(&reader, &[]),
        "family": receipt_stream(&reader, RECEIPT_KINDS),
        "authority_audit": audit_stream(&owner_memory),
    });
    let provider_seen: Vec<Value> = backend.seen().iter().map(seen_row).collect();
    Ok(GoldenDayRun {
        raw: json!({
            "steps": day.steps,
            "provider_seen": provider_seen,
            "streams": streams,
        }),
        bindings: day.bindings,
    })
}

/// The day's steps so far, and the refs bound to scenario names.
#[derive(Debug, Default)]
struct Day {
    steps: Vec<Value>,
    bindings: Vec<(String, String)>,
}

impl Day {
    fn bind(&mut self, raw: &str, name: &str) {
        if !raw.is_empty() {
            self.bindings.push((raw.to_owned(), name.to_owned()));
        }
    }

    /// Step 1: the seed. The same acts in the same order as
    /// `tests/dreamer.rs`, so the turn wake's prompts match its digests.
    fn seed(&mut self, vault: &Vault, clock: &FakeClock) -> Result<(), SeedError> {
        let owner = door::owner(vault).map_err(|error| format!("the owner: {error}"))?;
        attach_test_host(vault).map_err(|error| format!("the test host: {error}"))?;
        allow_scripted_extraction(vault)
            .map_err(|error| format!("the scripted extraction: {error}"))?;
        let conversation = vault
            .new_entity_id()
            .map_err(|error| format!("a conversation id: {error}"))?
            .to_hex();
        self.bind(&conversation, "conversation");
        let input = json!({
            "conversation_ref": conversation,
            "messages": [{
                "author": "user",
                "message_type": "dialogue",
                "content": SAID,
                "is_visible": true,
                "order": 0,
            }],
            "occurred_at": clock.now(),
        });
        let answer = door::invoke(&owner, "vault.witness", input.clone())
            .map_err(|error| format!("vault.witness: {error}"))?;
        self.steps.push(json!({
            "step": "witness",
            "verb": "vault.witness",
            "caller": "owner",
            "at": clock.now(),
            "input": input,
            "answer": answer,
        }));
        clock.advance(STEP_SECS);
        Ok(())
    }

    /// Runs `verb` as `caller` and records it as `step`; the clock then
    /// moves on. Returns the answer, or `None` on a refusal.
    fn call(
        &mut self,
        clock: &FakeClock,
        (caller_name, caller): Caller<'_, '_>,
        step: &str,
        verb: &str,
        input: Value,
    ) -> Option<Value> {
        let at = clock.now();
        let result = door::invoke(caller, verb, input.clone());
        let answer = self.record(step, verb, caller_name, at, input, result);
        clock.advance(STEP_SECS);
        answer
    }

    fn record(
        &mut self,
        step: &str,
        verb: &str,
        caller: &str,
        at: u64,
        input: Value,
        result: MemoryResult<Value>,
    ) -> Option<Value> {
        let mut row = json!({
            "step": step,
            "verb": verb,
            "caller": caller,
            "at": at,
            "input": input,
        });
        let answer = match result {
            Ok(answer) => {
                row["answer"] = answer.clone();
                Some(answer)
            }
            Err(error) => {
                row["refused"] = Value::String(error.to_string());
                None
            }
        };
        self.steps.push(row);
        answer
    }

    /// The four reads of step 5 and 7 as `caller`, each step named
    /// `<label>-<read>`.
    fn reads(
        &mut self,
        clock: &FakeClock,
        caller: Caller<'_, '_>,
        label: &str,
        claim: Option<&str>,
    ) {
        self.call(
            clock,
            caller,
            &format!("{label}-recall"),
            "vault.recall",
            json!({
                "query": "harbour survey Friday",
                "effort": "light",
                "limit": 10,
                "as_of": clock.now(),
            }),
        );
        self.call(
            clock,
            caller,
            &format!("{label}-search"),
            "vault.search.bm25",
            json!({"query": "harbour survey", "limit": 10}),
        );
        self.call(
            clock,
            caller,
            &format!("{label}-claims"),
            "vault.claims.list",
            json!({"predicate": "project.deadline", "limit": 100}),
        );
        self.call(
            clock,
            caller,
            &format!("{label}-get"),
            "vault.get",
            json!({"entity_ref": claim.unwrap_or_default()}),
        );
    }

    /// Step 2: what the Dreamer pass came to, without its wall times.
    fn record_pass(
        &mut self,
        clock: &FakeClock,
        pass: Result<DreamerPassReport, DreamerPassError>,
    ) {
        let mut row = json!({
            "step": "dreamer-turn-wake",
            "verb": "dreamer.turn_wake",
            "caller": "dreamer",
            "at": clock.now(),
            "input": {},
        });
        match pass {
            Ok(report) => row["answer"] = pass_answer(&report),
            Err(error) => row["refused"] = Value::String(error.to_string()),
        }
        self.steps.push(row);
    }
}

/// A caller of the day: its scenario name and its memory.
type Caller<'m, 'v> = (&'static str, &'m Memory<'v>);

/// The ref of the claim a `vault.remember` answer names.
fn claim_ref_of(answer: &Value) -> Option<String> {
    [
        "/claim_ref",
        "/claim/claim_ref",
        "/claim/id",
        "/id",
        "/receipt/claim_ref",
    ]
    .iter()
    .find_map(|pointer| answer.pointer(pointer).and_then(Value::as_str))
    .map(str::to_owned)
}

fn hex_list(ids: &[EntityId]) -> Vec<String> {
    ids.iter().map(EntityId::to_hex).collect()
}

fn pass_answer(report: &DreamerPassReport) -> Value {
    let tally = &report.tally;
    let attempts: Vec<Value> = report
        .attempts
        .iter()
        .map(|attempt| {
            let execution = match &attempt.execution {
                Ok(execution) => execution_summary(execution),
                Err(error) => format!("error: {error}"),
            };
            let rejected: Vec<Value> = attempt
                .rejected
                .iter()
                .map(|(claim, reason)| json!({"rejected_claim": claim.to_hex(), "rejection": reason}))
                .collect();
            json!({
                "attempt_id": attempt.attempt_id,
                "attempt_type": attempt.attempt_type,
                "execution": execution,
                "landed": hex_list(&attempt.landed),
                "pended": hex_list(&attempt.pended),
                "rejected": rejected,
                "unlent": attempt.unlent,
            })
        })
        .collect();
    let queue: Vec<Value> = report
        .queue
        .iter()
        .map(|row| {
            json!({
                "attempt_id": row.attempt_id,
                "kind": row.kind,
                "state": row.state,
                "park_reason": row.park_reason,
            })
        })
        .collect();
    json!({
        "wake": format!("{:?}", report.wake),
        "wake_queued": report.wake_queued,
        "stop": format!("{:?}", tally.stop),
        "admitted": tally.admitted,
        "completed": tally.completed,
        "failed": tally.failed,
        "deferred": tally.deferred,
        "parked": tally.parked,
        "landings": tally.landed,
        "sources_truncated": tally.sources_truncated,
        "claim_authoring_fallback": tally.claim_authoring_fallback.as_ref().map(|fallback| format!("{fallback:?}")),
        "attempts": attempts,
        "queue": queue,
    })
}

/// What an attempt's execution came to, without its step bindings (attempt
/// ids and step hashes as raw bytes) or a seat's bytes.
fn execution_summary(execution: &DreamerAttemptExecution) -> String {
    match execution {
        DreamerAttemptExecution::Completed {
            completed_units, ..
        } => format!("completed units={completed_units}"),
        DreamerAttemptExecution::Failed {
            reason,
            completed_units,
            budget_refusal,
            ..
        } => format!(
            "failed units={completed_units} budget_refusal={} reason={reason}",
            budget_refusal.is_some()
        ),
        DreamerAttemptExecution::Park { reason, cause } => {
            format!("park cause={cause:?} reason={reason}")
        }
        DreamerAttemptExecution::ParkWithSpend {
            reason,
            cause,
            completed_units,
            ..
        } => format!("park units={completed_units} cause={cause:?} reason={reason}"),
        DreamerAttemptExecution::ParkOnSeat {
            reason, reset_at_s, ..
        } => format!("park on a seat reset_at={reset_at_s:?} reason={reason}"),
        DreamerAttemptExecution::Deferred {
            completed_units,
            retry_at,
            ..
        } => format!("deferred units={completed_units} retry_at={retry_at}"),
        DreamerAttemptExecution::Landed {
            completed_units,
            reserve_units,
            status,
            hand_off,
            ..
        } => format!(
            "landed units={completed_units} reserve={reserve_units} status={status:?} hand_off={hand_off}"
        ),
    }
}

/// One model call the backend saw, without its body: the digest stands for
/// the prompt, and a scripted step matched it.
fn seen_row(call: &SeenCall) -> Value {
    json!({
        "step": call.step,
        "route": format!("{} {}", call.method, call.path),
        "digest": call.digest.as_ref().map(ToString::to_string),
        "streamed": call.streamed,
        "model": call.model,
    })
}

/// Every page of one `vault.receipts` stream, followed to its end: the rows
/// in read order, the page count and the undecodable rows the pages
/// reported.
fn receipt_stream(reader: &ReceiptReader<'_, '_>, kinds: &[&str]) -> Value {
    let mut rows = Vec::new();
    let mut undecodable = Vec::new();
    let mut after: Option<String> = None;
    for page_count in 1..=MAX_PAGES {
        let page = match reader.page(kinds, PAGE, after.as_deref()) {
            Ok(page) => page,
            Err(error) => {
                return json!({"rows": rows, "page_count": page_count, "undecodable": undecodable, "refused": error.to_string()});
            }
        };
        if let Some(found) = page.get("receipts").and_then(Value::as_array) {
            rows.extend(found.iter().cloned());
        }
        undecodable.push(page.get("undecodable").cloned().unwrap_or(Value::Null));
        match page.get("next_after").and_then(Value::as_str) {
            Some(next) if after.as_deref() != Some(next) => after = Some(next.to_owned()),
            _ => {
                return json!({"rows": rows, "page_count": page_count, "undecodable": undecodable});
            }
        }
    }
    json!({"rows": rows, "page_count": MAX_PAGES, "undecodable": undecodable, "refused": "the cursor did not reach the end"})
}

/// Every page of `vault.authority.audit` as the owner: the rows of every
/// page in read order (the log's own order follows entry hashes, which a run
/// draws: [`GoldenDayRun::normalise`] sorts them), and each page without its
/// rows.
fn audit_stream(owner: &Memory<'_>) -> Value {
    let mut rows = Vec::new();
    let mut pages = Vec::new();
    let mut after: Option<String> = None;
    for page_count in 1..=MAX_PAGES {
        let mut input = json!({"limit": PAGE});
        if let Some(after) = &after {
            input["after"] = json!(after);
        }
        let mut page = match door::invoke(owner, "vault.authority.audit", input) {
            Ok(page) => page,
            Err(error) => {
                return json!({"rows": rows, "pages": pages, "page_count": page_count, "refused": error.to_string()});
            }
        };
        if let Some(Value::Array(found)) = page.as_object_mut().and_then(|map| map.remove("rows")) {
            rows.extend(found);
        }
        let next = page
            .get("next_after")
            .and_then(Value::as_str)
            .map(str::to_owned);
        pages.push(page);
        match next {
            Some(next) if after.as_deref() != Some(next.as_str()) => after = Some(next),
            _ => return json!({"rows": rows, "pages": pages, "page_count": page_count}),
        }
    }
    json!({"rows": rows, "pages": pages, "page_count": MAX_PAGES, "refused": "the cursor did not reach the end"})
}
