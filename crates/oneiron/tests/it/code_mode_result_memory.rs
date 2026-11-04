//! B++ (OF-190) acceptance: a code-mode run whose history holds one result
//! larger than the 256 MiB fallback session share, plus thousands of small
//! results, keeps a flat resident-memory plateau while the model works and while
//! a real QuickJS guest reads the big result back by chunk.
//!
//! Before the fix every model turn reloaded each past observation whole, and a
//! 64 KiB chunk read loaded the whole body first; either one shows here as a
//! jump in anonymous resident memory the size of the body.
//!
//! No guest can print 288 MiB yet (one step emits at most 262,144 characters
//! until results stream to the body store), so a host-side producer stands in
//! for the first steps. The reads go through the real guest and bridge.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use oneiron::code_run::{CodeRunDeterminism, GatedActorWrite};
use oneiron::code_sandbox::quickjs::QuickJsRuntimeFactory;
use oneiron::code_sandbox::wasmtime_runtime::ComponentBudget;
use oneiron::compaction::output::OutputDecayPolicy;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorStatus, EngineNativeExecutor,
    JsCodeModeHost, JsCodeModeOutput, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, TimeRange, Vault, VaultConfig, WriteActor,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::common::entity;

/// Past the 256 MiB session share BPP-SPEC §3 falls back to.
const BODY_BYTES: usize = 288 << 20;
/// The body is fixed-width numbered lines, so any offset's text is known.
const LINE_BYTES: usize = 32;
const SMALL_STEPS: u64 = 40;
const RESULTS_PER_STEP: usize = 50;
/// Growth of anonymous resident memory a window may show. The body is 288 MiB;
/// one whole copy of it fails the check.
const PLATEAU_BYTES: u64 = 128 << 20;
const CHUNK_BYTES: usize = 64 * 1024;

fn line(index: usize) -> String {
    format!("{index:031}\n")
}

fn big_body() -> String {
    let mut body = String::with_capacity(BODY_BYTES);
    for index in 0..BODY_BYTES / LINE_BYTES {
        writeln!(body, "{index:031}").expect("write to a String");
    }
    body
}

/// Anonymous resident memory of this process: heap copies, not the vault's
/// mapped pages, which the kernel reclaims under pressure.
fn rss_anon_bytes() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("proc status");
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("RssAnon:"))
        .and_then(|rest| rest.trim().strip_suffix("kB"))
        .and_then(|kib| kib.trim().parse::<u64>().ok())
        .expect("RssAnon line");
    kib * 1024
}

/// Samples anonymous resident memory every millisecond; a body-sized copy
/// lives far longer than that while it is hashed and decoded.
struct Sampler {
    peak: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Sampler {
    fn start() -> Self {
        let peak = Arc::new(AtomicU64::new(rss_anon_bytes()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = std::thread::spawn({
            let (peak, stop) = (Arc::clone(&peak), Arc::clone(&stop));
            move || {
                while !stop.load(Ordering::Relaxed) {
                    peak.fetch_max(rss_anon_bytes(), Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        });
        Self {
            peak,
            stop,
            thread: Some(thread),
        }
    }

    /// Runs `work` and returns how far anonymous memory rose above where it
    /// stood when the window opened.
    fn window<T>(&self, work: impl FnOnce() -> T) -> (T, u64) {
        let base = rss_anon_bytes();
        self.peak.store(base, Ordering::Relaxed);
        let value = work();
        self.peak.fetch_max(rss_anon_bytes(), Ordering::Relaxed);
        (
            value,
            self.peak.load(Ordering::Relaxed).saturating_sub(base),
        )
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    match pin!(future).as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("executor future unexpectedly pending"),
    }
}

fn reply(text: impl Into<String>) -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text { text: text.into() }],
        },
        usage: LlmUsage::zero(),
        finish_reason: FinishReason::Stop,
    }
}

fn texts(request: &LlmRequest) -> impl Iterator<Item = &str> {
    request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
}

/// One scripted model turn: the program it writes, given the request.
type Reply = Box<dyn FnOnce(&LlmRequest) -> String + Send>;

/// The model's side. It keeps no request: a retained prompt would hold memory
/// the plateau must not count.
struct Model {
    replies: Mutex<VecDeque<Reply>>,
}

impl Model {
    fn new(replies: Vec<Reply>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
        }
    }
}

impl LlmBackend for Model {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let next = self
            .replies
            .lock()
            .expect("replies lock")
            .pop_front()
            .expect("a scripted reply for every turn");
        let text = next(&request);
        Box::pin(async move { Ok(reply(text)) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// Stands in for a guest that can print a result of any size: step 0 returns
/// the big body, each later step one line and many small stored results.
struct Producer;

impl JsCodeModeRuntime for Producer {
    fn run_step(
        &mut self,
        step: JsCodeModeStep<'_>,
        _host: &mut dyn JsCodeModeHost,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        if step.seq == 0 {
            return Ok(JsCodeModeStepOutcome::pending(big_body()));
        }
        Ok(JsCodeModeStepOutcome {
            done: false,
            observation: format!("step {} stored {RESULTS_PER_STEP} results", step.seq),
            outputs: (0..RESULTS_PER_STEP)
                .map(|index| {
                    JsCodeModeOutput::new(
                        format!("/mnt/outputs/result-{index}.txt"),
                        format!("result {index} of step {}", step.seq),
                    )
                })
                .collect(),
        })
    }
}

/// The read-file path the model is shown for step 0's observation.
fn stub_path(request: &LlmRequest) -> String {
    texts(request)
        .find_map(|text| {
            let body = text
                .split("<console>\n")
                .nth(1)?
                .split("\n</console>")
                .next()?;
            let stub: Value = serde_json::from_str(body).ok()?;
            let path = stub["sandbox.fs.read_file"].as_str()?;
            assert_eq!(
                stub["byte_len"], BODY_BYTES,
                "the stub names the whole body"
            );
            path.starts_with("/mnt/outputs/.oneiron-context-ref/0/")
                .then(|| path.to_owned())
        })
        .expect("the model sees the big observation as a read-file stub")
}

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.map_size = 1 << 30;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    (dir, vault)
}

#[test]
fn a_result_past_the_session_share_and_thousands_of_small_ones_keep_memory_flat() {
    let (_dir, vault) = vault();
    let actor = entity(0xB1);
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("seed the acting person");
    let gated = GatedActorWrite::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-big-result-memory",
    )
    .expect("gated actor write");
    let lease = BudgetLease::for_test("big-result-memory");
    let config = EngineExecutorConfig {
        run_id: entity(0xB2),
        task: "keep a big result and read it back".to_owned(),
        prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
            .expect("workspace test prompt package"),
        model: ModelId::new("test/executor@v1").expect("model id"),
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]),
        limits: EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 50,
        },
    };

    // Step 0 stores the big body; the steps after it each store fifty small
    // results. Every past observation shows as a stub, never a full view.
    let next_step = || -> Reply { Box::new(|_: &LlmRequest| "console.log('next');".to_owned()) };
    let producer_model = Model::new((0..=SMALL_STEPS).map(|_| next_step()).collect());
    let mut producer = Producer;
    let mut executor =
        EngineNativeExecutor::new(&vault, &producer_model, &lease, &mut producer, &gated)
            .with_output_decay(OutputDecayPolicy {
                overview_after_turns: 1,
                stub_after_turns: 1,
            });
    let stored = block_on_ready(executor.run(&config)).expect("the big result is stored");
    assert_eq!(
        stored.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 }
    );

    let sampler = Sampler::start();
    let (_, turns_growth) = sampler.window(|| {
        for seq in 1..=SMALL_STEPS {
            let outcome = block_on_ready(executor.run(&config)).expect("a small step");
            assert_eq!(
                outcome.status,
                EngineExecutorStatus::Yielded {
                    next_step_seq: seq + 1
                }
            );
        }
    });
    drop(executor);
    assert!(
        turns_growth <= PLATEAU_BYTES,
        "{SMALL_STEPS} model turns over a {BODY_BYTES}-byte result grew anonymous memory by \
         {turns_growth} bytes: a turn reloaded a past body whole"
    );

    // A real guest reads the head, the middle and the tail of the big body
    // through the path its stub names, then the model reads what it printed.
    let middle = BODY_BYTES / 2;
    let tail = BODY_BYTES - 3 * LINE_BYTES;
    let printed = Arc::new(Mutex::new(None::<String>));
    let reader_model = Model::new(vec![
        Box::new(move |request: &LlmRequest| {
            let path = stub_path(request);
            let base = &path[..=path.rfind('/').expect("chunk offset")];
            format!(
                "const base = {base}; \
                 const text = bytes => String.fromCharCode(...bytes); \
                 const read = async offset => {{ \
                   const chunk = await sandbox.fs.read_file(base + offset); \
                   return [offset, chunk.length, text(chunk.subarray(0, 32)), \
                           text(chunk.subarray(chunk.length - 32))]; \
                 }}; \
                 console.log('READ ' + JSON.stringify([await read(0), await read({middle}), \
                   await read({tail})]));",
                base = serde_json::to_string(base).expect("path literal"),
            )
        }),
        Box::new({
            let printed = Arc::clone(&printed);
            move |request: &LlmRequest| {
                let line = texts(request)
                    .find_map(|text| {
                        let start = text.find("READ [")?;
                        text[start + 5..].lines().next().map(str::to_owned)
                    })
                    .expect("the reading step's console reaches the model");
                *printed.lock().expect("printed lock") = Some(line);
                "finish('done');".to_owned()
            }
        }),
    ]);
    let artifacts = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/code-run-quickjs/artifacts");
    let component =
        std::fs::read(artifacts.join("quickjs-first-party.wasm")).expect("pinned QuickJS");
    let pin: [u8; 32] = Sha256::digest(&component).into();
    let factory = QuickJsRuntimeFactory::from_component(
        &component,
        pin,
        ComponentBudget {
            fuel: 2_000_000_000,
            memory_bytes: 128 * 1024 * 1024,
            wall_time: Duration::from_secs(30),
            ..ComponentBudget::default()
        },
    )
    .expect("first-party component");
    let mut guest = factory.runtime().expect("real guest");
    let mut reader = EngineNativeExecutor::new(&vault, &reader_model, &lease, &mut guest, &gated);
    let (finished, reads_growth) = sampler.window(|| {
        let read = block_on_ready(reader.run(&config)).expect("the guest reads by chunk");
        assert_eq!(
            read.status,
            EngineExecutorStatus::Yielded {
                next_step_seq: SMALL_STEPS + 2
            }
        );
        block_on_ready(reader.run(&config)).expect("the run finishes")
    });
    assert_eq!(finished.status, EngineExecutorStatus::Complete);
    assert!(
        reads_growth <= PLATEAU_BYTES,
        "chunk reads of a {BODY_BYTES}-byte result grew anonymous memory by {reads_growth} \
         bytes: a read loaded the body whole"
    );

    let expect = |offset: usize, length: usize| {
        json!([
            offset,
            length,
            line(offset / LINE_BYTES),
            line((offset + length) / LINE_BYTES - 1)
        ])
    };
    let printed = printed
        .lock()
        .expect("printed lock")
        .take()
        .expect("printed reads");
    let reads: Value = serde_json::from_str(&printed).expect("the guest printed JSON");
    assert_eq!(
        reads,
        json!([
            expect(0, CHUNK_BYTES),
            expect(middle, CHUNK_BYTES),
            expect(tail, 3 * LINE_BYTES)
        ]),
        "each chunk holds exactly the stored bytes at its offset"
    );
    let small_results = finished
        .replay_record
        .outputs
        .iter()
        .filter(|output| output.path.contains("/output/"))
        .count();
    assert_eq!(small_results, SMALL_STEPS as usize * RESULTS_PER_STEP);
}
