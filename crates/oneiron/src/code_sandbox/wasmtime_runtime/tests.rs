use super::*;
use crate::code_run::{CodeRunDeterminism, GatedActorWrite, SelfCall, SelfDispatcher};
use crate::engine_executor::SelfDispatchResponse;
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, WriteActor,
};

// Typed ABI fixture only, NOT a JavaScript interpreter. The complete record
// shape and run-step export match the C13 WIT, not the retired string-run ABI.
// A `verb-call` fixture calls one row, `input["verb"]`, with the rest of
// `input` as the row's JSON input.
fn fixture(import: &str, input: &serde_json::Value) -> String {
    let output = r#"{"done":true,"observation":"called"}"#;
    let mut data = Vec::new();
    let mut strings = Vec::new();
    let mut next = 128usize;
    if import == "verb-call" {
        let mut row = input.clone();
        let verb = row
            .as_object_mut()
            .and_then(|fields| fields.remove("verb"))
            .and_then(|verb| verb.as_str().map(str::to_owned))
            .unwrap_or_default();
        for value in [verb, row.to_string()] {
            data.push(format!(
                r#"(data (i32.const {next}) "{}")"#,
                escaped(&value)
            ));
            strings.push(format!("i32.const {next} i32.const {}", value.len()));
            next += value.len() + 1;
        }
    }
    data.push(format!(r#"(data (i32.const 2048) "{}")"#, escaped(output)));
    let types = r#"
      (type $time-shape (record (field "start" u64) (field "end" u64)))
      (import "time-range" (type $time (eq $time-shape)))
      (type $claim-shape (record (field "id" string) (field "predicate" string)
        (field "subject" string) (field "value" string) (field "confidence" (option f32))
        (field "occurred" (option $time)) (field "learned-at" (option u64))))
      (import "claim-input" (type $claim (eq $claim-shape)))
      (type $file-shape (record (field "path" string) (field "bytes" (list u8))))
      (import "file-proposal" (type $file (eq $file-shape)))
      (type $delete-shape (record (field "path" string)))
  (import "file-delete-proposal" (type $delete (eq $delete-shape)))
  (type $rename-shape (record (field "origin" string) (field "destination" string)))
  (import "file-rename-proposal" (type $rename (eq $rename-shape)))
  (type $proposal-shape (variant (case "file-write" $file) (case "claim-candidate" $claim) (case "file-delete" $delete) (case "file-rename" $rename)))
      (import "proposal-delta" (type $proposal (eq $proposal-shape)))
      (type $step-shape (record (field "result-json" string) (field "proposals" (list $proposal))))
      (import "step-result" (type $step (eq $step-shape)))
      (type $reply (result $step (error string)))"#;
    let (declaration, lower, core_import, call) = if import == "verb-call" {
        // Two strings flatten to four arguments plus the return pointer; an
        // error reply traps the step.
        (format!(r#"(import "{import}" (func $trap (param "verb" string) (param "input" string) (result (result string (error string)))))"#),
         r#"(core func $trap (canon lower (func $trap) (memory (core memory $mem "memory")) (realloc (core func $mem "realloc"))))"#.to_owned(),
         r#"(import "host" "trap" (func $trap (param i32 i32 i32 i32 i32)))"#.to_owned(),
         format!("{} i32.const 512 call $trap i32.const 512 i32.load8_u if unreachable end", strings.join(" ")))
    } else {
        (
            format!(r#"(import "{import}" (func $trap (result u64)))"#),
            "(core func $trap (canon lower (func $trap)))".into(),
            r#"(import "host" "trap" (func $trap (result i64)))"#.into(),
            "call $trap drop".into(),
        )
    };
    format!(
        r#"(component {types} {declaration}
      (core module $mem
        (memory (export "memory") 2)
        (global $next (mut i32) (i32.const 4096))
        (func (export "realloc") (param i32 i32 i32 i32) (result i32)
          (local $ptr i32)
          global.get $next local.tee $ptr local.get 3 i32.add
          i32.const 7 i32.add i32.const -8 i32.and global.set $next local.get $ptr)
        {data})
      (core instance $mem (instantiate $mem))
      {lower}
      (core module $main
        (import "mem" "memory" (memory 2))
        {core_import}
        (func (export "run-step") (param i32 i32) (result i32)
          {call}
          i32.const 1024 i32.const 0 i32.store
          i32.const 1028 i32.const 2048 i32.store
          i32.const 1032 i32.const {length} i32.store
          i32.const 1036 i32.const 0 i32.store
          i32.const 1040 i32.const 0 i32.store
          i32.const 1024))
      (core instance $host (export "trap" (func $trap)))
      (core instance $main (instantiate $main (with "mem" (instance $mem)) (with "host" (instance $host))))
      (func (export "run-step") (param "source" string) (result $reply)
        (canon lift (core func $main "run-step") (memory (core memory $mem "memory")) (realloc (core func $mem "realloc")))))"#,
        data = data.join("\n"),
        length = output.len()
    )
}

fn escaped(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("\\{byte:02x}"))
        .collect()
}

fn runtime_with(import: &str, input: &serde_json::Value) -> WasmtimeComponentRuntime {
    let component = fixture(import, input);
    WasmtimeComponentRuntime::from_component(
        component.as_bytes(),
        *blake3::hash(component.as_bytes()).as_bytes(),
        ComponentBudget::default(),
    )
    .expect("typed fixture component")
}
fn runtime(import: &str) -> WasmtimeComponentRuntime {
    runtime_with(import, &serde_json::Value::Null)
}

fn step(script: &str, tier: SandboxGuestTier) -> JsCodeModeStep<'_> {
    JsCodeModeStep {
        run_id: EntityId::from_bytes([0x25; 16]).expect("test fixture"),
        seq: 0,
        script,
        boundary: SandboxBoundaryContract::for_tier(tier),
        determinism: CodeRunDeterminism::new(10_000, [0x42; 32]),
    }
}

struct NoEffects;
impl JsCodeModeHost for NoEffects {
    fn dispatch_self(&mut self, _: SelfCall) -> Result<SelfDispatchResponse> {
        panic!("restricted component must not dispatch a write")
    }
}

struct DispatcherHost<'a>(GatedActorWrite<'a>);
impl JsCodeModeHost for DispatcherHost<'_> {
    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
        Ok(SelfDispatchResponse {
            outcome: self.0.dispatch(call.with_bridge_stamp(0, 10_000))?,
            budget: None,
        })
    }
}

fn gate_fixture() -> Result<(tempfile::TempDir, Vault, EntityId, EntityId, EntityId)> {
    let dir = tempfile::tempdir().expect("test fixture");
    let vault = Vault::open(dir.path(), crate::test_util::embedding_test_config())?;
    let actor = EntityId::from_bytes([0x64; 16])?;
    let subject = EntityId::from_bytes([0xb4; 16])?;
    let claim = EntityId::from_bytes([0xc4; 16])?;
    for id in [actor, subject] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    Ok((dir, vault, actor, subject, claim))
}

#[test]
fn component_write_enters_real_dispatcher_and_gate() -> Result<()> {
    let (_dir, vault, actor, subject, claim) = gate_fixture()?;
    let mut host = DispatcherHost(GatedActorWrite::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "component-gated-write",
    )?);
    let input = serde_json::json!({"verb":"put_claim","id":claim.to_hex(),
        "subject":subject.to_hex(),"predicate":"profile.favorite_drink","value":"sencha",
        "confidence":0.9});
    let outcome = runtime_with("verb-call", &input)
        .run_step(step("", SandboxGuestTier::FirstPartyDreamer), &mut host)?;
    assert!(outcome.done);
    let stored = vault
        .get_claim(&claim)?
        .expect("claim committed through trap");
    assert_eq!(stored.source, Some(ClaimSource::Generated));
    assert_eq!(stored.confidence, 0.9);
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    assert!(
        receipts
            .iter()
            .any(|r| r.actor.as_deref() == Some(actor.to_hex().as_str())
                && r.trigger_ref.as_deref() == Some(format!("claim:{}", claim.to_hex()).as_str()))
    );
    // Host-authority keys are not accepted as candidate data.
    let forged = serde_json::json!({"verb":"put_claim",
        "id":EntityId::from_bytes([0xc5;16])?.to_hex(),"subject":subject.to_hex(),
        "predicate":"profile.favorite_drink","value":"tea","source":"human",
        "approval":"confirmed"});
    assert!(
        runtime_with("verb-call", &forged)
            .run_step(step("", SandboxGuestTier::FirstPartyDreamer), &mut host)
            .is_err()
    );
    assert!(
        vault
            .get_claim(&EntityId::from_bytes([0xc5; 16])?)?
            .is_none()
    );
    Ok(())
}

#[test]
fn restricted_tiers_reject_write_at_component_link_time() {
    for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
        // execute is private. The production in-process entry refuses these
        // tiers altogether; this calls the same linker the guest runtime uses.
        assert!(
            runtime("verb-call")
                .execute(step("{}", tier), &mut NoEffects)
                .is_err()
        );
        assert!(
            runtime("clock-now-unix-ms")
                .execute(step("{}", tier), &mut NoEffects)
                .expect("test fixture")
                .done
        );
        assert!(
            runtime("clock-now-unix-ms")
                .run_step(step("{}", tier), &mut NoEffects)
                .is_err()
        );
    }
    assert!(
        runtime("bulk-write")
            .execute(
                step("{}", SandboxGuestTier::FirstPartyDreamer),
                &mut NoEffects
            )
            .is_err()
    );
}

#[test]
fn component_pin_and_resource_limits_fail_closed() {
    let component = fixture("clock-now-unix-ms", &serde_json::Value::Null);
    assert!(
        WasmtimeComponentRuntime::from_component(
            component.as_bytes(),
            [0; 32],
            ComponentBudget::default()
        )
        .is_err()
    );
    let mut runtime = runtime("clock-now-unix-ms");
    runtime.budget.fuel = 1;
    assert!(
        runtime
            .run_step(
                step("{}", SandboxGuestTier::FirstPartyDreamer),
                &mut NoEffects
            )
            .is_err()
    );
}

#[test]
fn component_post_return_trap_fails_closed() {
    for (body, traps) in [("", false), ("unreachable", true)] {
        let component = fixture("clock-now-unix-ms", &serde_json::Value::Null)
            .replace(
                r#"(func (export "run-step") (param i32 i32) (result i32)"#,
                &format!(
                    r#"(func (export "after-run") (param i32) {body})
                    (func (export "run-step") (param i32 i32) (result i32)"#
                ),
            )
            .replace(
                r#"(canon lift (core func $main "run-step")"#,
                r#"(canon lift (core func $main "run-step") (post-return (core func $main "after-run"))"#,
            );
        let mut runtime = WasmtimeComponentRuntime::from_component(
            component.as_bytes(),
            *blake3::hash(component.as_bytes()).as_bytes(),
            ComponentBudget::default(),
        )
        .expect("component with canonical post-return");
        let outcome = runtime.run_step(
            step("{}", SandboxGuestTier::FirstPartyDreamer),
            &mut NoEffects,
        );
        if traps {
            assert!(outcome.is_err());
        } else {
            assert!(outcome.expect("successful post-return").done);
        }
    }
}

/// A row's input is JSON, which carries no NaN, but a number can still be
/// past `f32`'s range: one that would round to infinity, or one just past
/// `f32::MAX` that would round down to it. The bridge refuses both before any
/// dispatch, as the typed import's adapter did; `f32::MAX` itself dispatches.
#[test]
fn non_finite_run_row_numbers_refuse_before_dispatch() {
    struct Counting(usize);
    impl JsCodeModeHost for Counting {
        fn dispatch_self(&mut self, _: SelfCall) -> Result<SelfDispatchResponse> {
            self.0 += 1;
            Err(crate::Error::InvalidConfig("test host".into()))
        }
    }
    let claim = |confidence: f64| {
        serde_json::json!({
            "verb": "put_claim",
            "id": "11111111111111111111111111111111",
            "subject": "22222222222222222222222222222222",
            "predicate": "profile.favorite_drink",
            "value": "sencha",
            "confidence": confidence
        })
    };
    let edge = |weight: f64| {
        serde_json::json!({
            "verb": "put_edge",
            "src": "11111111111111111111111111111111",
            "kind": "about",
            "tgt": "22222222222222222222222222222222",
            "weight": weight
        })
    };
    let past_max = 3.402_823_5e38;
    assert!(past_max > f64::from(f32::MAX) && past_max as f32 == f32::MAX);
    for (input, dispatched) in [
        (claim(1e39), 0),
        (edge(1e39), 0),
        (claim(past_max), 0),
        (edge(-past_max), 0),
        (claim(f64::from(f32::MAX)), 1),
    ] {
        let mut host = Counting(0);
        assert!(
            runtime_with("verb-call", &input)
                .run_step(step("", SandboxGuestTier::FirstPartyDreamer), &mut host)
                .is_err()
        );
        assert_eq!(host.0, dispatched, "{input}");
    }
}

/// A time past JavaScript's safe-integer range was rounded in the guest, and a
/// search limit past `u32` never fit the typed import: the bridge refuses
/// both before any dispatch, as the typed import's adapter did. The largest
/// safe time still dispatches.
#[test]
fn unsafe_run_row_integers_refuse_before_dispatch() {
    struct Counting(usize);
    impl JsCodeModeHost for Counting {
        fn dispatch_self(&mut self, _: SelfCall) -> Result<SelfDispatchResponse> {
            self.0 += 1;
            Err(crate::Error::InvalidConfig("test host".into()))
        }
    }
    let [id, other] = [
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
    ];
    let claim = |extra: serde_json::Value| {
        let mut input = serde_json::json!({
            "verb": "put_claim", "id": id, "subject": other,
            "predicate": "profile.favorite_drink", "value": "sencha"
        });
        input
            .as_object_mut()
            .expect("object")
            .extend(extra.as_object().expect("object").clone());
        input
    };
    let supersede = |now: u64| serde_json::json!({"verb": "supersede_claim", "newId": id, "oldId": other, "now": now});
    let unsafe_time = crate::code_run::JS_SAFE_INTEGER + 1;
    for (input, dispatched) in [
        (supersede(unsafe_time), 0),
        (claim(serde_json::json!({"learnedAt": unsafe_time})), 0),
        (
            claim(serde_json::json!({"occurred": {"start": 0, "end": unsafe_time}})),
            0,
        ),
        (
            serde_json::json!({"verb": "search", "query": "tea", "limit": 1_u64 << 32}),
            0,
        ),
        (supersede(crate::code_run::JS_SAFE_INTEGER), 1),
    ] {
        let mut host = Counting(0);
        assert!(
            runtime_with("verb-call", &input)
                .run_step(step("", SandboxGuestTier::FirstPartyDreamer), &mut host)
                .is_err()
        );
        assert_eq!(host.0, dispatched, "{input}");
    }
}

/// The checked-in QuickJS component, not an ABI fixture: this crosses JS,
/// generated WIT, the typed linker, the dispatcher, and the receipt reader.
fn native_quickjs_runtime() -> Result<WasmtimeComponentRuntime> {
    use sha2::{Digest, Sha256};
    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        std::path::PathBuf::from,
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("manifest.json"))?)
            .expect("QuickJS manifest JSON");
    assert_eq!(
        manifest["wit_sha256"],
        format!("{:x}", Sha256::digest(GUEST_WIT.as_bytes()))
    );
    let artifact = &manifest["artifacts"]["first-party"];
    let bytes = std::fs::read(directory.join(artifact["file"].as_str().expect("artifact file")))?;
    assert_eq!(artifact["sha256"], format!("{:x}", Sha256::digest(&bytes)));
    WasmtimeComponentRuntime::from_component(
        &bytes,
        *blake3::hash(&bytes).as_bytes(),
        ComponentBudget::default(),
    )
}

/// A guest call through each memory row reaches the host as the typed call the
/// row's hand-written import made, defaults included: a search limit of 20, a
/// claim's span and learned time at the step's frozen clock (10 s),
/// confidence 1.0, and an edge kind's default weight. The host's answer reaches
/// the guest in the import's shape.
#[test]
fn native_quickjs_memory_rows_make_the_calls_their_imports_made() -> Result<()> {
    use crate::code_run::{
        SelfDispatchOutcome, SelfMemoryEdgeWriteResult, SelfMemoryPutClaimCall,
        SelfMemoryPutEdgeCall, SelfMemorySearchCall, SelfMemorySearchResult,
        SelfMemorySupersedeClaimCall, SelfMemoryWriteResult,
    };
    use crate::{ClaimCandidate, ClaimSubject, EdgeKind, ScoredEntity};
    struct Recording(Vec<SelfCall>, EntityId);
    impl JsCodeModeHost for Recording {
        fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
            let outcome = match &call {
                SelfCall::MemorySearch(_) => {
                    SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
                        query: String::new(),
                        results: vec![ScoredEntity {
                            id: self.1,
                            score: 0.5,
                        }],
                    })
                }
                SelfCall::MemoryPutClaim(call) => {
                    SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: call.id })
                }
                SelfCall::MemorySupersedeClaim(call) => {
                    SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: call.new_id })
                }
                SelfCall::MemoryPutEdge(call) => {
                    SelfDispatchOutcome::MemoryEdgeWrite(SelfMemoryEdgeWriteResult {
                        src: call.src,
                        kind: call.kind,
                        tgt: call.tgt,
                    })
                }
                other => panic!("not a memory row: {other:?}"),
            };
            self.0.push(call);
            Ok(SelfDispatchResponse {
                outcome,
                budget: None,
            })
        }
    }
    let [first, second, subject, hit] =
        [0x61, 0x62, 0x63, 0x64].map(|byte| EntityId::from_bytes([byte; 16]).expect("test id"));
    let script = format!(
        "const [a, b, s] = ['{a}', '{b}', '{s}']; const out = {{}}; \
         out.search = await self.memory.search({{query: 'tea'}}); \
         out.first = await self.memory.put_claim({{id: a, subject: s, predicate: 'p.q', \
           value: 'sencha'}}); \
         out.second = await self.memory.put_claim({{id: b, subject: s, predicate: 'p.q', \
           value: 'matcha', confidence: 0.25, occurred: {{start: 3, end: 4}}, learnedAt: 5}}); \
         out.superseded = await self.memory.supersede_claim({{newId: b, oldId: a, now: 6}}); \
         out.edge = await self.memory.put_edge({{src: b, kind: 'about', tgt: s}}); \
         out.weighted = await self.memory.put_edge({{src: b, kind: 'mentions', tgt: s, \
           weight: 0.75}}); \
         finish(JSON.stringify(out));",
        a = first.to_hex(),
        b = second.to_hex(),
        s = subject.to_hex(),
    );
    let mut host = Recording(Vec::new(), hit);
    let outcome = native_quickjs_runtime()?.run_step(
        step(&script, SandboxGuestTier::FirstPartyDreamer),
        &mut host,
    )?;
    let claim = |id, value: &str, confidence, occurred, learned_at| {
        SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id,
            ClaimCandidate::new(
                "p.q",
                ClaimSubject::Entity(subject),
                rmpv::Value::from(value),
                confidence,
            ),
            occurred,
            learned_at,
        ))
    };
    assert_eq!(
        host.0,
        [
            SelfCall::MemorySearch(SelfMemorySearchCall::new("tea", 20)),
            claim(first, "sencha", 1.0, TimeRange { start: 10, end: 10 }, 10),
            claim(second, "matcha", 0.25, TimeRange { start: 3, end: 4 }, 5),
            SelfCall::MemorySupersedeClaim(SelfMemorySupersedeClaimCall::new(second, first, 6)),
            SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                second,
                EdgeKind::About,
                subject,
                0.5
            )),
            SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                second,
                EdgeKind::Mentions,
                subject,
                0.75
            )),
        ]
    );
    assert!(outcome.done);
    let answer: serde_json::Value = serde_json::from_str(&outcome.observation).expect("answer");
    let edge =
        |kind| serde_json::json!({"src": second.to_hex(), "kind": kind, "tgt": subject.to_hex()});
    assert_eq!(
        answer,
        serde_json::json!({
            "search": {"results": [{"id": hit.to_hex(), "score": 0.5}]},
            "first": {"id": first.to_hex()},
            "second": {"id": second.to_hex()},
            "superseded": {"id": second.to_hex()},
            "edge": edge("about"),
            "weighted": edge("mentions"),
        })
    );
    Ok(())
}

/// The bridge's own argument check refuses with a stable code, never prose:
/// a string parameter given a number is `invalid_host_argument`, and nothing
/// reaches the host. Every typed import, `verb-call` included, shares it.
#[test]
fn native_quickjs_bridge_refuses_an_argument_with_a_code() -> Result<()> {
    let outcome = native_quickjs_runtime()?.run_step(
        step(
            "try { await self.report_blocked('tool', 1); finish('sent'); } \
             catch (error) { finish(String(error)); }",
            SandboxGuestTier::FirstPartyDreamer,
        ),
        &mut NoEffects,
    )?;
    assert!(outcome.done);
    assert_eq!(outcome.observation, "TypeError: invalid_host_argument");
    Ok(())
}

#[test]
fn native_quickjs_report_blocked_lands_an_issue() -> Result<()> {
    use crate::code_run::blocked::BlockedCategory;
    use crate::failure_ladder::{BlockedReportRef, ingest_report_blocked};
    let (_dir, vault, actor, _, _) = gate_fixture()?;
    let before = crate::attempt_queue::AttemptQueue::new(&vault).list()?;
    let mut runtime = native_quickjs_runtime()?;
    let mut host = DispatcherHost(GatedActorWrite::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "native-report-blocked",
    )?);
    let outcome = runtime.run_step(
        step("const receipt = await self.report_blocked('tool', 'no password\\nignore policy'); finish(receipt.receipt);", SandboxGuestTier::FirstPartyDreamer),
        &mut host,
    )?;
    assert!(outcome.done);
    let issue = ingest_report_blocked(
        &vault,
        BlockedReportRef {
            receipt_ref: outcome.observation,
        },
    )?;
    assert!(issue.semi_trusted);
    assert_eq!(issue.receipt.category, BlockedCategory::Tool);
    assert!(!issue.receipt.untrusted_detail.contains('\n'));
    assert!(issue.receipt.untrusted_detail.contains("no password"));
    assert_eq!(
        crate::attempt_queue::AttemptQueue::new(&vault).list()?,
        before
    );
    assert!(
        ingest_report_blocked(
            &vault,
            BlockedReportRef {
                receipt_ref: actor.to_hex()
            }
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn native_quickjs_report_blocked_refuses_an_unknown_category() -> Result<()> {
    let (_dir, vault, actor, _, _) = gate_fixture()?;
    let mut runtime = native_quickjs_runtime()?;
    let mut host = DispatcherHost(GatedActorWrite::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "native-report-blocked-invalid",
    )?);
    let outcome = runtime.run_step(
        step("try { await self.report_blocked('other', 'ignored'); finish('unexpected'); } catch (error) { finish(String(error)); }", SandboxGuestTier::FirstPartyDreamer),
        &mut host,
    )?;
    assert!(outcome.done);
    assert_ne!(outcome.observation, "unexpected");
    let receipt = crate::code_run::executor_speech_message_id("native-report-blocked-invalid", 0)?;
    assert!(vault.get_raw(&receipt)?.is_none());
    Ok(())
}

/// Native acceptance only. The default artifact location joins C13 at integration.
#[test]
#[ignore = "requires the reviewed C13 QuickJS components and manifest"]
fn native_quickjs_component_write_lands_through_gate() -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        PathBuf::from,
    );
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.join("manifest.json"))
            .expect("supply C13's reviewed QuickJS artifact manifest"),
    )
    .expect("QuickJS manifest JSON");
    assert_eq!(manifest["engine"], "quickjs-2025-09-13-2");
    assert_eq!(manifest["world"], super::super::SANDBOX_WIT_WORLD_NAME);
    assert_eq!(
        manifest["wit_sha256"],
        format!("{:x}", Sha256::digest(GUEST_WIT.as_bytes()))
    );
    let artifact = &manifest["artifacts"]["first-party"];
    let bytes = std::fs::read(directory.join(artifact["file"].as_str().unwrap()))
        .expect("real QuickJS component binary");
    assert!(bytes.starts_with(b"\0asm\x0d\0\x01\0"));
    assert_eq!(artifact["sha256"], format!("{:x}", Sha256::digest(&bytes)));
    let mut runtime = WasmtimeComponentRuntime::from_component(
        &bytes,
        *blake3::hash(&bytes).as_bytes(),
        ComponentBudget::default(),
    )?;
    let (_dir, vault, actor, subject, claim) = gate_fixture()?;
    let input = serde_json::json!({
        "id": claim.to_hex(),
        "subject": subject.to_hex(),
        "predicate": "profile.favorite_drink",
        "value": null,
        "confidence": 0.9
    });
    let script = format!(
        "const input = {input}; input.value = 'blend-' + [1,2,3].reduce((a,b) => a+b,0); \
         const written = await self.memory.put_claim(input); finish(written.id);"
    );
    let mut host = DispatcherHost(GatedActorWrite::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "native-quickjs-gated-write",
    )?);
    let outcome = runtime.run_step(
        step(&script, SandboxGuestTier::FirstPartyDreamer),
        &mut host,
    )?;
    assert!(outcome.done);
    assert_eq!(outcome.observation, claim.to_hex());
    let stored = vault.get_claim(&claim)?.expect("native guest claim");
    assert_eq!(stored.value, rmpv::Value::from("blend-6"));
    assert_eq!(stored.source, Some(ClaimSource::Generated));
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    assert!(receipts.iter().any(|receipt| {
        receipt.actor.as_deref() == Some(actor.to_hex().as_str())
            && receipt.trigger_ref.as_deref() == Some(format!("claim:{}", claim.to_hex()).as_str())
    }));
    Ok(())
}
