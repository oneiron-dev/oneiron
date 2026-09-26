use super::*;
use crate::code_run::{CodeRunDeterminism, GatedActorWrite, SelfCall, SelfDispatcher};
use crate::engine_executor::SelfDispatchResponse;
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, WriteActor,
};

const CLAIM_CALL: &str = "i32.const 0 i32.load i32.const 4 i32.load
    i32.const 8 i32.load i32.const 12 i32.load
    i32.const 16 i32.load i32.const 20 i32.load
    i32.const 24 i32.load i32.const 28 i32.load
    i32.const 0 f32.const 0 i32.const 0 i64.const 0 i64.const 0
    i32.const 0 i64.const 0 i32.const 512 call $trap";

// Typed ABI fixture only, NOT a JavaScript interpreter. The complete record
// shape and run-step export match the C13 WIT, not the retired string-run ABI.
fn fixture(import: &str, input: &serde_json::Value, forged: bool) -> String {
    let output = r#"{"done":true,"observation":"called"}"#;
    let mut data = Vec::new();
    let mut init = String::new();
    let mut next = 128usize;
    for (slot, value) in [
        input
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        input
            .get("predicate")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        serde_json::to_string(&input["subject"]).unwrap(),
        serde_json::to_string(&input["value"]).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        data.push(format!(
            r#"(data (i32.const {next}) "{}")"#,
            escaped(&value)
        ));
        init.push_str(&format!(
            "i32.const {} i32.const {next} i32.store\ni32.const {} i32.const {} i32.store\n",
            slot * 8,
            slot * 8 + 4,
            value.len()
        ));
        next += value.len() + 1;
    }
    data.push(format!(r#"(data (i32.const 2048) "{}")"#, escaped(output)));
    let extra = if forged {
        "(field \"approval\" string)"
    } else {
        ""
    };
    let types = format!(
        r#"
      (type $time-shape (record (field "start" u64) (field "end" u64)))
      (import "time-range" (type $time (eq $time-shape)))
      (type $claim-shape (record (field "id" string) (field "predicate" string)
        (field "subject" string) (field "value" string) (field "confidence" (option f32))
        (field "occurred" (option $time)) (field "learned-at" (option u64)) {extra}))
      (import "claim-input" (type $claim (eq $claim-shape)))
      (type $claim-output-shape (record (field "id" string)))
      (import "claim-output" (type $claim-output (eq $claim-output-shape)))
      (type $file-shape (record (field "path" string) (field "bytes" (list u8))))
      (import "file-proposal" (type $file (eq $file-shape)))
      (type $proposal-shape (variant (case "file-write" $file) (case "claim-candidate" $claim)))
      (import "proposal-delta" (type $proposal (eq $proposal-shape)))
      (type $step-shape (record (field "result-json" string) (field "proposals" (list $proposal))))
      (import "step-result" (type $step (eq $step-shape)))
      (type $reply (result $step (error string)))"#
    );
    let (declaration, lower, core_import, call) = if import == "memory-put-claim" {
        // The canonical claim flattens to 15 arguments plus its return pointer.
        // Adding a forged field exceeds MAX_FLAT_PARAMS and uses an input pointer.
        let (parameters, invoke) = if forged {
            ("i32 i32", "i32.const 0 i32.const 512 call $trap")
        } else {
            (
                "i32 i32 i32 i32 i32 i32 i32 i32 i32 f32 i32 i64 i64 i32 i64 i32",
                CLAIM_CALL,
            )
        };
        let invoke = match input["confidence"].as_f64() {
            Some(confidence) => invoke.replace(
                "i32.const 0 f32.const 0",
                &format!("i32.const 1 f32.const {confidence}"),
            ),
            None => invoke.to_owned(),
        };
        (format!(r#"(import "{import}" (func $trap (param "input" $claim) (result (result $claim-output (error string)))))"#),
         r#"(core func $trap (canon lower (func $trap) (memory (core memory $mem "memory")) (realloc (core func $mem "realloc"))))"#.to_owned(),
         format!(r#"(import "host" "trap" (func $trap (param {parameters})))"#),
         format!("{init} {invoke} i32.const 512 i32.load8_u if unreachable end"))
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

fn runtime_with(import: &str, input: &serde_json::Value, forged: bool) -> WasmtimeComponentRuntime {
    let component = fixture(import, input, forged);
    WasmtimeComponentRuntime::from_component(
        component.as_bytes(),
        *blake3::hash(component.as_bytes()).as_bytes(),
        ComponentBudget::default(),
    )
    .expect("typed fixture component")
}
fn runtime(import: &str) -> WasmtimeComponentRuntime {
    runtime_with(import, &serde_json::Value::Null, false)
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
    let input = serde_json::json!({"id":claim.to_hex(),"subject":subject.to_hex(),
        "predicate":"profile.favorite_drink","value":"sencha","confidence":0.9})
    .to_string();
    let outcome = runtime_with(
        "memory-put-claim",
        &serde_json::from_str(&input).unwrap(),
        false,
    )
    .run_step(step(&input, SandboxGuestTier::FirstPartyDreamer), &mut host)?;
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
    let forged = serde_json::json!({"id":EntityId::from_bytes([0xc5;16])?.to_hex(),
        "subject":subject.to_hex(),"predicate":"profile.favorite_drink","value":"tea",
        "source":"human","approval":"confirmed"})
    .to_string();
    assert!(
        runtime_with(
            "memory-put-claim",
            &serde_json::from_str(&forged).unwrap(),
            true
        )
        .run_step(
            step(&forged, SandboxGuestTier::FirstPartyDreamer),
            &mut host
        )
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
            runtime("memory-put-claim")
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
    let component = fixture("clock-now-unix-ms", &serde_json::Value::Null, false);
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
        let component = fixture("clock-now-unix-ms", &serde_json::Value::Null, false)
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

#[test]
fn invalid_typed_arguments_still_consume_host_call_budget() {
    struct NoCalls;
    impl JsCodeModeHost for NoCalls {
        fn dispatch_self(&mut self, _: SelfCall) -> Result<SelfDispatchResponse> {
            panic!("invalid subject must not reach the engine host")
        }
    }
    // Empty/null fixture fields cannot become a valid typed claim. The guest
    // ignores the first typed error, then repeats the invalid invocation.
    let component = fixture("memory-put-claim", &serde_json::Value::Null, false)
        .replace("i32.const 512 i32.load8_u if unreachable end", "")
        .replace(CLAIM_CALL, &format!("{CLAIM_CALL} {CLAIM_CALL}"));
    let mut runtime = WasmtimeComponentRuntime::from_component(
        component.as_bytes(),
        *blake3::hash(component.as_bytes()).as_bytes(),
        ComponentBudget {
            host_calls: 1,
            ..ComponentBudget::default()
        },
    )
    .expect("typed component");
    assert!(
        runtime
            .run_step(step("", SandboxGuestTier::FirstPartyDreamer), &mut NoCalls)
            .is_err()
    );
}

#[test]
fn non_finite_typed_claim_confidence_refuses_before_dispatch() {
    let input = serde_json::json!({
        "id": "11111111111111111111111111111111",
        "subject": "22222222222222222222222222222222",
        "predicate": "profile.favorite_drink",
        "value": "sencha"
    });
    let component = fixture("memory-put-claim", &input, false)
        .replace("i32.const 0 f32.const 0", "i32.const 1 f32.const nan");
    let mut runtime = WasmtimeComponentRuntime::from_component(
        component.as_bytes(),
        *blake3::hash(component.as_bytes()).as_bytes(),
        ComponentBudget::default(),
    )
    .expect("typed component");
    assert!(
        runtime
            .run_step(
                step("", SandboxGuestTier::FirstPartyDreamer),
                &mut NoEffects
            )
            .is_err()
    );
}

#[test]
fn shared_engine_cleanup_does_not_cancel_a_sibling_store() {
    use crate::code_run::{SelfDispatchOutcome, SelfMemoryWriteResult};

    struct Host {
        entered: Option<mpsc::Sender<()>>,
        release: Option<mpsc::Receiver<()>>,
    }
    impl JsCodeModeHost for Host {
        fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).expect("announce blocked host call");
            }
            if let Some(release) = self.release.take() {
                release.recv().expect("release host call");
            }
            let SelfCall::MemoryPutClaim(call) = call else {
                panic!("unexpected test import");
            };
            Ok(SelfDispatchResponse {
                outcome: SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: call.id }),
                budget: None,
            })
        }
    }
    let input = serde_json::json!({
        "id": "11111111111111111111111111111111",
        "subject": "22222222222222222222222222222222",
        "predicate": "profile.favorite_drink",
        "value": "sencha"
    });
    let component = fixture("memory-put-claim", &input, false)
        .replace(
            "(func (export \"run-step\") (param i32 i32) (result i32)",
            "(func (export \"run-step\") (param i32 i32) (result i32) (local $remaining i32)",
        )
        .replace(
            "i32.const 1024 i32.const 0 i32.store",
            "local.get 1 local.set $remaining
             (loop $after
               local.get $remaining i32.const 1 i32.sub local.tee $remaining br_if $after)
             i32.const 1024 i32.const 0 i32.store",
        );
    let mut first = WasmtimeComponentRuntime::from_component(
        component.as_bytes(),
        *blake3::hash(component.as_bytes()).as_bytes(),
        ComponentBudget {
            wall_time: Duration::from_secs(30),
            ..ComponentBudget::default()
        },
    )
    .expect("typed component");
    let mut sibling = first.fresh();
    let (entered, arrival) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let running = std::thread::spawn(move || {
        sibling.run_step(
            step("work", SandboxGuestTier::FirstPartyDreamer),
            &mut Host {
                entered: Some(entered),
                release: Some(resume),
            },
        )
    });
    arrival
        .recv_timeout(Duration::from_secs(10))
        .expect("sibling entered guest");
    let first_result = first.run_step(
        step("work", SandboxGuestTier::FirstPartyDreamer),
        &mut Host {
            entered: None,
            release: None,
        },
    );
    // The first run has completed cleanup and incremented the shared epoch.
    release.send(()).expect("release sibling");
    let sibling_result = running.join().expect("sibling thread");
    assert!(first_result.expect("first run").done);
    assert!(
        sibling_result
            .expect("sibling must keep its own deadline")
            .done
    );
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
