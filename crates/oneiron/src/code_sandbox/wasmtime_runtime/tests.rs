use super::*;
use crate::code_run::{CodeRunDeterminism, GatedActorWrite, SelfCall, SelfDispatcher};
use crate::engine_executor::SelfDispatchResponse;
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, WriteActor,
};

// A bounded ABI test component. This is NOT a QuickJS implementation.
// It forwards the run input to exactly one linked function and returns a
// constant step result. Both lowering and lifting execute through Wasmtime.
fn fixture(import: &str) -> String {
    let result = r#"{"done":true,"observation":"called"}"#;
    let escaped = result
        .as_bytes()
        .iter()
        .map(|b| format!("\\{b:02x}"))
        .collect::<String>();
    format!(
        r#"(component
      (import "{import}" (func $trap (param "input" string) (result string)))
      (core module $mem
        (memory (export "memory") 2)
        (global $next (mut i32) (i32.const 4096))
        (func (export "realloc") (param i32 i32 i32 i32) (result i32)
          (local $ptr i32)
          global.get $next local.tee $ptr local.get 3 i32.add
          i32.const 7 i32.add i32.const -8 i32.and global.set $next local.get $ptr)
        (data (i32.const 64) "{escaped}"))
      (core instance $mem (instantiate $mem))
      (core func $trap (canon lower (func $trap)
        (memory (core memory $mem "memory")) (realloc (core func $mem "realloc"))))
      (core module $main
        (import "mem" "memory" (memory 2))
        (import "host" "trap" (func $trap (param i32 i32 i32)))
        (func (export "run") (param i32 i32) (result i32)
          local.get 0 local.get 1 i32.const 0 call $trap
          i32.const 16 i32.const 64 i32.store
          i32.const 20 i32.const {length} i32.store
          i32.const 16))
      (core instance $host (export "trap" (func $trap)))
      (core instance $main (instantiate $main (with "mem" (instance $mem)) (with "host" (instance $host))))
      (func (export "run") (param "script" string) (result string)
        (canon lift (core func $main "run") (memory (core memory $mem "memory")) (realloc (core func $mem "realloc")))))"#,
        length = result.len()
    )
}

fn runtime(import: &str) -> WasmtimeComponentRuntime {
    let component = fixture(import);
    WasmtimeComponentRuntime::from_component(
        component.as_bytes(),
        *blake3::hash(component.as_bytes()).as_bytes(),
        ComponentBudget::default(),
    )
    .expect("fixture component")
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
            outcome: self.0.dispatch(call)?,
            budget: None,
        })
    }
}

#[test]
fn component_write_enters_real_dispatcher_and_gate() -> Result<()> {
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
    let mut host = DispatcherHost(GatedActorWrite::new(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "component-gated-write",
    )?);
    let input = serde_json::json!({"id":claim.to_hex(),"subject":subject.to_hex(),
        "predicate":"profile.favorite_drink","value":"sencha","confidence":0.9})
    .to_string();
    let outcome = runtime("memory-put-claim")
        .run_step(step(&input, SandboxGuestTier::FirstPartyDreamer), &mut host)?;
    assert!(outcome.done);
    let stored = vault
        .get_claim(&claim)?
        .expect("claim committed through trap");
    assert_eq!(stored.source, Some(ClaimSource::Generated));
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
        runtime("memory-put-claim")
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
    let component = fixture("clock-now-unix-ms");
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
