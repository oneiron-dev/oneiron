//! Component fixtures test the boundary, not a substitute JavaScript runtime.
use super::*;
use bindings::*;

struct Host(u64);
impl GuestImports for Host {
    fn read_file(&mut self, _: String) -> Result<Vec<u8>, String> {
        Err("not mounted".into())
    }
    fn credential_call(&mut self, _: CredentialInput) -> Result<String, String> {
        Err("unknown handle".into())
    }
    fn clock_now_unix_ms(&mut self) -> u64 {
        self.0
    }
    fn random_bytes(&mut self, n: u32) -> Result<Vec<u8>, String> {
        if n > 65536 {
            return Err("random request too large".into());
        }
        Ok(vec![7; n as usize])
    }
    fn memory_search(&mut self, _: SearchInput) -> Result<SearchOutput, String> {
        Ok(SearchOutput { results: vec![] })
    }
    fn memory_put_claim(&mut self, input: ClaimInput) -> Result<ClaimOutput, String> {
        Ok(ClaimOutput { id: input.id })
    }
    fn memory_supersede_claim(&mut self, input: SupersedeInput) -> Result<ClaimOutput, String> {
        Ok(ClaimOutput { id: input.new_id })
    }
    fn memory_put_edge(&mut self, input: EdgeInput) -> Result<EdgeOutput, String> {
        Ok(EdgeOutput {
            src: input.src,
            kind: input.kind,
            tgt: input.tgt,
        })
    }
    fn ask_human(&mut self, _: PromptInput) -> Result<WaitOutput, String> {
        Ok(WaitOutput {
            wait_id: "wait".into(),
        })
    }
    fn ask_human_camel(&mut self, input: PromptInput) -> Result<WaitOutput, String> {
        self.ask_human(input)
    }
    fn speak(&mut self, _: TextInput) -> Result<SpeechOutput, String> {
        Ok(SpeechOutput {
            order: 0,
            is_visible: true,
        })
    }
    fn think(&mut self, input: TextInput) -> Result<SpeechOutput, String> {
        self.speak(input)
    }
    fn express(&mut self, input: TextInput) -> Result<SpeechOutput, String> {
        self.speak(input)
    }
}

const CLOCK_AND_COUNTER: &[u8] = br#"(component
  (import "clock-now-unix-ms" (func $now (result u64)))
  (core func $lowered (canon lower (func $now)))
  (core module $m
    (import "" "now" (func $now (result i64)))
    (global $counter (mut i32) (i32.const 0))
    (func (export "clock") (result i64) call $now)
    (func (export "next") (result i32)
      global.get $counter i32.const 1 i32.add global.set $counter global.get $counter))
  (core instance $i (instantiate $m
    (with "" (instance (export "now" (func $lowered))))))
  (func (export "clock") (result u64) (canon lift (core func $i "clock")))
  (func (export "next") (result u32) (canon lift (core func $i "next"))))"#;

#[test]
fn per_tier_import_inventory_equals_boundary_contract() {
    for tier in [
        SandboxGuestTier::FirstPartyDreamer,
        SandboxGuestTier::Foreign,
        SandboxGuestTier::Untrusted,
    ] {
        let actual: std::collections::BTreeSet<_> = linked_imports(tier)
            .iter()
            .map(|(_, public)| *public)
            .collect();
        let contract = SandboxBoundaryContract::for_tier(tier);
        let expected = contract
            .linked_imports()
            .iter()
            .map(|import| import.name())
            .collect();
        assert_eq!(actual, expected);
        if tier.requires_zero_write_imports() {
            assert!(actual.iter().all(|name| !name.starts_with("self.")));
        }
    }
}

#[test]
fn each_request_has_fresh_guest_globals_and_host_controlled_clock() {
    let boundary = WasmtimeBoundary::new().unwrap();
    let component = boundary.compile(CLOCK_AND_COUNTER).unwrap();
    for tier in [
        SandboxGuestTier::FirstPartyDreamer,
        SandboxGuestTier::Foreign,
        SandboxGuestTier::Untrusted,
    ] {
        let mut first = boundary.request(&component, tier, Host(123)).unwrap();
        assert_eq!(first.call::<(), (u64,)>("clock", ()).unwrap(), (123,));
        assert_eq!(first.call::<(), (u32,)>("next", ()).unwrap(), (1,));
        assert_eq!(first.call::<(), (u32,)>("next", ()).unwrap(), (2,));
        let mut second = boundary.request(&component, tier, Host(456)).unwrap();
        assert_eq!(second.call::<(), (u64,)>("clock", ()).unwrap(), (456,));
        assert_eq!(second.call::<(), (u32,)>("next", ()).unwrap(), (1,));
    }
}

#[test]
fn foreign_writes_and_all_wasi_imports_fail_construction() {
    let boundary = WasmtimeBoundary::new().unwrap();
    let write = boundary
        .compile(
            br#"(component
      (type $input-shape (record (field "new-id" string) (field "old-id" string) (field "now" u64)))
      (import "supersede-input" (type $input (eq $input-shape)))
      (type $output-shape (record (field "id" string)))
      (import "mutation-result" (type $output (eq $output-shape)))
      (type $reply (result $output (error string)))
      (import "memory-supersede-claim" (func (param "input" $input) (result $reply))))"#,
        )
        .unwrap();
    assert!(
        boundary
            .request(&write, SandboxGuestTier::FirstPartyDreamer, Host(0))
            .is_ok()
    );
    for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
        assert!(boundary.request(&write, tier, Host(0)).is_err());
    }
    let wasi = boundary
        .compile(
            br#"(component
      (import "wasi:filesystem/preopens@0.2.0" (instance (export "get-directories" (func)))))"#,
        )
        .unwrap();
    for tier in [
        SandboxGuestTier::FirstPartyDreamer,
        SandboxGuestTier::Foreign,
        SandboxGuestTier::Untrusted,
    ] {
        assert!(boundary.request(&wasi, tier, Host(0)).is_err());
    }
}

#[test]
fn fuel_and_memory_exhaustion_trap() {
    let boundary = WasmtimeBoundary::new().unwrap();
    let component = boundary
        .compile(
            br#"(component
      (core module $m
        (memory 1)
        (func (export "spin") (loop br 0))
        (func (export "grow") (result i32) i32.const 1024 memory.grow))
      (core instance $i (instantiate $m))
      (func (export "spin") (canon lift (core func $i "spin")))
      (func (export "grow") (result s32) (canon lift (core func $i "grow"))))"#,
        )
        .unwrap();
    let mut request = boundary
        .request(&component, SandboxGuestTier::Foreign, Host(0))
        .unwrap();
    let error = request.call::<(), ()>("spin", ()).unwrap_err();
    assert_eq!(
        error.downcast_ref::<wasmtime::Trap>(),
        Some(&wasmtime::Trap::OutOfFuel)
    );
    let mut request = boundary
        .request(&component, SandboxGuestTier::Foreign, Host(0))
        .unwrap();
    assert!(request.call::<(), (i32,)>("grow", ()).is_err());
}
