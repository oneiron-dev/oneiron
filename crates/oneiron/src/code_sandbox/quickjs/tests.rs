//! Acceptance tests require the real artifacts produced by the pinned build.
use super::*;
use crate::code_run::{
    SelfDispatchOutcome, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
    SelfMemoryEdgeWriteResult, SelfMemoryWriteResult,
};
use crate::engine_executor::JsCodeModeStepOutcome;
use serde_json::Value;
use std::path::PathBuf;

fn artifact(tier: &str) -> (Vec<u8>, [u8; 32]) {
    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        PathBuf::from,
    );
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(directory.join("manifest.json"))
            .expect("build the real QuickJS components; see components/code-run-quickjs/README.md"),
    )
    .unwrap();
    assert_eq!(manifest["world"], super::super::SANDBOX_WIT_WORLD_NAME);
    let row = &manifest["artifacts"][tier];
    let bytes = std::fs::read(directory.join(row["file"].as_str().unwrap())).unwrap();
    let text = row["sha256"].as_str().unwrap();
    assert_eq!(text.len(), 64);
    let mut hash = [0; 32];
    for (index, value) in hash.iter_mut().enumerate() {
        *value = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
    }
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), hash);
    (bytes, hash)
}

#[derive(Default)]
struct Host {
    calls: Vec<SelfCall>,
}
impl JsCodeModeHost for Host {
    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
        self.calls.push(call.clone());
        let outcome = match call {
            SelfCall::MemoryPutClaim(call) => {
                SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: call.id })
            }
            SelfCall::MemoryPutEdge(call) => {
                SelfDispatchOutcome::MemoryEdgeWrite(SelfMemoryEdgeWriteResult {
                    src: call.src,
                    kind: call.kind,
                    tgt: call.tgt,
                })
            }
            SelfCall::Ask(_) => SelfDispatchOutcome::DurableWait(SelfDurableWait {
                wait_id: EntityId::from_bytes([2; 16])?,
                effect: SelfEffect::Ask,
                reason: SelfDurableWaitReason::HumanInput,
                prompt: None,
            }),
            _ => return Err(Error::InvalidConfig("unexpected test call".into())),
        };
        Ok(SelfDispatchResponse {
            outcome,
            budget: None,
        })
    }
}

fn run(
    runtime: &mut dyn JsCodeModeRuntime,
    script: &str,
    host: &mut Host,
) -> Result<JsCodeModeStepOutcome> {
    runtime.run_step(
        JsCodeModeStep {
            run_id: EntityId::from_bytes([1; 16])?,
            seq: 3,
            script,
            boundary: SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer),
            determinism: CodeRunDeterminism::new(1_700_000_000_000, [9; 32]),
        },
        host,
    )
}

#[test]
fn quickjs_real_language_typed_writes_determinism_and_escape_refusal() {
    let (bytes, hash) = artifact("first-party");
    let factory =
        QuickJsRuntimeFactory::from_component(&bytes, hash, ComponentBudget::default()).unwrap();
    let mut runtime = factory.runtime().unwrap();
    let mut host = Host::default();
    let language = run(
        &mut runtime,
        include_str!("../../../../../components/code-run-quickjs/fixtures/language.js"),
        &mut host,
    )
    .unwrap();
    assert!(language.done);
    let value: Value = serde_json::from_str(&language.observation).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"result":42,"regexp":true,"bigint":"18446744073709551616"})
    );
    let script = include_str!("../../../../../components/code-run-quickjs/fixtures/determinism.js");
    let first = run(&mut runtime, script, &mut host).unwrap();
    let second = run(&mut runtime, script, &mut host).unwrap();
    assert_eq!(first, second);
    let value: Value = serde_json::from_str(&first.observation).unwrap();
    assert_eq!(value["now"], 1_700_000_000_000u64);
    assert_eq!(value["date"], value["now"]);
    assert_eq!(value["zone"], 0);
    assert_ne!(value["random"][0], value["random"][1]);
    let written = run(
        &mut runtime,
        include_str!("../../../../../components/code-run-quickjs/fixtures/writes.js"),
        &mut host,
    )
    .unwrap();
    assert!(written.done);
    assert_eq!(host.calls.len(), 2);
    assert!(matches!(host.calls[0], SelfCall::MemoryPutClaim(_)));
    assert!(matches!(host.calls[1], SelfCall::MemoryPutEdge(_)));
    let escaped = run(
        &mut runtime,
        include_str!("../../../../../components/code-run-quickjs/fixtures/escape.js"),
        &mut host,
    )
    .unwrap();
    let value: Value = serde_json::from_str(&escaped.observation).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"absent":["undefined","undefined","undefined","undefined","undefined","undefined"],"moduleRefused":true,"readRefused":true,"pathRefused":true,"indirect":"undefined"})
    );
    run(
        &mut runtime,
        "globalThis.leaked = 7; finish('one');",
        &mut host,
    )
    .unwrap();
    assert_eq!(
        run(&mut runtime, "finish(typeof leaked);", &mut host)
            .unwrap()
            .observation,
        "undefined"
    );
}

#[test]
fn quickjs_exposes_bare_ask_but_no_self_ask_alias() {
    let (bytes, hash) = artifact("first-party");
    let factory = QuickJsRuntimeFactory::from_component(&bytes, hash, ComponentBudget::default())
        .expect("pinned real component");
    let mut host = Host::default();
    let mut runtime = factory.runtime().expect("runtime");
    let output = run(
        &mut runtime,
        "const wait = await ask({prompt:'continue?'}); finish(JSON.stringify({wait, old:typeof self.ask_human, camel:typeof self.askHuman}));",
        &mut host,
    ).expect("guest bare ask");
    let result: Value = serde_json::from_str(&output.observation).expect("guest result");
    assert_eq!(
        result["wait"]["waitId"],
        EntityId::from_bytes([2; 16]).unwrap().to_hex()
    );
    assert_eq!(result["old"], "undefined");
    assert_eq!(result["camel"], "undefined");
    assert!(matches!(&host.calls[..], [SelfCall::Ask(call)] if call.prompt == "continue?"));
}

#[test]

fn quickjs_json_validate_returns_shared_allow_reject_verdicts_without_dispatch() {
    let (bytes, hash) = artifact("first-party");
    let factory =
        QuickJsRuntimeFactory::from_component(&bytes, hash, ComponentBudget::default()).unwrap();
    let mut host = Host::default();
    let result = run(
        &mut factory.runtime().unwrap(),
        "const schema = {type:'object',required:['count'],properties:{count:{type:'integer'}}}; \
         const allow = await self.json.validate(schema,{count:3}); \
         const reject = await self.json.validate(schema,{count:'three'}); \
         const invalidSchema = await self.json.validate({type:'not-a-type'},{count:3}); \
         finish(JSON.stringify({allow,reject,invalidSchema}));",
        &mut host,
    )
    .unwrap();
    assert!(result.done);
    assert_eq!(
        serde_json::from_str::<Value>(&result.observation).unwrap(),
        serde_json::json!({"allow":true,"reject":false,"invalidSchema":false})
    );
    assert!(
        host.calls.is_empty(),
        "validation must not dispatch a self effect"
    );
}

#[test]
fn quickjs_json_validate_recursive_schemas_are_bounded() {
    const CHILD: &str = "ONEIRON_JSON_VALIDATE_RECURSIVE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let (bytes, hash) = artifact("first-party");
        let factory =
            QuickJsRuntimeFactory::from_component(&bytes, hash, ComponentBudget::default())
                .expect("pinned component");
        let result = run(
            &mut factory.runtime().expect("runtime"),
            "const bad = {allOf:[{$ref:'#'}]}; \
             const recursive = {type:'object',properties:{next:{$ref:'#'}}}; \
             const tupleCycle = {$schema:'http://json-schema.org/draft-07/schema#', \
                items:[{allOf:[{$ref:'#/items/0'}]}]}; \
             const tuple = {$schema:'http://json-schema.org/draft-07/schema#', \
                items:[{type:'integer'}]}; \
             const emptyKey = {$defs:{'':{type:'integer'}},$ref:'#/$defs/'}; \
             const pct = {$defs:{a:{type:'integer'}},$ref:'#/$defs/%61'}; \
             const pctCycle = {$defs:{a:{allOf:[{$ref:'#/$defs/%61'}]},'%61':{}}, \
                $ref:'#/$defs/a'}; \
             const draft4Cycle = {$schema:'http://json-schema.org/draft-04/schema#', \
                properties:{a:{id:'urn:oneiron:test:a',allOf:[{$ref:'#'}]}}}; \
             finish(JSON.stringify({loop:await self.json.validate(bad,null), \
                valid:await self.json.validate(recursive,{next:{next:{}}}), \
                invalid:await self.json.validate(recursive,{next:5}), \
                tupleLoop:await self.json.validate(tupleCycle,[null]), \
                tupleValid:await self.json.validate(tuple,[3]), \
                tupleInvalid:await self.json.validate(tuple,['bad']), \
                emptyValid:await self.json.validate(emptyKey,3), \
                emptyInvalid:await self.json.validate(emptyKey,'bad'), \
                pctValid:await self.json.validate(pct,3), \
                pctInvalid:await self.json.validate(pct,'bad'), \
                pctCycle:await self.json.validate(pctCycle,null), \
                draft4Cycle:await self.json.validate(draft4Cycle,{a:null})}));",
            &mut Host::default(),
        )
        .expect("sandbox returns without aborting the host");
        assert_eq!(
            serde_json::from_str::<Value>(&result.observation).unwrap(),
            serde_json::json!({"loop":false,"valid":true,"invalid":false,
                "tupleLoop":false,"tupleValid":true,"tupleInvalid":false,
                "emptyValid":true,"emptyInvalid":false,
                "pctValid":true,"pctInvalid":false,"pctCycle":false,"draft4Cycle":false})
        );
        return;
    }
    // A native stack overflow aborts the process and cannot be caught by Wasmtime.
    // Isolate the regression so the parent test runner survives a broken validator.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("code_sandbox::quickjs::tests::quickjs_json_validate_recursive_schemas_are_bounded")
        .env(CHILD, "1")
        .spawn()
        .expect("spawn isolated sandbox regression");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().expect("child status") {
            assert!(
                status.success(),
                "recursive schema must not abort the host: {status}"
            );
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().expect("stop stalled validation child");
            let _ = child.wait();
            panic!("recursive schema validation exceeded the child deadline");
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

#[test]
fn default_budget_passes_the_readiness_probe() {
    let (bytes, hash) = artifact("first-party");
    assert!(
        QuickJsRuntimeFactory::from_component(&bytes, hash, ComponentBudget::default()).is_ok()
    );
}

#[test]
fn quickjs_pin_and_instruction_limits_fail_closed() {
    let (bytes, hash) = artifact("first-party");
    assert!(
        QuickJsRuntimeFactory::from_component(&bytes, [0; 32], ComponentBudget::default()).is_err()
    );
    let factory =
        QuickJsRuntimeFactory::from_component(&bytes, hash, ComponentBudget::default()).unwrap();
    assert!(
        run(
            &mut factory.runtime().unwrap(),
            "for (;;) {}",
            &mut Host::default()
        )
        .is_err()
    );
}

#[test]
fn quickjs_foreign_exports_proposals_and_cannot_link_first_party() {
    use crate::code_sandbox::wasmtime_boundary::{WasmtimeBoundary, bindings};
    let (foreign, _) = artifact("foreign");
    let (first_party, _) = artifact("first-party");
    let boundary = WasmtimeBoundary::new().unwrap();
    let foreign = boundary.compile(&foreign).unwrap();
    let first_party = boundary.compile(&first_party).unwrap();
    assert!(
        boundary
            .request(&first_party, SandboxGuestTier::Foreign, ForeignHost)
            .is_err()
    );
    let mut request = boundary
        .request(&foreign, SandboxGuestTier::Foreign, ForeignHost)
        .unwrap();
    let result = request
        .run_step(
            include_str!("../../../../../components/code-run-quickjs/fixtures/foreign.js")
                .to_owned(),
        )
        .unwrap();
    assert_eq!(result.proposals.len(), 2);
    assert!(matches!(
        result.proposals[0],
        bindings::ProposalDelta::FileWrite(_)
    ));
    assert!(matches!(
        result.proposals[1],
        bindings::ProposalDelta::ClaimCandidate(_)
    ));
    let value: Value = serde_json::from_str(&result.result_json).unwrap();
    assert_eq!(value["observation"], "proposals-only");
}

struct ForeignHost;
impl crate::code_sandbox::wasmtime_boundary::bindings::GuestImports for ForeignHost {
    fn clock_now_unix_ms(&mut self) -> u64 {
        1_700_000_000_000
    }
    fn random_bytes(&mut self, length: u32) -> std::result::Result<Vec<u8>, String> {
        Ok(vec![7; length as usize])
    }
    fn read_file(&mut self, _: String) -> std::result::Result<Vec<u8>, String> {
        Err("unavailable".into())
    }
    fn credential_call(
        &mut self,
        _: crate::code_sandbox::wasmtime_boundary::bindings::CredentialInput,
    ) -> std::result::Result<String, String> {
        Err("unlinked capability".into())
    }
    fn agents_put(
        &mut self,
        _: crate::code_sandbox::wasmtime_boundary::bindings::AgentPutInput,
    ) -> std::result::Result<crate::code_sandbox::wasmtime_boundary::bindings::AgentPutOutput, String>
    {
        Err("unlinked capability".into())
    }
    fn json_validate(&mut self, _: String, _: String) -> std::result::Result<bool, String> {
        Err("unlinked capability".into())
    }
    fn memory_search(
        &mut self,
        _: crate::code_sandbox::wasmtime_boundary::bindings::SearchInput,
    ) -> std::result::Result<crate::code_sandbox::wasmtime_boundary::bindings::SearchOutput, String>
    {
        Err("unlinked capability".into())
    }
    fn memory_put_claim(
        &mut self,
        _: crate::code_sandbox::wasmtime_boundary::bindings::ClaimInput,
    ) -> std::result::Result<crate::code_sandbox::wasmtime_boundary::bindings::ClaimOutput, String>
    {
        Err("unlinked capability".into())
    }
    fn memory_supersede_claim(
        &mut self,
        _: crate::code_sandbox::wasmtime_boundary::bindings::SupersedeInput,
    ) -> std::result::Result<crate::code_sandbox::wasmtime_boundary::bindings::ClaimOutput, String>
    {
        Err("unlinked capability".into())
    }
    fn memory_put_edge(
        &mut self,
        _: crate::code_sandbox::wasmtime_boundary::bindings::EdgeInput,
    ) -> std::result::Result<crate::code_sandbox::wasmtime_boundary::bindings::EdgeOutput, String>
    {
        Err("unlinked capability".into())
    }
    fn report_blocked(
        &mut self,
        _: String,
        _: String,
    ) -> std::result::Result<crate::code_sandbox::wasmtime_boundary::bindings::BlockedOutput, String>
    {
        Err("unlinked capability".into())
    }
    fn ask(
        &mut self,
        _: crate::code_sandbox::wasmtime_boundary::bindings::PromptInput,
    ) -> std::result::Result<crate::code_sandbox::wasmtime_boundary::bindings::WaitOutput, String>
    {
        Err("unlinked capability".into())
    }
    fn speak(
        &mut self,
        _: crate::code_sandbox::wasmtime_boundary::bindings::TextInput,
    ) -> std::result::Result<crate::code_sandbox::wasmtime_boundary::bindings::SpeechOutput, String>
    {
        Err("unlinked capability".into())
    }
    fn think(
        &mut self,
        _: crate::code_sandbox::wasmtime_boundary::bindings::TextInput,
    ) -> std::result::Result<crate::code_sandbox::wasmtime_boundary::bindings::SpeechOutput, String>
    {
        Err("unlinked capability".into())
    }
    fn express(
        &mut self,
        _: crate::code_sandbox::wasmtime_boundary::bindings::TextInput,
    ) -> std::result::Result<crate::code_sandbox::wasmtime_boundary::bindings::SpeechOutput, String>
    {
        Err("unlinked capability".into())
    }
}

#[test]
fn quickjs_concurrent_handles_do_not_interrupt_each_other() {
    use std::sync::mpsc;
    struct PausedHost {
        ready: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }
    impl JsCodeModeHost for PausedHost {
        fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
            assert!(matches!(call, SelfCall::MemorySearch(_)));
            self.ready.send(()).unwrap();
            self.release
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            Ok(SelfDispatchResponse {
                outcome: SelfDispatchOutcome::MemorySearch(
                    crate::code_run::SelfMemorySearchResult {
                        query: "hold".into(),
                        results: vec![],
                    },
                ),
                budget: None,
            })
        }
    }
    let (bytes, hash) = artifact("first-party");
    let factory =
        QuickJsRuntimeFactory::from_component(&bytes, hash, ComponentBudget::default()).unwrap();
    let mut left = factory.runtime().unwrap();
    let mut right = factory.runtime().unwrap();
    let (ready, received) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        right.run_step(JsCodeModeStep {
        run_id: EntityId::from_bytes([2;16]).unwrap(), seq: 0,
        script: "self.memory.search({query:'hold'}); let n=0; for(let i=0;i<20000;i++)n+=i; finish(String(n));",
        boundary: SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer),
        determinism: CodeRunDeterminism::new(1_700_000_000_000, [9;32]),
    }, &mut PausedHost { ready, release: released })
    });
    received
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    let completed = run(&mut left, "finish('short');", &mut Host::default());
    release.send(()).unwrap();
    assert_eq!(completed.unwrap().observation, "short");
    assert_eq!(worker.join().unwrap().unwrap().observation, "199990000");
}
