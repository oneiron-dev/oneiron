use super::*;
use crate::code_sandbox::microvm::{
    CredentialAllowlist, CredentialDestination, CredentialResolver,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Resolver {
    calls: Mutex<Vec<String>>,
}
impl CredentialResolver for Resolver {
    fn resolve_for(
        &self,
        handle: &SandboxCredentialHandle,
        destination: &CredentialDestination,
    ) -> Result<Vec<u8>> {
        self.calls.lock().expect("test fixture").push(format!(
            "{}:{}",
            handle.as_str(),
            destination
        ));
        Ok(b"host-only-test-credential".to_vec())
    }
}
struct Transport {
    destinations: Mutex<Vec<String>>,
}
impl CredentialReadTransport for Transport {
    fn read(
        &self,
        destination: &CredentialDestination,
        operation: &crate::code_sandbox::SandboxCredentialOperation,
        _: &rmpv::Value,
        secret: &[u8],
    ) -> Result<()> {
        assert_eq!(secret, b"host-only-test-credential");
        assert_eq!(
            operation.effect(),
            crate::code_sandbox::SandboxCredentialEffect::ReadOnly
        );
        self.destinations
            .lock()
            .expect("test fixture")
            .push(destination.to_string());
        Ok(())
    }
}
fn send(stream: &mut UnixStream, frame: Value) {
    let bytes = frame.to_string().into_bytes();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .expect("test fixture");
    stream.write_all(&bytes).expect("test fixture");
}
fn receive(stream: &mut UnixStream) -> Value {
    let mut size = [0; 4];
    stream.read_exact(&mut size).expect("test fixture");
    let mut bytes = vec![0; u32::from_be_bytes(size) as usize];
    stream.read_exact(&mut bytes).expect("test fixture");
    assert!(!String::from_utf8_lossy(&bytes).contains("host-only-test-credential"));
    serde_json::from_slice(&bytes).expect("test fixture")
}

#[test]
fn socket_protocol_denies_off_list_before_resolution_and_returns_proposals_not_writes() -> Result<()>
{
    let dir = tempfile::tempdir().expect("test fixture");
    let base = dir.path().join("base");
    std::fs::create_dir(&base).expect("test fixture");
    std::fs::write(base.join("input.txt"), b"base").expect("test fixture");
    let vm = MicroVmHandle::new(
        "protocol-test",
        crate::code_sandbox::SandboxGuestTier::Foreign,
        &base,
        dir.path().join("upper"),
        dir.path().join("egress.sock"),
    )?;
    let resolver = Arc::new(Resolver {
        calls: Mutex::new(vec![]),
    });
    let mut allow = CredentialAllowlist::new();
    allow.allow(
        &SandboxCredentialHandle::new("handle")?,
        CredentialDestination::new("https", "example.com")?,
    );
    let mut proxy = CredentialEgressProxy::new(allow, resolver.clone());
    proxy.arm();
    let transport = Transport {
        destinations: Mutex::new(vec![]),
    };
    let (host, mut guest) = UnixStream::pair().expect("test fixture");
    guest
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("test fixture");
    let result = std::thread::scope(|scope| {
        scope.spawn(move || {
            send(&mut guest,json!({"type":"hello","version":1}));
            let start = receive(&mut guest);
            assert_eq!(start["type"], "start");
            assert_eq!(start["source"], "fixture source");
            loop { if receive(&mut guest)["type"]=="ready" {break;} }
            send(&mut guest,json!({"type":"credential_read","handle":"handle","operation":"metadata","scheme":"https","host":"evil.test"}));
            assert_eq!(receive(&mut guest),json!({"type":"receipt","accepted":false}));
            send(&mut guest,json!({"type":"credential_read","handle":"handle","operation":"metadata","scheme":"https","host":"api.example.com"}));
            assert_eq!(receive(&mut guest),json!({"type":"receipt","accepted":true}));
            send(&mut guest,json!({"type":"write","path":"/mnt/workspace/result.txt","bytes":[111,107]}));
            assert_eq!(receive(&mut guest),json!({"type":"receipt","accepted":true}));
            send(&mut guest,json!({"type":"write","path":"/mnt/workspace/adapter-output.json",
                "bytes": br#"{"inbound":[],"verbs":[],"events":[]}"#.to_vec()}));
            assert_eq!(receive(&mut guest),json!({"type":"receipt","accepted":true}));
            send(&mut guest,json!({"type":"finish","status":0}));
        });
        exchange(
            host,
            &vm,
            GuestProgram {
                component: b"bounded-component-input",
                source: "fixture source",
            },
            ExecutionBudget::new(3, 128, 32),
            Instant::now() + Duration::from_secs(3),
            &proxy,
            Some(&transport),
        )
    })?;
    assert_eq!(
        resolver.calls.lock().expect("test fixture").as_slice(),
        &["handle:https://api.example.com"]
    );
    assert_eq!(
        transport
            .destinations
            .lock()
            .expect("test fixture")
            .as_slice(),
        &["https://api.example.com"]
    );
    assert!(result.0.overlay_dirty);
    let [
        SandboxProposalWrite::FileEdit(adapter_output),
        SandboxProposalWrite::FileEdit(file),
    ] = result.1.as_slice()
    else {
        panic!("two lowered edit proposals")
    };
    let bytes = crate::skill_hub::pack_catalog::script_output_bytes(&result.1[0])?;
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).expect("typed output JSON"),
        json!({"inbound":[],"verbs":[],"events":[]})
    );
    assert_eq!(
        adapter_output.path.as_str(),
        "/mnt/workspace/adapter-output.json"
    );
    assert_eq!(file.path.as_str(), "/mnt/workspace/result.txt");
    assert_eq!(file.edit.replacement, "ok");
    assert_eq!(file.edit.start, 0);
    assert_eq!(file.edit.end, 0);
    assert_eq!(
        std::fs::read(base.join("input.txt")).expect("test fixture"),
        b"base"
    );
    assert!(!base.join("result.txt").exists());
    assert!(!base.join("adapter-output.json").exists());
    Ok(())
}

#[test]
fn oversized_frame_and_expired_deadline_fail_closed() {
    let (mut host, mut guest) = UnixStream::pair().expect("test fixture");
    guest
        .write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
        .expect("test fixture");
    assert!(read_frame(&mut host, Instant::now() + Duration::from_secs(1)).is_err());
    assert!(read_frame(&mut host, Instant::now()).is_err());
}

#[cfg(target_os = "linux")]
fn full_boundary_source() -> Result<crate::skill_hub::pack_catalog::PackSource> {
    use crate::skill_hub::{HubFile, pack_catalog::PackSource};
    const SCRIPT: &str = r#"
        const head = '{"inbound":[],"verbs":[],"events":[{"event_id":"e","connector":"email","event_kind":"arrived","predicate":"email.message","payload":"';
        const tail = '"}]}';
        const out = Array(65536).fill(120);
        for (let i = 0; i < head.length; i++) out[i] = head.charCodeAt(i);
        for (let i = 0; i < tail.length; i++) out[out.length - tail.length + i] = tail.charCodeAt(i);
        propose.file('/mnt/workspace/adapter-output.json', out);
        finish('ok');
    "#;
    let mut files = vec![
        HubFile::new(
            "PACK.md",
            include_bytes!("../../../../tests/fixtures/echo_pack/PACK.md").to_vec(),
        ),
        HubFile::new("scripts/adapter.js", SCRIPT.as_bytes().to_vec()),
        HubFile::new(
            "scripts/input.json",
            include_bytes!("../../../../tests/fixtures/echo_pack/scripts/input.json").to_vec(),
        ),
    ];
    let target = oneiron_sandbox_contract::MAX_WORKSPACE_BYTES - 64 * 1024;
    let mut left = target - files.iter().map(|f| f.content.len()).sum::<usize>();
    let mut index = 0;
    while left > 0 {
        let bytes = left.min(oneiron_sandbox_contract::MAX_FILE_BYTES);
        files.push(HubFile::new(
            format!("knowledge/part-{index}.txt"),
            vec![b'x'; bytes],
        ));
        left -= bytes;
        index += 1;
    }
    PackSource::from_files(files)
}

// A cheap typed Component Model fixture isolates the 64 KiB workspace law
// from QuickJS's fixed 100M interpreter fuel. The separate real QuickJS test
// executes the shared echo pack source. This component receives the plan's
// exact program through the actual host/guest transport but emits a fixed
// bounded JSON payload instead of interpreting JavaScript.
#[cfg(target_os = "linux")]
fn boundary_component(output_len: usize) -> Vec<u8> {
    let empty = r#"{"inbound":[],"verbs":[],"events":[{"event_kind":"arrived","pad":""}]}"#;
    assert!(output_len >= empty.len());
    let json = format!(
        r#"{{"inbound":[],"verbs":[],"events":[{{"event_kind":"arrived","pad":"{}"}}]}}"#,
        "x".repeat(output_len - empty.len())
    );
    assert_eq!(json.len(), output_len);
    let wat_bytes = json.replace('"', "\\22");
    let wat = include_str!("../../../../../oneiron-guest/src/conformance.wat")
        .replace("(data (i32.const 4192) \"typed-component-conformance\\0a\")",
            &format!("(data (i32.const 1000000) \"{wat_bytes}\")"))
        .replace("(data (i32.const 4128) \"/mnt/workspace/result.txt\")",
            "(data (i32.const 4128) \"/mnt/workspace/adapter-output.json\")")
        .replace("(i32.store (i32.const 2060) (i32.const 25))",
            "(i32.store (i32.const 2060) (i32.const 34))")
        .replace(r#"      (if (local.get $length)
        (then
          (i32.store (i32.const 2064) (local.get $source))
          (i32.store (i32.const 2068) (local.get $length)))
        (else
          (i32.store (i32.const 2064) (i32.const 4192))
          (i32.store (i32.const 2068) (i32.const 28))))"#,
            &format!("      (i32.store (i32.const 2064) (i32.const 1000000))\n      (i32.store (i32.const 2068) (i32.const {output_len}))"))
        .replace(r#"      (call $credential
        (i32.const 4256) (i32.const 8) (i32.const 4288) (i32.const 18)
        (i32.const 4320) (i32.const 43) (i32.const 1536))
      (if (i32.load (i32.const 1536)) (then unreachable))"#, "");
    wat::parse_str(wat).expect("valid typed boundary component")
}

/// A catalog-qualified maximum snapshot and its plan-produced program traverse
/// the actual host socket/lowering and unprivileged guest, not a mock budget.
#[cfg(target_os = "linux")]
#[test]
fn qualified_max_workspace_round_trips_full_reserved_output_and_refuses_one_extra_byte()
-> Result<()> {
    use crate::skill_hub::pack_catalog::{PackAdapter, PackRuntimeRecipe, ScriptExecutionPlan};
    let source = full_boundary_source()?;
    let recipe = PackRuntimeRecipe {
        adapter: PackAdapter::Script("scripts/adapter.js".into()),
        runtime_id: crate::code_sandbox::SANDBOX_JS_COMPONENT_NAME.into(),
        runtime_hash: blake3::hash(&boundary_component(64 * 1024))
            .to_hex()
            .to_string(),
    };
    let plan = ScriptExecutionPlan::from_source(&source, &recipe)?;
    let mut grants = BTreeMap::new();
    grants.insert(
        "email".into(),
        json!({"handle":"pack-demo", "scheme":"https", "host":"api.example.com"}),
    );
    let mut oversized_files = source.files().to_vec();
    let adapter = oversized_files
        .iter_mut()
        .find(|file| file.path == "scripts/adapter.js")
        .expect("adapter exists");
    adapter.content = String::from_utf8(adapter.content.clone())
        .expect("ASCII fixture")
        .replace("Array(65536).fill(120)", "Array(65537).fill(120)")
        .into_bytes();
    let oversized_source = crate::skill_hub::pack_catalog::PackSource::from_files(oversized_files)?;
    let oversized_plan = ScriptExecutionPlan::from_source(&oversized_source, &recipe)?;
    for overshoot in [false, true] {
        let active = if overshoot { &oversized_plan } else { &plan };
        let dir = tempfile::tempdir().expect("fixture root");
        let base = dir.path().join("base");
        let guest_root = dir.path().join("guest");
        std::fs::create_dir(&base)?;
        std::fs::create_dir(&guest_root)?;
        for file in active.files() {
            let target = base.join(&file.path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(target, &file.content)?;
        }
        let vm = MicroVmHandle::new(
            "max-boundary",
            crate::code_sandbox::SandboxGuestTier::Foreign,
            &base,
            dir.path().join("upper"),
            dir.path().join("egress.sock"),
        )?;
        let mut proxy = CredentialEgressProxy::new(
            CredentialAllowlist::new(),
            Arc::new(Resolver {
                calls: Mutex::new(Vec::new()),
            }),
        );
        proxy.arm();
        let (host, guest) = UnixStream::pair()?;
        let guest_root = guest_root.canonicalize()?;
        let worker = std::thread::spawn(move || oneiron_guest::serve_localtest(guest, &guest_root));
        let script = active.assemble_program(&grants)?;
        let outcome = exchange(
            host,
            &vm,
            GuestProgram {
                component: &boundary_component(if overshoot { 64 * 1024 + 1 } else { 64 * 1024 }),
                source: &script,
            },
            ExecutionBudget::new(150, 256, 64),
            Instant::now() + Duration::from_secs(150),
            &proxy,
            None,
        );
        let guest_outcome = worker.join().expect("guest worker");
        if overshoot {
            assert!(
                outcome.is_err(),
                "one output byte beyond reservation must refuse"
            );
            assert!(
                guest_outcome.is_err(),
                "guest refuses merged workspace before writing"
            );
        } else {
            assert!(
                outcome.is_ok(),
                "qualified host exchange: {outcome:?}; guest: {guest_outcome:?}"
            );
            let (exit, writes) = outcome?;
            assert_eq!(exit.status, 0);
            assert!(
                guest_outcome.is_ok(),
                "qualified snapshot must execute: {guest_outcome:?}"
            );
            assert_eq!(writes.len(), 1);
            let bytes = active.output_bytes(&writes[0])?;
            assert_eq!(bytes.len(), 64 * 1024);
            assert_eq!(
                serde_json::from_slice::<Value>(&bytes).expect("typed JSON")["events"][0]["event_kind"],
                "arrived"
            );
        }
        assert!(
            !base.join("adapter-output.json").exists(),
            "guest proposals cannot mutate source"
        );
    }
    Ok(())
}
