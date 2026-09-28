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
fn full_boundary_source(target: usize) -> Result<crate::skill_hub::pack_catalog::PackSource> {
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
    let empty = r#"{"inbound":[],"verbs":[],"events":[{"event_id":"e","connector":"email","event_kind":"arrived","predicate":"email.message","payload":{"pad":""}}]}"#;
    assert!(output_len >= empty.len());
    let json = format!(
        r#"{{"inbound":[],"verbs":[],"events":[{{"event_id":"e","connector":"email","event_kind":"arrived","predicate":"email.message","payload":{{"pad":"{}"}}}}]}}"#,
        "x".repeat(output_len - empty.len())
    );
    assert_eq!(json.len(), output_len);
    let wat_bytes = json.replace('"', "\\22");
    let wat = include_str!("../../../../../oneiron-guest/src/conformance.wat")
        .replace("(data (i32.const 4192) \"typed-component-conformance\\0a\")",
            &format!("(data (i32.const 1500000) \"{wat_bytes}\")"))
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
            &format!("      (i32.store (i32.const 2064) (i32.const 1500000))\n      (i32.store (i32.const 2068) (i32.const {output_len}))"))
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
    let source = full_boundary_source(oneiron_sandbox_contract::MAX_WORKSPACE_BYTES - 64 * 1024)?;
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
    // Give the one-byte-over result actual workspace headroom. The guest and
    // host transport must accept the edit; the PACK output contract must then
    // refuse it before any durable admission.
    let spare_source =
        full_boundary_source(oneiron_sandbox_contract::MAX_WORKSPACE_BYTES - 64 * 1024 - 1)?;
    let oversized_plan = ScriptExecutionPlan::from_source(&spare_source, &recipe)?;
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
            let (exit, writes) = outcome?;
            assert_eq!(exit.status, 0, "spare workspace admits the guest edit");
            assert!(
                guest_outcome.is_ok(),
                "guest accepts the merged tree: {guest_outcome:?}"
            );
            assert_eq!(writes.len(), 1);
            assert!(
                active.output_bytes(&writes[0]).is_err(),
                "the pack output contract must refuse 64 KiB + 1 before intake"
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
            let typed = crate::skill_hub::pack_catalog::ScriptOutput::decode(&bytes)?;
            assert_eq!(typed.events[0].event_kind, "arrived");
            assert_eq!(typed.events[0].connector, "email");
        }
        assert!(
            !base.join("adapter-output.json").exists(),
            "guest proposals cannot mutate source"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn guest_snapshot_result(files: &[crate::skill_hub::HubFile], program: &str) -> bool {
    use std::{
        io::{Cursor, Read, Write},
        sync::{Arc, Mutex},
    };
    struct Channel {
        input: Cursor<Vec<u8>>,
        output: Arc<Mutex<Vec<u8>>>,
    }
    impl Read for Channel {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(bytes)
        }
    }
    impl Write for Channel {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.output
                .lock()
                .expect("fixture output")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn send(frames: &mut Vec<u8>, value: Value) {
        let bytes = serde_json::to_vec(&value).expect("fixture frame");
        frames.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        frames.extend_from_slice(&bytes);
    }
    let component = boundary_component(256);
    let mut frames = Vec::new();
    send(
        &mut frames,
        json!({"type":"start","version":1,"vm_id":"shape-matrix",
        "tier":"foreign","pids":2,"component_bytes":component.len(),"source":program}),
    );
    for (index, bytes) in component.chunks(256 * 1024).enumerate() {
        send(
            &mut frames,
            json!({"type":"component","offset":index * 256 * 1024,"bytes":bytes}),
        );
    }
    for file in files {
        send(
            &mut frames,
            json!({"type":"file","path":format!("/mnt/workspace/{}", file.path),
            "bytes":file.content}),
        );
    }
    send(&mut frames, json!({"type":"ready"}));
    send(&mut frames, json!({"type":"receipt","accepted":true}));
    let channel = Channel {
        input: Cursor::new(frames),
        output: Arc::new(Mutex::new(Vec::new())),
    };
    let root = tempfile::tempdir().expect("guest workspace");
    oneiron_guest::serve_localtest(channel, &root.path().canonicalize().unwrap()).is_ok()
}

#[cfg(target_os = "linux")]
#[test]
fn qualification_and_guest_agree_on_path_file_and_program_boundaries() -> Result<()> {
    use crate::skill_hub::{
        HubFile,
        pack_catalog::{PackAdapter, PackRuntimeRecipe, PackSource, ScriptExecutionPlan},
    };
    let base = full_boundary_source(1024 * 1024)?;
    let recipe = PackRuntimeRecipe {
        adapter: PackAdapter::Script("scripts/adapter.js".into()),
        runtime_id: crate::code_sandbox::SANDBOX_JS_COMPONENT_NAME.into(),
        runtime_hash: blake3::hash(&boundary_component(256)).to_hex().to_string(),
    };
    let base_plan = ScriptExecutionPlan::from_source(&base, &recipe)?;
    let mut grants = BTreeMap::new();
    grants.insert(
        "email".into(),
        json!({"handle":"pack-demo","scheme":"https","host":"api.example.com"}),
    );
    let program = base_plan.assemble_program(&grants)?;
    for (relative, len, accepted) in [
        (format!("knowledge/{}x", "a/".repeat(62)), 1, true), // 64 components
        (format!("knowledge/{}x", "a/".repeat(63)), 1, false), // 65 components
        (format!("knowledge/{}", "x".repeat(255)), 1, true),
        (format!("knowledge/{}", "x".repeat(256)), 1, false),
        (format!("knowledge/{}a", "é".repeat(127)), 1, true),
        (format!("knowledge/{}", "é".repeat(128)), 1, false),
        ("knowledge/size.txt".into(), 1024 * 1024, true),
        ("knowledge/size.txt".into(), 1024 * 1024 + 1, false),
    ] {
        let mut files = base.files().to_vec();
        files.push(HubFile::new(relative, vec![b'x'; len]));
        let candidate = PackSource::from_files(files)?;
        let qualified = ScriptExecutionPlan::from_source(&candidate, &recipe).is_ok();
        assert_eq!(qualified, accepted, "qualifier shape mismatch");
        assert_eq!(
            guest_snapshot_result(candidate.files(), &program),
            accepted,
            "guest disagrees with qualifier for {len}-byte file"
        );
    }
    // Program boundary: the same accepted source plus a host-authored prelude
    // reaches exactly 1 MiB, while one extra byte fails both plan and guest.
    let mut files = vec![
        HubFile::new(
            "PACK.md",
            include_bytes!("../../../../tests/fixtures/echo_pack/PACK.md").to_vec(),
        ),
        HubFile::new(
            "scripts/adapter.js",
            include_bytes!("../../../../tests/fixtures/echo_pack/scripts/adapter.js").to_vec(),
        ),
    ];
    let script = files
        .iter_mut()
        .find(|file| file.path == "scripts/adapter.js")
        .unwrap();
    script.content.resize(
        oneiron_sandbox_contract::MAX_PROGRAM_BYTES - 128 * 1024,
        b' ',
    );
    let script_len = script.content.len();
    let candidate = PackSource::from_files(files)?;
    let plan = ScriptExecutionPlan::from_source(&candidate, &recipe)?;
    let base_program = plan.assemble_program(&grants)?;
    let current_prelude = base_program.len() - script_len;
    let remaining = 128 * 1024 - current_prelude;
    // The added JSON key consumes a small fixed overhead; grow its string
    // until the actual encoded prelude reaches the exact reservation.
    grants.insert("padding".into(), Value::String(String::new()));
    let added_overhead = plan.assemble_program(&grants)?.len() - base_program.len();
    grants.insert(
        "padding".into(),
        Value::String("x".repeat(remaining - added_overhead)),
    );
    let exact = plan.assemble_program(&grants)?;
    assert_eq!(exact.len(), oneiron_sandbox_contract::MAX_PROGRAM_BYTES);
    assert!(guest_snapshot_result(candidate.files(), &exact));
    grants.insert(
        "padding".into(),
        Value::String("x".repeat(remaining - added_overhead + 1)),
    );
    assert!(plan.assemble_program(&grants).is_err());
    assert!(!guest_snapshot_result(
        candidate.files(),
        &format!("{exact}x")
    ));
    Ok(())
}

#[test]
fn socket_protocol_delete_and_rename_are_typed_and_do_not_mutate_base() -> Result<()> {
    let dir = tempfile::tempdir().expect("fixture");
    let base_root = dir.path().join("base");
    std::fs::create_dir(&base_root).expect("fixture");
    std::fs::write(base_root.join("removed"), b"old").expect("fixture");
    std::fs::write(base_root.join("moved"), b"identity").expect("fixture");
    let vm = MicroVmHandle::new(
        "protocol-rename",
        crate::code_sandbox::SandboxGuestTier::Foreign,
        &base_root,
        dir.path().join("upper"),
        dir.path().join("egress.sock"),
    )?;
    let base = super::super::snapshot::files(&base_root)?;
    let resolver = Arc::new(Resolver {
        calls: Mutex::new(vec![]),
    });
    let mut proxy = CredentialEgressProxy::new(CredentialAllowlist::new(), resolver);
    proxy.arm();
    let (host, mut guest) = UnixStream::pair().expect("fixture");
    let (exit, proposals) = std::thread::scope(|scope| {
        scope.spawn(move || {
            send(&mut guest, json!({"type":"delete", "path":"/mnt/workspace/removed"}));
            assert_eq!(receive(&mut guest), json!({"type":"receipt","accepted":true}));
            send(&mut guest, json!({"type":"rename", "from":"/mnt/workspace/moved", "to":"/mnt/workspace/destination"}));
            assert_eq!(receive(&mut guest), json!({"type":"receipt","accepted":true}));
            send(&mut guest, json!({"type":"finish","status":0}));
        });
        receive_proposals(
            host,
            &vm,
            &base,
            Instant::now() + Duration::from_secs(3),
            &proxy,
            None,
        )
    })?;
    assert!(exit.overlay_dirty);
    assert!(proposals.iter().any(|proposal| matches!(proposal,
        SandboxProposalWrite::FileDelete(delete) if delete.path.as_str() == "/mnt/workspace/removed")));
    assert!(proposals.iter().any(|proposal| matches!(proposal,
        SandboxProposalWrite::FileRename(rename) if rename.from.as_str() == "/mnt/workspace/moved"
            && rename.to.as_str() == "/mnt/workspace/destination")));
    assert_eq!(
        std::fs::read(base_root.join("removed")).expect("fixture"),
        b"old"
    );
    assert_eq!(
        std::fs::read(base_root.join("moved")).expect("fixture"),
        b"identity"
    );
    assert!(!base_root.join("destination").exists());
    Ok(())
}

#[test]
fn socket_protocol_rejects_delete_of_unknown_and_rename_over_existing_base() -> Result<()> {
    let dir = tempfile::tempdir().expect("fixture");
    let base_root = dir.path().join("base");
    std::fs::create_dir(&base_root).expect("fixture");
    std::fs::write(base_root.join("old"), b"existing").expect("fixture");
    let vm = MicroVmHandle::new(
        "protocol-error",
        crate::code_sandbox::SandboxGuestTier::Foreign,
        &base_root,
        dir.path().join("upper"),
        dir.path().join("egress.sock"),
    )?;
    let base = super::super::snapshot::files(&base_root)?;
    let resolver = Arc::new(Resolver {
        calls: Mutex::new(vec![]),
    });
    let mut proxy = CredentialEgressProxy::new(CredentialAllowlist::new(), resolver);
    proxy.arm();
    for frame in [
        json!({"type":"delete","path":"/mnt/workspace/missing"}),
        json!({"type":"rename","from":"/mnt/workspace/old","to":"/mnt/workspace/old"}),
    ] {
        let (host, mut guest) = UnixStream::pair().expect("fixture");
        send(&mut guest, frame);
        drop(guest);
        assert!(
            receive_proposals(
                host,
                &vm,
                &base,
                Instant::now() + Duration::from_secs(3),
                &proxy,
                None
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn socket_protocol_refuses_file_ancestors_existing_directories_and_cross_proposal_conflicts()
-> Result<()> {
    let dir = tempfile::tempdir().expect("fixture");
    let base_root = dir.path().join("base");
    std::fs::create_dir_all(base_root.join("directory")).expect("fixture");
    std::fs::create_dir_all(base_root.join("empty")).expect("fixture");
    for file in ["a", "b", "directory/child"] {
        std::fs::write(base_root.join(file), b"source").expect("fixture");
    }
    let vm = MicroVmHandle::new(
        "protocol-tree",
        crate::code_sandbox::SandboxGuestTier::Foreign,
        &base_root,
        dir.path().join("upper"),
        dir.path().join("egress.sock"),
    )?;
    let base = super::super::snapshot::files(&base_root)?;
    let resolver = Arc::new(Resolver {
        calls: Mutex::new(vec![]),
    });
    let mut proxy = CredentialEgressProxy::new(CredentialAllowlist::new(), resolver);
    proxy.arm();
    for frames in [
        vec![json!({"type":"rename","from":"/mnt/workspace/a","to":"/mnt/workspace/b/child"})],
        vec![json!({"type":"rename","from":"/mnt/workspace/a","to":"/mnt/workspace/directory"})],
        vec![json!({"type":"rename","from":"/mnt/workspace/a","to":"/mnt/workspace/empty"})],
        vec![json!({"type":"rename","from":"/mnt/workspace/a","to":"/mnt/workspace/b"})],
        vec![
            json!({"type":"rename","from":"/mnt/workspace/a","to":"/mnt/workspace/directory/child/new"}),
        ],
        vec![
            json!({"type":"write","path":"/mnt/workspace/destination/child","bytes":[1]}),
            json!({"type":"rename","from":"/mnt/workspace/a","to":"/mnt/workspace/destination"}),
        ],
        vec![
            json!({"type":"rename","from":"/mnt/workspace/a","to":"/mnt/workspace/destination"}),
            json!({"type":"write","path":"/mnt/workspace/destination/child","bytes":[1]}),
        ],
    ] {
        let (host, mut guest) = UnixStream::pair().expect("fixture");
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let count = frames.len();
                for (index, frame) in frames.into_iter().enumerate() {
                    send(&mut guest, frame);
                    if index + 1 < count {
                        assert_eq!(
                            receive(&mut guest),
                            json!({"type":"receipt","accepted":true})
                        );
                    }
                }
            });
            assert!(
                receive_proposals(
                    host,
                    &vm,
                    &base,
                    Instant::now() + Duration::from_secs(3),
                    &proxy,
                    None
                )
                .is_err(),
                "a structurally impossible tree must be refused"
            );
        });
    }
    assert_eq!(std::fs::read(base_root.join("a")).expect("base"), b"source");
    Ok(())
}
