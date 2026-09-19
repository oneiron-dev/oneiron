use super::*;
use crate::{
    filesystem::Workspace,
    protocol::{MAX_COMPONENT, MAX_FILE, MAX_FRAME, MAX_REQUESTS, MAX_SOURCE, Session, Snapshot},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Cursor,
    os::unix::{fs::symlink, net::UnixStream},
    sync::{Arc, Mutex},
    time::Duration,
};

fn put(channel: &mut impl Write, value: Value) {
    let bytes = serde_json::to_vec(&value).expect("encode host fixture");
    channel
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .expect("frame header");
    channel.write_all(&bytes).expect("frame bytes");
}

fn get(channel: &mut impl Read) -> Value {
    let mut header = [0; 4];
    channel.read_exact(&mut header).expect("guest header");
    let len = u32::from_be_bytes(header) as usize;
    assert!(len > 0 && len <= MAX_FRAME);
    let mut bytes = vec![0; len];
    channel.read_exact(&mut bytes).expect("guest bytes");
    serde_json::from_slice(&bytes).expect("guest JSON")
}

fn start(length: usize) -> Value {
    json!({"type":"start", "version":1, "vm_id":"localtest-1", "tier":"foreign",
        "pids":2, "component_bytes":length, "source":""})
}

fn input(channel: &mut impl Write, component: &[u8], source: &str) {
    let mut first = start(component.len());
    first["source"] = source.into();
    put(channel, first);
    for (index, bytes) in component.chunks(256 * 1024).enumerate() {
        put(
            channel,
            json!({"type":"component", "offset":index * 256 * 1024, "bytes":bytes}),
        );
    }
    put(channel, json!({"type":"ready"}));
}

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
        self.output.lock().expect("output").extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn channel(bytes: Vec<u8>) -> (Channel, Arc<Mutex<Vec<u8>>>) {
    let output = Arc::new(Mutex::new(Vec::new()));
    (
        Channel {
            input: Cursor::new(bytes),
            output: output.clone(),
        },
        output,
    )
}

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().expect("scratch");
    let path = temp.path().canonicalize().expect("real scratch path");
    (temp, path)
}

#[test]
fn typed_component_over_unix_stream_returns_receipt_only_and_proposes_source_bytes() {
    let (_temp, root) = scratch();
    let (mut host, guest) = UnixStream::pair().expect("socketpair");
    host.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    guest
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    let path = root.clone();
    let worker = std::thread::spawn(move || serve_localtest(guest, &path));
    assert_eq!(get(&mut host), json!({"type":"hello", "version":1}));
    // Literal fixture bytes are echoed; this is explicitly not JS execution.
    input(
        &mut host,
        &conformance::component().expect("WAT encoding"),
        "typed source conduit",
    );
    assert_eq!(
        get(&mut host),
        json!({"type":"credential_read", "handle":"conformance-handle",
        "operation":"metadata", "scheme":"https", "host":"api.example.com"})
    );
    put(&mut host, json!({"type":"receipt", "accepted":true}));
    assert_eq!(
        get(&mut host),
        json!({"type":"write", "path":"/mnt/workspace/result.txt",
        "bytes":b"typed source conduit".to_vec()})
    );
    put(&mut host, json!({"type":"receipt", "accepted":true}));
    assert_eq!(get(&mut host), json!({"type":"finish", "status":0}));
    worker.join().expect("guest thread").expect("guest run");
    assert_eq!(
        fs::read(root.join("result.txt")).expect("proposal scratch"),
        b"typed source conduit"
    );
}

#[test]
fn typed_fixture_refuses_secret_bearing_receipts_and_denied_credentials() {
    for receipt in [
        json!({"type":"receipt", "accepted":true, "secret":"host-only"}),
        json!({"type":"receipt", "accepted":false}),
    ] {
        let (_temp, root) = scratch();
        let mut bytes = Vec::new();
        input(&mut bytes, &conformance::component().expect("fixture"), "");
        put(&mut bytes, receipt);
        let (transport, output) = channel(bytes);
        assert!(serve_localtest(transport, &root).is_err());
        let mut frames = Cursor::new(output.lock().expect("output").clone());
        assert_eq!(get(&mut frames)["type"], "hello");
        assert_eq!(get(&mut frames)["type"], "credential_read");
        assert_eq!(get(&mut frames), json!({"type":"finish", "status":1}));
        assert!(!root.join("result.txt").exists());
    }
}

#[test]
fn typed_fixture_refuses_first_party_import_and_unknown_credential_args() {
    for fixture in [
        conformance::WAT.replace("\"credential-call\"", "\"memory-put-claim\""),
        conformance::WAT.replace("\\22host\\22", "\\22body\\22"),
    ] {
        let (_temp, root) = scratch();
        let mut bytes = Vec::new();
        input(
            &mut bytes,
            &wat::parse_str(fixture).expect("fixture encoding"),
            "",
        );
        let (transport, output) = channel(bytes);
        assert!(serve_localtest(transport, &root).is_err());
        let mut frames = Cursor::new(output.lock().expect("output").clone());
        assert_eq!(get(&mut frames)["type"], "hello");
        assert_eq!(get(&mut frames), json!({"type":"finish", "status":1}));
        assert!(!root.join("result.txt").exists());
    }
}

#[test]
fn typed_component_claim_proposal_refuses_the_whole_step() {
    let fixture = conformance::WAT.replace(
        "(i32.store (i32.const 2048) (i32.const 0))",
        "(i32.store (i32.const 2048) (i32.const 1))",
    );
    let (_temp, root) = scratch();
    let mut bytes = Vec::new();
    input(
        &mut bytes,
        &wat::parse_str(fixture).expect("fixture encoding"),
        "",
    );
    put(&mut bytes, json!({"type":"receipt", "accepted":true}));
    let (transport, output) = channel(bytes);
    let result = serve_localtest(transport, &root);
    assert!(
        matches!(result, Err(Error::UnsupportedClaimCandidate)),
        "{result:?}"
    );
    let mut frames = Cursor::new(output.lock().expect("output").clone());
    assert_eq!(get(&mut frames)["type"], "hello");
    assert_eq!(get(&mut frames)["type"], "credential_read");
    assert_eq!(get(&mut frames), json!({"type":"finish", "status":1}));
    assert!(!root.join("result.txt").exists());
}

#[test]
fn start_refuses_authority_version_and_resource_escalation() {
    let mut cases = Vec::new();
    for (key, value) in [
        ("version", json!(2)),
        ("tier", json!("first_party_dreamer")),
        ("pids", json!(0)),
        ("pids", json!(4097)),
        ("component_bytes", json!(0)),
        ("component_bytes", json!(MAX_COMPONENT + 1)),
        ("source", json!("s".repeat(MAX_SOURCE + 1))),
        ("extra", json!(true)),
    ] {
        let mut frame = start(1);
        frame[key] = value;
        cases.push(frame);
    }
    for frame in cases {
        let mut bytes = Vec::new();
        put(&mut bytes, frame);
        let (transport, _) = channel(bytes);
        assert!(Session::new(transport).receive().is_err());
    }
}

#[test]
fn source_order_duplicates_paths_and_budgets_fail_closed() {
    let component = json!({"type":"component", "offset":0, "bytes":[0]});
    let file = json!({"type":"file", "path":"/mnt/workspace/file", "bytes":[1]});
    let cases = vec![
        vec![json!({"type":"ready"})],
        vec![file.clone()],
        vec![json!({"type":"component", "offset":1, "bytes":[0]})],
        vec![json!({"type":"component", "offset":0, "bytes":[]})],
        vec![component.clone(), component.clone()],
        vec![component.clone(), file.clone(), file],
        vec![
            component.clone(),
            json!({"type":"file", "path":"/mnt/workspace/../escape", "bytes":[]}),
        ],
        vec![
            component.clone(),
            json!({"type":"file", "path":"/mnt/uploads/file", "bytes":[]}),
        ],
        vec![
            component,
            json!({"type":"file", "path":"/mnt/workspace/file", "bytes":vec![0; MAX_FILE + 1]}),
        ],
    ];
    for frames in cases {
        let mut bytes = Vec::new();
        put(&mut bytes, start(1));
        for frame in frames {
            put(&mut bytes, frame);
        }
        put(&mut bytes, json!({"type":"ready"}));
        let (transport, _) = channel(bytes);
        assert!(Session::new(transport).receive().is_err());
    }
}

#[test]
fn frame_and_sequential_request_bounds_are_enforced() {
    for size in [0, MAX_FRAME + 1] {
        let (transport, _) = channel((size as u32).to_be_bytes().to_vec());
        assert!(Session::new(transport).receive().is_err());
    }
    let mut bytes = Vec::new();
    put(&mut bytes, start(MAX_REQUESTS));
    for offset in 0..MAX_REQUESTS {
        put(
            &mut bytes,
            json!({"type":"component", "offset":offset, "bytes":[0]}),
        );
    }
    put(&mut bytes, json!({"type":"ready"}));
    let (transport, _) = channel(bytes);
    assert!(Session::new(transport).receive().is_err());
}

#[test]
fn descriptor_workspace_refuses_symlinks_hardlinks_and_special_files() {
    let (_temp, root) = scratch();
    let (_outside, outside) = scratch();
    fs::write(outside.join("secret"), b"unchanged").expect("outside fixture");
    symlink(&outside, root.join("escape")).expect("symlink fixture");
    let workspace = Workspace::open(&root).expect("workspace");
    assert!(workspace.read("/mnt/workspace/escape/secret").is_err());
    let proposal = Snapshot::from([("/mnt/workspace/escape/secret".into(), b"changed".to_vec())]);
    assert!(workspace.apply(&proposal).is_err());
    assert!(workspace.snapshot().is_err());
    fs::remove_file(root.join("escape")).expect("remove symlink");
    fs::hard_link(outside.join("secret"), root.join("linked")).expect("hardlink fixture");
    assert!(workspace.read("/mnt/workspace/linked").is_err());
    assert!(workspace.snapshot().is_err());
    fs::remove_file(root.join("linked")).expect("remove hardlink");
    let fifo = std::ffi::CString::new(root.join("pipe").as_os_str().as_encoded_bytes())
        .expect("fifo path");
    // SAFETY: valid C string, creating a test-owned FIFO with no readers/writers.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(workspace.read("/mnt/workspace/pipe").is_err());
    assert!(workspace.snapshot().is_err());
    assert_eq!(
        fs::read(outside.join("secret")).expect("outside"),
        b"unchanged"
    );
}

#[test]
fn descriptor_walk_refuses_symlink_ancestors_and_conflicting_tree() {
    let (_temp, root) = scratch();
    fs::create_dir(root.join("real")).expect("real dir");
    symlink(root.join("real"), root.join("alias")).expect("alias");
    assert!(Workspace::open(&root.join("alias")).is_err());
    let workspace = Workspace::open(&root.join("real")).expect("workspace");
    let files = Snapshot::from([
        ("/mnt/workspace/a".into(), vec![]),
        ("/mnt/workspace/a/b".into(), vec![]),
    ]);
    assert!(workspace.seed(&files).is_err());
    assert!(workspace.snapshot().expect("empty").is_empty());
}

#[test]
fn repeated_snapshot_and_whole_file_replacement_preserve_other_files() {
    let (_temp, root) = scratch();
    let workspace = Workspace::open(&root).expect("workspace");
    let files = Snapshot::from([
        ("/mnt/workspace/nested/a".into(), b"before".to_vec()),
        ("/mnt/workspace/kept".into(), b"same".to_vec()),
    ]);
    workspace.seed(&files).expect("seed");
    assert_eq!(workspace.snapshot().expect("snapshot 1"), files);
    assert_eq!(workspace.snapshot().expect("snapshot 2"), files);
    workspace
        .apply(&Snapshot::from([(
            "/mnt/workspace/nested/a".into(),
            b"after".to_vec(),
        )]))
        .expect("apply");
    assert_eq!(
        workspace.read("/mnt/workspace/nested/a").expect("read"),
        b"after"
    );
    assert_eq!(
        workspace.read("/mnt/workspace/kept").expect("read"),
        b"same"
    );
}
