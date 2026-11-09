use super::*;
use crate::{
    filesystem::Workspace,
    protocol::{MAX_COMPONENT, MAX_FILE, MAX_FRAME, MAX_SOURCE, Session, Snapshot},
};
use oneiron_sandbox_contract::GUEST_PROTOCOL_VERSION;
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
    json!({"type":"start", "version":GUEST_PROTOCOL_VERSION, "vm_id":"localtest-1", "tier":"foreign",
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
fn typed_fixture_refuses_secret_bearing_receipts_and_denied_credentials() {
    for receipt in [
        json!({"type":"receipt", "accepted":true, "secret":"host-only"}),
        json!({"type":"receipt", "accepted":false}),
    ] {
        let (_temp, root) = scratch();
        let mut bytes = Vec::new();
        input(&mut bytes, &conformance_component().expect("fixture"), "");
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
        conformance::WAT.replace("\"credential-call\"", "\"verb-call\""),
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
        let (_temp, root) = scratch();
        let workspace = Workspace::open(&root).expect("workspace");
        assert!(Session::new(transport).receive(&workspace).is_err());
    }
}

#[test]
fn source_order_duplicates_paths_and_budgets_fail_closed() {
    let component = json!({"type":"component", "offset":0, "bytes":[0]});
    // A source file streams as file_open, its chunks, then file_close (#5006).
    let file_frames = |path: &str, bytes: Vec<u8>| {
        let mut frames = vec![json!({"type":"file_open", "path":path, "len":bytes.len()})];
        if !bytes.is_empty() {
            frames.push(json!({"type":"file_chunk", "bytes":bytes}));
        }
        frames.push(json!({"type":"file_close"}));
        frames
    };
    let file = file_frames("/mnt/workspace/file", vec![1]);
    let cases = vec![
        vec![json!({"type":"ready"})],
        file.clone(),
        vec![json!({"type":"component", "offset":1, "bytes":[0]})],
        vec![json!({"type":"component", "offset":0, "bytes":[]})],
        vec![component.clone(), component.clone()],
        [vec![component.clone()], file.clone(), file].concat(),
        [
            vec![component.clone()],
            file_frames("/mnt/workspace/../escape", vec![]),
        ]
        .concat(),
        [
            vec![component.clone()],
            file_frames("/mnt/uploads/file", vec![]),
        ]
        .concat(),
        [
            vec![component],
            file_frames("/mnt/workspace/file", vec![0; MAX_FILE + 1]),
        ]
        .concat(),
    ];
    for frames in cases {
        let mut bytes = Vec::new();
        put(&mut bytes, start(1));
        for frame in frames {
            put(&mut bytes, frame);
        }
        put(&mut bytes, json!({"type":"ready"}));
        let (transport, _) = channel(bytes);
        let (_temp, root) = scratch();
        let workspace = Workspace::open(&root).expect("workspace");
        assert!(Session::new(transport).receive(&workspace).is_err());
    }
}

#[test]
fn descriptor_workspace_refuses_symlinks_hardlinks_and_special_files() {
    let (_temp, root) = scratch();
    let (_outside, outside) = scratch();
    fs::write(outside.join("secret"), b"unchanged").expect("outside fixture");
    symlink(&outside, root.join("escape")).expect("symlink fixture");
    let workspace = Workspace::open(&root).expect("workspace");
    assert!(workspace.read("/mnt/workspace/escape/secret").is_err());
    // A write lands only by create_seed since #5006 (16349c2258d): it cannot
    // follow the planted symlink out of the workspace either.
    assert!(workspace.create_seed("/mnt/workspace/escape/secret").is_err());
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
    // Seeding streams one file at a time since #5006 (16349c2258d): the file
    // `a` lands, and the conflicting `a/b` is refused at the descriptor walk
    // and writes nothing.
    drop(workspace.create_seed("/mnt/workspace/a").expect("the first file"));
    assert!(workspace.create_seed("/mnt/workspace/a/b").is_err());
    assert_eq!(
        workspace.snapshot().expect("the first file only"),
        Snapshot::from([("/mnt/workspace/a".to_owned(), 0)])
    );
}

fn real_foreign_component() -> Vec<u8> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/code-run-quickjs/artifacts");
    let manifest: Value =
        serde_json::from_slice(&fs::read(dir.join("manifest.json")).expect("pinned manifest"))
            .expect("manifest JSON");
    let name = manifest["artifacts"]["foreign"]["file"]
        .as_str()
        .expect("foreign component");
    fs::read(dir.join(name)).expect("pinned foreign component")
}

#[test]
fn real_quickjs_guest_sends_delete_and_rename_then_preserves_seeded_base() {
    let (_temp, root) = scratch();
    let (mut host, guest) = UnixStream::pair().expect("socketpair");
    host.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("deadline");
    let path = root.clone();
    let worker = std::thread::spawn(move || serve_localtest(guest, &path));
    assert_eq!(get(&mut host), json!({"type":"hello", "version":1}));
    let component = real_foreign_component();
    let mut start = start(component.len());
    start["source"] = "propose.delete('/mnt/workspace/removed'); propose.rename('/mnt/workspace/moved', '/mnt/workspace/destination'); finish('ok');".into();
    put(&mut host, start);
    for (index, bytes) in component.chunks(256 * 1024).enumerate() {
        put(
            &mut host,
            json!({"type":"component", "offset":index * 256 * 1024, "bytes":bytes}),
        );
    }
    put(
        &mut host,
        json!({"type":"file", "path":"/mnt/workspace/removed", "bytes":b"old"}),
    );
    put(
        &mut host,
        json!({"type":"file", "path":"/mnt/workspace/moved", "bytes":b"identity"}),
    );
    put(&mut host, json!({"type":"ready"}));
    assert_eq!(
        get(&mut host),
        json!({"type":"delete", "path":"/mnt/workspace/removed"})
    );
    put(&mut host, json!({"type":"receipt", "accepted":true}));
    assert_eq!(
        get(&mut host),
        json!({"type":"rename", "from":"/mnt/workspace/moved", "to":"/mnt/workspace/destination"})
    );
    put(&mut host, json!({"type":"receipt", "accepted":true}));
    assert_eq!(get(&mut host), json!({"type":"finish", "status":0}));
    worker.join().expect("guest thread").expect("guest success");
    assert_eq!(fs::read(root.join("removed")).expect("seeded file"), b"old");
    assert_eq!(
        fs::read(root.join("moved")).expect("seeded file"),
        b"identity"
    );
    assert!(!root.join("destination").exists());
}

#[test]
fn real_quickjs_guest_invalid_rename_finishes_error_without_effect() {
    let (_temp, root) = scratch();
    let (mut host, guest) = UnixStream::pair().expect("socketpair");
    host.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("deadline");
    let path = root.clone();
    let worker = std::thread::spawn(move || serve_localtest(guest, &path));
    assert_eq!(get(&mut host), json!({"type":"hello", "version":1}));
    let component = real_foreign_component();
    let mut start = start(component.len());
    start["source"] =
        "propose.rename('/mnt/workspace/old', '/mnt/workspace/old/child'); finish('no');".into();
    put(&mut host, start);
    for (index, bytes) in component.chunks(256 * 1024).enumerate() {
        put(
            &mut host,
            json!({"type":"component", "offset":index * 256 * 1024, "bytes":bytes}),
        );
    }
    put(
        &mut host,
        json!({"type":"file", "path":"/mnt/workspace/old", "bytes":b"old"}),
    );
    put(&mut host, json!({"type":"ready"}));
    assert_eq!(get(&mut host), json!({"type":"finish", "status":1}));
    assert!(worker.join().expect("guest thread").is_err());
    assert_eq!(fs::read(root.join("old")).expect("seeded file"), b"old");
}
