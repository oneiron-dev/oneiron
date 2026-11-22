//! A run on a vendor's sandbox (L8-43, VENDOR-BOUNDARY = A): the real QuickJS
//! foreign component runs one exchange as a transcript. The host's opening is
//! a file, the guest's frames land in another, and every receipt wait is
//! answered in the guest. The transcript is what a live run would send, with
//! no receipt in it, and the staged base files are left as they were.
//!
//! `cargo test --locked -p oneiron-guest --test batch_transcript`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::{Cursor, Read, Write};

use oneiron_sandbox_contract::GUEST_PROTOCOL_VERSION;
use serde_json::{Value, json};

fn put(channel: &mut impl Write, value: Value) {
    let bytes = serde_json::to_vec(&value).expect("encode host frame");
    channel
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .expect("frame header");
    channel.write_all(&bytes).expect("frame bytes");
}

fn frames(bytes: Vec<u8>) -> Vec<Value> {
    let len = bytes.len() as u64;
    let mut cursor = Cursor::new(bytes);
    let mut out = Vec::new();
    while cursor.position() < len {
        let mut header = [0; 4];
        cursor.read_exact(&mut header).expect("guest header");
        let mut body = vec![0; u32::from_be_bytes(header) as usize];
        cursor.read_exact(&mut body).expect("guest bytes");
        out.push(serde_json::from_slice(&body).expect("guest JSON"));
    }
    out
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
fn batch_run_writes_the_live_transcript_without_receipts() {
    let temp = tempfile::tempdir().expect("tempdir");
    // The workspace walk refuses a symlink ancestor (macOS: /var is one).
    let root = temp.path().canonicalize().expect("real temp path");
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let host_frames = root.join("host-frames");
    let guest_frames = root.join("guest-frames");

    let component = real_foreign_component();
    let mut opening = Vec::new();
    put(
        &mut opening,
        json!({"type":"start", "version":GUEST_PROTOCOL_VERSION, "vm_id":"vendor-batch-1",
            "tier":"foreign", "pids":2, "component_bytes":component.len(),
            "source":"propose.delete('/mnt/workspace/removed'); propose.rename('/mnt/workspace/moved', '/mnt/workspace/destination'); finish('ok');"}),
    );
    for (index, bytes) in component.chunks(256 * 1024).enumerate() {
        put(
            &mut opening,
            json!({"type":"component", "offset":index * 256 * 1024, "bytes":bytes}),
        );
    }
    for (path, bytes) in [
        ("/mnt/workspace/removed", &b"old"[..]),
        ("/mnt/workspace/moved", &b"identity"[..]),
    ] {
        put(
            &mut opening,
            json!({"type":"file_open", "path":path, "len":bytes.len()}),
        );
        put(&mut opening, json!({"type":"file_chunk", "bytes":bytes}));
        put(&mut opening, json!({"type":"file_close"}));
    }
    put(&mut opening, json!({"type":"ready"}));
    fs::write(&host_frames, opening).expect("host frames");

    oneiron_guest::serve_batch(&host_frames, &guest_frames, &workspace).expect("batch run");

    let sent = frames(fs::read(&guest_frames).expect("guest frames"));
    assert_eq!(
        sent.first(),
        Some(&json!({"type":"hello", "version":GUEST_PROTOCOL_VERSION}))
    );
    assert!(
        sent.iter().all(|frame| frame["type"] != "receipt"),
        "a transcript holds the guest's frames only: {sent:?}"
    );
    let effects: Vec<&Value> = sent
        .iter()
        .filter(|frame| {
            !matches!(
                frame["type"].as_str(),
                Some("hello" | "output_text" | "output_bytes" | "store_bytes")
            )
        })
        .collect();
    assert_eq!(effects.len(), 4, "{effects:?}");
    assert_eq!(
        effects[0],
        &json!({"type":"delete", "path":"/mnt/workspace/removed"})
    );
    assert_eq!(
        effects[1],
        &json!({"type":"rename", "from":"/mnt/workspace/moved", "to":"/mnt/workspace/destination"})
    );
    assert_eq!(effects[2]["type"], "step_result");
    assert_eq!(effects[3], &json!({"type":"finish", "status":0}));

    assert_eq!(fs::read(workspace.join("removed")).expect("seeded"), b"old");
    assert_eq!(
        fs::read(workspace.join("moved")).expect("seeded"),
        b"identity"
    );
    assert!(!workspace.join("destination").exists());

    // The guest never replaces a transcript.
    assert!(oneiron_guest::serve_batch(&host_frames, &guest_frames, &workspace).is_err());
}
