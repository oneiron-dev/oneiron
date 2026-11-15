//! Two host queue-check helpers sharing one scratch take turns on it.
//!
//! The host backend materializes every check under one scratch, so one
//! helper's cleanup used to remove the other's tree while its commands
//! ran. Each helper now claims a host-wide lock beside the scratch before
//! it cleans up and holds it until its run is done. This drives two copies
//! of `guest/checker/checker.py` at once, the second starting while the
//! first sleeps: the first one's later command must still see the file
//! its first command left, and its run must stay green. The pinned tree
//! is empty: file materialization is broken on this main for reasons
//! outside this row, so the race shows through files the commands leave.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-container --all-features --test
//! queue_check_host_scratch_shared`.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// One running helper: its child, its input held open (closing it ends
/// the helper), and its output.
struct Helper {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

/// What one helper reported: each phase command's exit status, and
/// whether the phase went red.
struct HelperRun {
    statuses: Vec<Option<i64>>,
    red: bool,
}

impl Helper {
    /// Starts the helper over `header` with an empty pinned tree.
    fn spawn(header: &Value) -> Self {
        let checker =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("guest/checker/checker.py");
        assert!(checker.is_file(), "the checker helper ships beside this crate");
        let mut child = Command::new("python3")
            .arg(&checker)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // A traceback goes to the test's own stderr, never the protocol.
            .stderr(Stdio::inherit())
            .spawn()
            .expect("python3 runs the checker helper");
        let stdin = child.stdin.take().expect("a helper has its input");
        let stdout = child.stdout.take().expect("a helper has its output");
        let mut helper = Self {
            child,
            stdin,
            stdout,
        };
        helper.send(&frame(
            b'H',
            &serde_json::to_vec(header).expect("a header encodes"),
        ));
        helper.send(&frame(b'E', &[]));
        helper
    }

    fn send(&mut self, bytes: &[u8]) {
        self.stdin.write_all(bytes).expect("a helper takes its input");
        self.stdin.flush().expect("a helper takes its input");
    }

    fn read_frame(&mut self) -> (u8, Vec<u8>) {
        let mut length = [0_u8; 4];
        self.stdout
            .read_exact(&mut length)
            .expect("a helper answers every run");
        let length = u32::from_be_bytes(length) as usize;
        assert!(length >= 1, "a check frame carries its kind");
        let mut kind = [0_u8; 1];
        self.stdout
            .read_exact(&mut kind)
            .expect("a helper answers every run");
        let mut payload = vec![0_u8; length - 1];
        self.stdout
            .read_exact(&mut payload)
            .expect("a helper answers every run");
        (kind[0], payload)
    }

    /// Reads the run to its done frame, then reaps the helper.
    fn run(&mut self) -> HelperRun {
        let mut statuses = Vec::new();
        let mut red = false;
        loop {
            let (kind, payload) = self.read_frame();
            match kind {
                b'R' => {
                    let result: Value =
                        serde_json::from_slice(&payload).expect("a helper sends JSON results");
                    statuses.push(result["status"].as_i64());
                    let (out_kind, _) = self.read_frame();
                    assert_eq!(out_kind, b'O', "stdout follows its result");
                    let (err_kind, _) = self.read_frame();
                    assert_eq!(err_kind, b'X', "stderr follows its stdout");
                }
                b'I' => {
                    let digests: Value =
                        serde_json::from_slice(&payload).expect("a helper sends JSON digests");
                    assert!(
                        digests["before"].is_string() && digests["after"].is_string(),
                        "input digests name their start and end"
                    );
                }
                b'D' => {
                    let done: Value =
                        serde_json::from_slice(&payload).expect("a helper sends a JSON done");
                    red = done["red"].as_bool().expect("done names its color");
                    break;
                }
                other => panic!("a helper sends no frame {other}"),
            }
        }
        self.reap();
        HelperRun { statuses, red }
    }

    fn reap(&mut self) {
        // The helper exits on its own after its done frame; a stuck one
        // fails the test instead of hanging it.
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.child.try_wait().expect("a helper reaps").is_none() {
            assert!(
                Instant::now() < deadline,
                "a helper exits after its done frame"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// One frame: its length over the kind byte and payload, then both.
fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.extend_from_slice(
        &u32::try_from(payload.len() + 1)
            .expect("a test frame fits")
            .to_be_bytes(),
    );
    out.push(kind);
    out.extend_from_slice(payload);
    out
}

/// Waits until `path` reads back as `want`: the first helper is inside
/// its slow command then, so only then does the second one start.
fn wait_for_content(path: &Path, want: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if std::fs::read_to_string(path).is_ok_and(|text| text == want) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the first helper runs its first command"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn two_helpers_sharing_one_scratch_take_turns() {
    let dir = tempfile::tempdir().expect("a scratch parent");
    let scratch = dir.path().join("queue-check");
    let scratch_name = scratch.to_str().expect("a scratch path").to_owned();
    let marker = scratch.join("src").join("marker.txt");
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let header_a = json!({
        "version": 1,
        "scratch": scratch_name.clone(),
        "commit": commit,
        "commands": [
            {"argv": ["/bin/sh", "-c", "/usr/bin/printf '%s' A-marker > marker.txt"],
             "env": {}, "declared_outputs": []},
            {"argv": ["/bin/sleep", "6"], "env": {}, "declared_outputs": []},
            {"argv": ["/bin/sh", "-c", "test \"$(/bin/cat marker.txt)\" = A-marker"],
             "env": {}, "declared_outputs": []},
        ],
        "contract_outputs": [],
    });
    let header_b = json!({
        "version": 1,
        "scratch": scratch_name,
        "commit": commit,
        "commands": [
            {"argv": ["/usr/bin/true"], "env": {}, "declared_outputs": []},
        ],
        "contract_outputs": [],
    });

    let mut first = Helper::spawn(&header_a);
    wait_for_content(&marker, "A-marker");
    let mut second = Helper::spawn(&header_b);
    let first_run = first.run();
    let second_run = second.run();

    assert_eq!(
        second_run.statuses,
        [Some(0)],
        "the later helper still runs its own check"
    );
    assert_eq!(
        first_run.statuses,
        [Some(0), Some(0), Some(0)],
        "the first helper's later command still sees the file its first command left"
    );
    assert!(!first_run.red, "the first helper's run stays green");
}
