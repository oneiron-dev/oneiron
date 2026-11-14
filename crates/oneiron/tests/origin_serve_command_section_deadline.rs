//! Census L4-31, ARCH-0068 #ra1-push-spool-open: "deadline for a trickling
//! command section".
//!
//! A receive-pack takes the repository's coordinator, then reads its command
//! section (the ref updates up to the first flush) before the backend runs.
//! A byte resets only the idle limit, so a client that sent one byte every few
//! seconds held every other push to that repository for as long as it kept
//! sending. The whole section now has to arrive within the host's
//! `command_section` bound of its first read; past it the push is refused as
//! an idle stall and the coordinator is let go.
//!
//! The test serves a push whose command section trickles in one byte per
//! 100 ms (about 12 s whole) under a 1 s deadline, and, while it still
//! trickles, a second push to the same repository that waits up to 3 s for
//! the coordinator. The trickling push is refused near its deadline, and the
//! second push lands.
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! origin_serve_command_section_deadline`.
#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use oneiron::error::CodeError;
use oneiron::origin::smart_http::{
    self, DoorSeam, ExchangeBounds, ScanBounds, ServeReport, ServeRequest, ServeSink,
};
use oneiron::{EntityId, Vault, VaultConfig};

const REPO: &str = "demo";
const ZERO_OID: &str = "0000000000000000000000000000000000000000";
const TRICKLE_REF: &str = "refs/heads/trickle";
const PLAIN_REF: &str = "refs/heads/plain";

/// The command section deadline the test serves under.
const SECTION_DEADLINE: Duration = Duration::from_secs(1);
/// How long apart the trickling push sends the bytes of its command section.
const TRICKLE_PACE: Duration = Duration::from_millis(100);
/// When the second push starts, after the trickling one.
const SECOND_PUSH_AFTER: Duration = Duration::from_secs(2);
/// How long the second push waits for the coordinator.
const SECOND_PUSH_WAIT: Duration = Duration::from_secs(3);

fn git_command(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Owen")
        .env("GIT_AUTHOR_EMAIL", "owen@example.com")
        .env("GIT_COMMITTER_NAME", "Owen")
        .env("GIT_COMMITTER_EMAIL", "owen@example.com");
    command
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = git_command(dir, args)
        .stdin(Stdio::null())
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git prints UTF-8")
        .trim()
        .to_owned()
}

/// A commit of one file in a scratch repository, and the pack carrying it.
fn commit_and_pack(scratch: &Path) -> (String, Vec<u8>) {
    git(scratch, &["init", "--quiet", "--initial-branch=main"]);
    std::fs::write(scratch.join("notes.txt"), "plain notes\n").expect("write the file");
    git(scratch, &["add", "--", "notes.txt"]);
    git(scratch, &["commit", "--quiet", "-m", "notes"]);
    let commit = git(scratch, &["rev-parse", "--verify", "HEAD"]);
    let mut packing = git_command(scratch, &["pack-objects", "--revs", "--stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start pack-objects");
    packing
        .stdin
        .take()
        .expect("pack-objects stdin")
        .write_all(format!("{commit}\n").as_bytes())
        .expect("name the commit to pack");
    let pack = packing.wait_with_output().expect("pack-objects output");
    assert!(pack.status.success(), "pack-objects failed");
    (commit, pack.stdout)
}

/// The command section creating `name` at `commit`, up to and with its flush.
fn command_section(name: &str, commit: &str) -> Vec<u8> {
    let command = format!("{ZERO_OID} {commit} {name}\0report-status\n");
    format!("{:04x}{command}0000", command.len() + 4).into_bytes()
}

fn receive_pack_request(owner: EntityId, body_len: usize) -> ServeRequest {
    ServeRequest {
        method: "POST".to_owned(),
        path_info: format!("/{REPO}.git/git-receive-pack"),
        query_string: String::new(),
        content_type: Some("application/x-git-receive-pack-request".to_owned()),
        content_length: Some(u64::try_from(body_len).expect("body length")),
        content_encoding: None,
        git_protocol: None,
        // An in-process serve admits a push from the vault's owner only
        // (FIX 6867, G1-PUSH).
        remote_user: Some(owner.to_hex()),
        remote_addr: Some("127.0.0.1".to_owned()),
    }
}

fn bounds() -> ExchangeBounds {
    ExchangeBounds {
        idle: Duration::from_secs(30),
        repository_wait: SECOND_PUSH_WAIT,
        command_section: SECTION_DEADLINE,
        scan: ScanBounds::default(),
        spill_floor: None,
    }
}

/// A push body whose command section comes one byte per [`TRICKLE_PACE`],
/// and whose pack then comes at once.
struct TricklingBody {
    section: Vec<u8>,
    sent: usize,
    pack: io::Cursor<Vec<u8>>,
}

impl Read for TricklingBody {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if let Some(&byte) = self.section.get(self.sent) {
            thread::sleep(TRICKLE_PACE);
            out[0] = byte;
            self.sent += 1;
            return Ok(1);
        }
        self.pack.read(out)
    }
}

/// A response sink that keeps the response for the failure messages.
#[derive(Default)]
struct KeptResponse {
    status: Option<u16>,
    body: Vec<u8>,
}

impl ServeSink for KeptResponse {
    fn begin(&mut self, status: u16, _headers: &[(String, String)]) -> io::Result<()> {
        self.status = Some(status);
        Ok(())
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.body.extend_from_slice(bytes);
        Ok(())
    }
}

fn serve_push(
    vault: &Arc<Vault>,
    request: &ServeRequest,
    body: &mut (dyn Read + Send),
) -> (oneiron::Result<ServeReport>, KeptResponse) {
    let mut response = KeptResponse::default();
    let served = smart_http::serve_bounded(
        vault,
        REPO,
        request,
        DoorSeam::Landed,
        bounds(),
        body,
        &mut response,
    );
    (served, response)
}

fn origin_ref(repo: &Path, name: &str) -> Option<String> {
    let output = git_command(repo, &["rev-parse", "--verify", "--quiet", name])
        .stdin(Stdio::null())
        .output()
        .expect("run git rev-parse");
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[test]
fn a_trickling_command_section_is_refused_at_its_deadline_and_frees_the_repository() {
    let dir = tempfile::tempdir().expect("vault tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("open vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let root = smart_http::origin_serving_root(&vault).expect("serving root");
    git(
        &root,
        &[
            "init",
            "--bare",
            "--quiet",
            "--initial-branch=main",
            &format!("{REPO}.git"),
        ],
    );
    let repo = root.join(format!("{REPO}.git"));
    let scratch = tempfile::tempdir().expect("scratch tempdir");
    let (commit, pack) = commit_and_pack(scratch.path());

    let trickled_section = command_section(TRICKLE_REF, &commit);
    let trickle_length = TRICKLE_PACE * u32::try_from(trickled_section.len()).expect("length");
    let trickled_request = receive_pack_request(owner, trickled_section.len() + pack.len());
    let mut trickled_body = TricklingBody {
        section: trickled_section,
        sent: 0,
        pack: io::Cursor::new(pack.clone()),
    };
    let started = Instant::now();
    let trickling = thread::spawn({
        let vault = Arc::clone(&vault);
        move || {
            let (served, response) = serve_push(&vault, &trickled_request, &mut trickled_body);
            (served, response, started.elapsed())
        }
    });

    thread::sleep(SECOND_PUSH_AFTER);
    let mut plain_body = command_section(PLAIN_REF, &commit);
    plain_body.extend_from_slice(&pack);
    let plain_request = receive_pack_request(owner, plain_body.len());
    let plain_started = Instant::now();
    let (plain, plain_response) =
        serve_push(&vault, &plain_request, &mut io::Cursor::new(plain_body));
    let plain_waited = plain_started.elapsed();
    let plain = plain.unwrap_or_else(|error| {
        panic!(
            "a push to the repository lands once the trickling push's command section is past \
             its {SECTION_DEADLINE:?} deadline; it was refused after waiting {plain_waited:?} \
             with {error:?} ({error}) while the trickle, {trickle_length:?} whole, still held \
             the coordinator"
        )
    });
    assert!(
        plain.landing.is_some(),
        "the second push lands; status {:?}, response:\n{}",
        plain_response.status,
        String::from_utf8_lossy(&plain_response.body)
    );
    assert_eq!(
        origin_ref(&repo, PLAIN_REF).as_deref(),
        Some(commit.as_str()),
        "the second push moved its ref"
    );

    let (trickled, trickled_response, trickled_took) =
        trickling.join().expect("the trickling push's thread");
    assert!(
        matches!(
            trickled,
            Err(oneiron::Error::Code(CodeError::GitHttpExchangeIdle))
        ),
        "a command section still trickling past its deadline is refused as an idle stall; \
         got {trickled:?} after {trickled_took:?}, status {:?}",
        trickled_response.status
    );
    assert!(
        trickled_took < trickle_length / 2,
        "the refusal comes at the deadline, not when the trickle ends: it took \
         {trickled_took:?} of a {trickle_length:?} trickle under a {SECTION_DEADLINE:?} deadline"
    );
    assert_eq!(
        origin_ref(&repo, TRICKLE_REF),
        None,
        "the refused push moved no ref"
    );
}
