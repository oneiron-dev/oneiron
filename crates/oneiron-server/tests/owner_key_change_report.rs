#![cfg(all(unix, oneiron_test_support))]
//! The hosted vault's owner key change report (Engine ruling 21 Nov 06:00):
//! one sweep sends every listed change this install has not reported yet, as
//! exactly one `owner_key_change` line each, oldest first, and each joins
//! the install-local cursor once its ack says reported.
//!
//! The boot baseline on a vault with an enrolled passkey writes the cursor
//! and sends nothing, so a deploy mails no old change; a sweep writes no
//! baseline, so with no cursor row it sends every listed change. A passkey
//! enrolled after the baseline is sent as one line with the enrolment's
//! entry, `enrolled`, `passkey` and the list's time, and the next sweep sends
//! nothing. A refusal, an ack outside the contract or over the line cap, and
//! a supervisor whose accept backlog is full leave the change unreported at
//! once, and the next sweep sends it again. A set stop flag sends nothing
//! and ends a wait for an ack within one read slice.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --features oneiron/test-support
//! --test owner_key_change_report`.

use std::collections::BTreeSet;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::thread::JoinHandle;
use std::time::Duration;

use base64::Engine as _;
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityEntryHash, HostSlipIssuer, MachineRole,
    OwnerPasskeyEnrollment, OwnerPasskeyEnrollmentReceipt,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_server::managed::OWNER_KEY_CHANGE_REPORTED_KEY;
use oneiron_server::test_doors::owner_key_change_report::{
    baseline_cursor, report_client, sweep_once, sweep_once_until,
};
use oneiron_vault_contract::MAX_CTL_LINE;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest as _, Sha256};

const VAULT: &str = "vault-7";
const BOUND: Duration = Duration::from_secs(5);
/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
/// The origin the passkey enrols at.
const ORIGIN: &str = "https://oneiron.test";
/// The passkey's credential id (`rawId`).
const CREDENTIAL_ID: &[u8] = b"passkey-credential-0001";
/// A second passkey's credential id.
const SECOND_CREDENTIAL_ID: &[u8] = b"passkey-credential-0002";

fn token() -> String {
    "c3".repeat(32)
}

/// What the test's supervisor does with the one line it reads.
enum Answer {
    Line(&'static str),
    /// `{"reported":true}` padded with spaces to this many bytes, then the
    /// newline.
    Padded(usize),
    /// No answer: says on the sender that the line is read, then holds the
    /// connection until the vault closes it.
    Silent(Sender<()>),
}

/// A supervisor on a fresh socket that reads one line, then answers as told;
/// the line it read comes back from the handle.
fn supervisor(answer: Answer) -> (tempfile::TempDir, PathBuf, JoinHandle<String>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("hypnos.sock");
    let listener = UnixListener::bind(&socket).expect("bind the supervisor socket");
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept the vault");
        let mut reader = BufReader::new(stream.try_clone().expect("clone the stream"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("read the request");
        // the clone holds the connection open too: a close must drop both
        drop(reader);
        let mut stream = stream;
        match answer {
            // a caller that gave up may be gone: its answer is then lost
            Answer::Line(text) => {
                stream.write_all(text.as_bytes()).ok();
                stream.write_all(b"\n").ok();
            }
            Answer::Padded(len) => {
                let mut text = br#"{"reported":true}"#.to_vec();
                text.resize(len, b' ');
                text.push(b'\n');
                stream.write_all(&text).ok();
            }
            Answer::Silent(read) => {
                read.send(()).ok();
                // the vault's close ends the read
                stream.read(&mut [0_u8; 1]).ok();
            }
        }
        line
    });
    (dir, socket, handle)
}

/// A supervisor socket with no accept backlog and one connection waiting in
/// it, so the next connect finds the backlog full. The listener and the
/// waiting connection keep it so while held.
fn full_backlog_supervisor() -> (tempfile::TempDir, PathBuf, UnixListener, UnixStream) {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketType, bind, listen, socket};
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("hypnos.sock");
    let fd = socket(AddressFamily::UNIX, SocketType::STREAM, None).expect("a Unix socket");
    bind(
        &fd,
        &SocketAddrUnix::new(&path).expect("the socket's address"),
    )
    .expect("bind");
    listen(&fd, 0).expect("listen with no backlog");
    let listener = UnixListener::from(fd);
    let waiting = UnixStream::connect(&path).expect("the one connection the backlog holds");
    (dir, path, listener, waiting)
}

/// One vault under the Hosted posture, rooted under the test host, with this
/// install's machine profile enrolled and the embedded owner authenticated
/// but bound to no key. The vault drops first.
struct HostedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl HostedVault {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        let vault = Vault::open(dir.path(), config).expect("hosted vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let (_, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            vault,
            issuer,
            proof,
            _dir: dir,
        }
    }

    fn as_owner(&self) -> ActAuthority {
        ActAuthority::Owner(self.proof.clone(), ActSurface::ThisInstall)
    }
}

/// The passkey a platform authenticator holds, as a software key.
fn passkey() -> P256SigningKey {
    P256SigningKey::from_slice(&[0x5A; 32]).expect("a P-256 scalar")
}

/// A second passkey.
fn second_passkey() -> P256SigningKey {
    P256SigningKey::from_slice(&[0x4C; 32]).expect("a P-256 scalar")
}

/// What `navigator.credentials.get` returns for `challenge`: authenticator
/// data (RP id hash, `flags`, a zero sign count), the client data JSON, and
/// the DER signature over the one and SHA-256 of the other.
struct Assertion {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
}

/// What `navigator.credentials.get` returns for `challenge` when the
/// passkey `key` answers it at `origin`.
fn assert_by(key: &P256SigningKey, challenge: &[u8], flags: u8, origin: &str) -> Assertion {
    let mut authenticator_data = Sha256::digest(b"oneiron.test").to_vec();
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&[0; 4]);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    )
    .into_bytes();
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let signature: P256Signature = key.sign(&signed);
    Assertion {
        authenticator_data,
        client_data_json,
        signature: signature.to_der().as_bytes().to_vec(),
    }
}

/// `passkey`'s enrollment input with `credential_id`, its assertion over
/// the enrollment challenge as its proof of possession.
fn passkey_enrollment(
    hosted: &HostedVault,
    passkey: &P256SigningKey,
    credential_id: &[u8],
) -> OwnerPasskeyEnrollment {
    let public_key = passkey
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let challenge = hosted
        .vault
        .owner_passkey_enrollment_challenge_as(&hosted.as_owner(), &public_key)
        .expect("the passkey's enrollment challenge");
    let assertion = assert_by(passkey, &challenge, FLAGS_PRESENT_VERIFIED, ORIGIN);
    OwnerPasskeyEnrollment {
        credential_id: credential_id.to_vec(),
        public_key,
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
        signature: assertion.signature,
    }
}

/// The host enrols `passkey` for the owner with its custodial root as the
/// predecessor, as a hosted vault with no owner key enrols its first one.
fn host_enrols_passkey(
    hosted: &HostedVault,
    passkey: &P256SigningKey,
    credential_id: &[u8],
) -> OwnerPasskeyEnrollmentReceipt {
    hosted
        .vault
        .enrol_owner_passkey_as_host(
            &hosted.as_owner(),
            &passkey_enrollment(hosted, passkey, credential_id),
            &hosted.issuer,
        )
        .expect("the host enrols the owner's passkey")
}

/// The cursor row's reported entry hashes.
fn cursor(vault: &Vault) -> BTreeSet<AuthorityEntryHash> {
    let raw = vault
        .sync_state_get(OWNER_KEY_CHANGE_REPORTED_KEY)
        .expect("the cursor row reads")
        .expect("the cursor row is written");
    assert_eq!(raw.len() % 32, 0, "the cursor holds whole entry hashes");
    raw.chunks_exact(32)
        .map(|chunk| chunk.try_into().expect("a 32-byte entry hash"))
        .collect()
}

/// One sweep against a supervisor answering `answer`; the line it read and
/// the cursor row after.
fn sweep_and_read_line(
    hosted: &HostedVault,
    answer: Answer,
) -> (String, BTreeSet<AuthorityEntryHash>) {
    let (_dir, socket, supervisor) = supervisor(answer);
    let client = report_client(&socket, VAULT, &token(), BOUND);
    sweep_once(&hosted.vault, &client);
    // a sweep that sent nothing left the supervisor in its accept: this
    // connection releases it with no line, and is refused or dropped else
    let _ = UnixStream::connect(&socket);
    (
        supervisor.join().expect("supervisor"),
        cursor(&hosted.vault),
    )
}

/// One sweep that must send nothing; the cursor row after. The supervisor
/// still waits in its accept, so a connection of the test's own releases
/// it, having read nothing.
fn sweep_and_read_nothing(hosted: &HostedVault) -> BTreeSet<AuthorityEntryHash> {
    let (_dir, socket, supervisor) = supervisor(Answer::Line(r#"{"reported":true}"#));
    let client = report_client(&socket, VAULT, &token(), BOUND);
    sweep_once(&hosted.vault, &client);
    drop(UnixStream::connect(&socket).expect("connect to release the supervisor"));
    assert_eq!(
        supervisor.join().expect("supervisor"),
        "",
        "the sweep sent nothing"
    );
    cursor(&hosted.vault)
}

fn expected_line(entry: &AuthorityEntryHash, at: u64) -> String {
    format!(
        "{{\"op\":\"owner_key_change\",\"vault\":\"{VAULT}\",\"token\":\"{}\",\"entry\":\"{}\",\"change\":\"enrolled\",\"key\":\"passkey\",\"at\":{at}}}\n",
        token(),
        oneiron_hex::encode(entry),
    )
}

/// The list's time of the enrolment `entry`.
fn listed_at(hosted: &HostedVault, entry: &AuthorityEntryHash) -> u64 {
    hosted
        .vault
        .owner_key_changes_as_host()
        .expect("the owner key changes list")
        .iter()
        .find(|change| change.entry == *entry)
        .expect("the list names the enrolment")
        .at
}

#[test]
fn the_boot_baseline_writes_the_cursor_and_sends_nothing() {
    let hosted = HostedVault::open();
    let enrolled = host_enrols_passkey(&hosted, &passkey(), CREDENTIAL_ID);
    baseline_cursor(&hosted.vault);
    assert_eq!(
        cursor(&hosted.vault),
        BTreeSet::from([enrolled.entry]),
        "the baseline names the passkey's enrolment"
    );
    let reported = sweep_and_read_nothing(&hosted);
    assert_eq!(
        reported,
        BTreeSet::from([enrolled.entry]),
        "the sweep after the baseline sends nothing"
    );
}

#[test]
fn a_sweep_with_no_cursor_row_sends_every_listed_change() {
    let hosted = HostedVault::open();
    let enrolled = host_enrols_passkey(&hosted, &passkey(), CREDENTIAL_ID);
    let (line, reported) = sweep_and_read_line(&hosted, Answer::Line(r#"{"reported":true}"#));
    assert_eq!(
        line,
        expected_line(&enrolled.entry, listed_at(&hosted, &enrolled.entry)),
        "a sweep writes no baseline: the enrolment is sent"
    );
    assert_eq!(
        reported,
        BTreeSet::from([enrolled.entry]),
        "the reported enrolment is the cursor"
    );
}

#[test]
fn a_passkey_enrolled_after_the_baseline_is_sent_as_one_exact_line() {
    let hosted = HostedVault::open();
    let first = host_enrols_passkey(&hosted, &passkey(), CREDENTIAL_ID);
    baseline_cursor(&hosted.vault);
    let second = host_enrols_passkey(&hosted, &second_passkey(), SECOND_CREDENTIAL_ID);
    let (line, reported) = sweep_and_read_line(&hosted, Answer::Line(r#"{"reported":true}"#));
    assert_eq!(
        line,
        expected_line(&second.entry, listed_at(&hosted, &second.entry)),
        "the enrolment is sent as exactly one line"
    );
    assert_eq!(
        reported,
        BTreeSet::from([first.entry, second.entry]),
        "the reported enrolment joins the cursor"
    );
}

#[test]
fn the_next_sweep_after_a_report_sends_nothing() {
    let hosted = HostedVault::open();
    host_enrols_passkey(&hosted, &passkey(), CREDENTIAL_ID);
    baseline_cursor(&hosted.vault);
    let second = host_enrols_passkey(&hosted, &second_passkey(), SECOND_CREDENTIAL_ID);
    let (_, reported) = sweep_and_read_line(&hosted, Answer::Line(r#"{"reported":true}"#));
    assert!(
        reported.contains(&second.entry),
        "guard: the sweep reported it"
    );
    let again = sweep_and_read_nothing(&hosted);
    assert_eq!(again, reported, "a reported change is never sent twice");
}

#[test]
fn an_ack_outside_the_contract_leaves_the_change_unreported() {
    let hosted = HostedVault::open();
    let first = host_enrols_passkey(&hosted, &passkey(), CREDENTIAL_ID);
    baseline_cursor(&hosted.vault);
    let second = host_enrols_passkey(&hosted, &second_passkey(), SECOND_CREDENTIAL_ID);
    for answer in [
        "[true]",
        r#"{"reported":true,"reported":true}"#,
        r#"{"reported":true,"error":"refused"}"#,
        r#"{"reported":true,"error":null}"#,
        r#"{"reported":false}"#,
        r#"{"ok":true}"#,
    ] {
        let (line, reported) = sweep_and_read_line(&hosted, Answer::Line(answer));
        assert_eq!(
            line,
            expected_line(&second.entry, listed_at(&hosted, &second.entry)),
            "the change was sent ({answer})"
        );
        assert_eq!(
            reported,
            BTreeSet::from([first.entry]),
            "an answer outside the contract reports nothing ({answer})"
        );
    }
}

#[test]
fn a_refused_report_stays_unreported_and_goes_again() {
    let hosted = HostedVault::open();
    let first = host_enrols_passkey(&hosted, &passkey(), CREDENTIAL_ID);
    baseline_cursor(&hosted.vault);
    let second = host_enrols_passkey(&hosted, &second_passkey(), SECOND_CREDENTIAL_ID);
    let (line, reported) = sweep_and_read_line(
        &hosted,
        Answer::Line(r#"{"reported":false,"error":"stale_generation"}"#),
    );
    assert_eq!(
        line,
        expected_line(&second.entry, listed_at(&hosted, &second.entry)),
        "the refused change was sent"
    );
    assert_eq!(
        reported,
        BTreeSet::from([first.entry]),
        "a refused change stays unreported"
    );
    let (line, reported) = sweep_and_read_line(&hosted, Answer::Line(r#"{"reported":true}"#));
    assert_eq!(
        line,
        expected_line(&second.entry, listed_at(&hosted, &second.entry)),
        "the next sweep sends the refused change again"
    );
    assert_eq!(
        reported,
        BTreeSet::from([first.entry, second.entry]),
        "the reported change joins the cursor"
    );
}

#[test]
fn an_ack_over_the_line_cap_leaves_the_change_unreported() {
    let hosted = HostedVault::open();
    let first = host_enrols_passkey(&hosted, &passkey(), CREDENTIAL_ID);
    baseline_cursor(&hosted.vault);
    let second = host_enrols_passkey(&hosted, &second_passkey(), SECOND_CREDENTIAL_ID);
    // the line and its newline are one byte over the cap
    let (line, reported) = sweep_and_read_line(&hosted, Answer::Padded(MAX_CTL_LINE));
    assert_eq!(
        line,
        expected_line(&second.entry, listed_at(&hosted, &second.entry)),
        "the change was sent"
    );
    assert_eq!(
        reported,
        BTreeSet::from([first.entry]),
        "an ack over the line cap reports nothing"
    );
    // positive control: the line and its newline at the cap read
    let (_, reported) = sweep_and_read_line(&hosted, Answer::Padded(MAX_CTL_LINE - 1));
    assert_eq!(
        reported,
        BTreeSet::from([first.entry, second.entry]),
        "an ack at the line cap reports the change"
    );
}

#[test]
fn a_full_supervisor_backlog_fails_the_report_at_once() {
    let hosted = HostedVault::open();
    let first = host_enrols_passkey(&hosted, &passkey(), CREDENTIAL_ID);
    baseline_cursor(&hosted.vault);
    let second = host_enrols_passkey(&hosted, &second_passkey(), SECOND_CREDENTIAL_ID);
    let (_dir, socket, listener, waiting) = full_backlog_supervisor();
    let client = report_client(&socket, VAULT, &token(), BOUND);
    let (done, finished) = channel();
    let returned = std::thread::scope(|scope| {
        scope.spawn(|| {
            sweep_once(&hosted.vault, &client);
            let _ = done.send(());
        });
        let returned = finished.recv_timeout(BOUND).is_ok();
        // a sweep still waiting in its connect is woken, refused, before the
        // scope joins it
        drop(listener);
        returned
    });
    drop(waiting);
    assert!(returned, "the sweep returned while the backlog was full");
    assert_eq!(
        cursor(&hosted.vault),
        BTreeSet::from([first.entry]),
        "a full backlog reports nothing"
    );
    // positive control: a supervisor with room takes the same change
    let (line, reported) = sweep_and_read_line(&hosted, Answer::Line(r#"{"reported":true}"#));
    assert_eq!(
        line,
        expected_line(&second.entry, listed_at(&hosted, &second.entry)),
        "the next sweep sends it"
    );
    assert_eq!(reported, BTreeSet::from([first.entry, second.entry]));
}

#[test]
fn a_set_stop_flag_sends_nothing() {
    let hosted = HostedVault::open();
    let first = host_enrols_passkey(&hosted, &passkey(), CREDENTIAL_ID);
    baseline_cursor(&hosted.vault);
    let second = host_enrols_passkey(&hosted, &second_passkey(), SECOND_CREDENTIAL_ID);
    let (_dir, socket, supervisor) = supervisor(Answer::Line(r#"{"reported":true}"#));
    let client = report_client(&socket, VAULT, &token(), BOUND);
    sweep_once_until(&hosted.vault, &client, &AtomicBool::new(true));
    drop(UnixStream::connect(&socket).expect("connect to release the supervisor"));
    assert_eq!(
        supervisor.join().expect("supervisor"),
        "",
        "a stopped sweep sent nothing"
    );
    assert_eq!(cursor(&hosted.vault), BTreeSet::from([first.entry]));
    // positive control: an unstopped sweep sends it
    let (_, reported) = sweep_and_read_line(&hosted, Answer::Line(r#"{"reported":true}"#));
    assert_eq!(reported, BTreeSet::from([first.entry, second.entry]));
}

#[test]
fn a_stop_ends_the_wait_for_an_ack_within_one_slice() {
    let hosted = HostedVault::open();
    let first = host_enrols_passkey(&hosted, &passkey(), CREDENTIAL_ID);
    baseline_cursor(&hosted.vault);
    let second = host_enrols_passkey(&hosted, &second_passkey(), SECOND_CREDENTIAL_ID);
    let (read, line_read) = channel();
    let (_dir, socket, supervisor) = supervisor(Answer::Silent(read));
    // a bound far past the slice: only the stop can end the wait in time
    let client = report_client(&socket, VAULT, &token(), Duration::from_secs(60));
    let stop = AtomicBool::new(false);
    let (done, finished) = channel();
    let ended = std::thread::scope(|scope| {
        scope.spawn(|| {
            sweep_once_until(&hosted.vault, &client, &stop);
            let _ = done.send(());
        });
        line_read
            .recv_timeout(BOUND)
            .expect("the supervisor read the line");
        stop.store(true, Ordering::Relaxed);
        finished.recv_timeout(Duration::from_secs(3)).is_ok()
    });
    assert!(ended, "the sweep ended within 3 s of the stop");
    assert_eq!(
        supervisor.join().expect("supervisor"),
        expected_line(&second.entry, listed_at(&hosted, &second.entry)),
        "the change was sent before the stop"
    );
    assert_eq!(
        cursor(&hosted.vault),
        BTreeSet::from([first.entry]),
        "an unanswered report stays unreported"
    );
}
