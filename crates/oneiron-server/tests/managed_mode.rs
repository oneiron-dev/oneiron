// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! Managed serve mode: the engine as a supervised child process (ONE-1595).
//!
//! What each area is pinned by, and why that row is the discriminator:
//!
//! - **argv surface** — `each_missing_required_flag_fails_loudly`,
//!   `an_unknown_contract_version_is_refused_before_any_io`,
//!   `managed_mode_refuses_the_unmanaged_configuration_layers`,
//!   `a_flag_managed_mode_never_reads_is_refused_by_name`. Managed mode takes
//!   its whole configuration from argv, so a flag that goes missing has to be
//!   an error rather than a default, and a flag that belongs to the layers
//!   managed mode does not read has to be a refusal rather than a silent
//!   no-op — including the ones clap accepts and `serve_config` would drop.
//! - **inherited fd** — `a_dupd_inherited_listener_serves_http_and_its_path_survives`
//!   drives a real dup'd, bound unix listener through axum and then checks the
//!   socket's inode: an engine that unlinked and rebound would pass an
//!   `exists()` check and still have stranded every queued connection.
//!   `aliased_descriptors_are_refused_before_any_of_them_is_adopted` is the
//!   other half of the same ownership claim, on the inputs rather than the
//!   path: every adoption path here assumes it alone owns its descriptor.
//! - **socket paths** —
//!   `a_socket_bind_replaces_a_stale_socket_and_refuses_a_regular_file`. The
//!   path is argv, and the bind replaces what is at it, so the row that matters
//!   is the one where "what is at it" is a file nobody can get back.
//! - **open gates** — `a_markerless_vault_is_refused_as_a_real_tenant`,
//!   `a_canary_vault_seals_its_dek_and_refuses_a_different_one`. Fail-closed
//!   means the refusal names what is missing; a bare "denied" would leave the
//!   real-tenant gap invisible.
//! - **ctl verbs** — `ctl_socket_answers_the_contract_verbs`, plus the
//!   over-cap and out-of-bounds rows, which are the reject-not-truncate
//!   guarantee.
//! - **reap freeze** —
//!   `a_served_write_is_refused_while_frozen_and_accepted_again_after_abort`
//!   drives a real write over the served socket. A `guard_write()` call on a
//!   fixture shows the gate refuses without showing that anything on the
//!   serving path asks it to, so those rows stay green against a freeze
//!   nothing enforces. This one cannot.
//!   `a_sync_session_upgraded_before_the_freeze_denies_quiescence` covers what
//!   that gate cannot see: a session opened before the freeze, whose frames no
//!   middleware runs over.
//! - **wake ledger** — `exported_wake_times_ride_the_wire_as_unix_seconds`
//!   pins the serde shape against the contract types (a millisecond stamp
//!   would sail past any "is it a number" assertion),
//!   `ledger_rev_persists_across_a_restart` pins the durability.
//! - **shutdown** — `a_failing_push_is_retried_exactly_once_after_200ms` and
//!   `a_supervisor_that_never_acks_does_not_hold_the_exit_open` are the retry
//!   discipline, and
//!   `a_connected_supervisor_that_never_acks_is_abandoned_on_a_deadline` is
//!   what makes that discipline bound anything: a supervisor that closes gives
//!   an EOF to fail on, one that stays connected and silent gives nothing.
//!   `the_final_push_advances_the_rev_when_the_entries_moved` is
//!   the ordering the contract delivers it under;
//!   `managed_shutdown_closes_ctl_and_leaves_the_inherited_socket_alone`
//!   is the socket-ownership half.
//! - **spawn order** — `ready_byte_lands_only_after_sockets_credentials_and_gates`
//!   and `a_canary_vault_boots_managed_and_signals_ready` run the real
//!   `serve_managed` boot over real descriptors, because the ready byte is the
//!   supervisor's only evidence that any of the ordering held.

use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use oneiron_server::config::{ServeArgs, SyncServerConfig};
use oneiron_server::managed::{
    CANARY_MARKER_KEY, CANARY_MARKER_VALUE, DEK_MAC_KEY, HYPNOS_LISTEN_FD, LEDGER_REV_KEY,
    ManagedArgs, ManagedCtl, ManagedError, ManagedShutdown, ManagedState, ServeListener,
    WRITES_FROZEN_TAG, WakeLedger, check_managed_open_gates, final_ledger_push,
    read_managed_credentials, serve_managed, signal_ready, spawn_sigterm_shutdown,
};
use oneiron_server::server::SyncServer;
use oneiron_vault_contract::{
    CONTRACT_VERSION, CREDENTIALS_LEN, Credentials, CtlResponse, DEK_LEN, LedgerAck, LedgerUpdate,
    MAX_CTL_LINE, READY_BYTE, Schedule, TOKEN_LEN, WakeEntry, read_credentials,
    validate_wake_entries, write_credentials,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

const VAULT_NAME: &str = "canary-vault";

/// Drives `ServeArgs` through a real clap parse, so these rows test the flags
/// the supervisor will actually type rather than a struct literal that cannot
/// disagree with the parser.
#[derive(Parser)]
struct ArgvProbe {
    #[command(flatten)]
    serve: ServeArgs,
}

fn parse_serve(argv: &[String]) -> ServeArgs {
    let mut full = vec!["oneiron-server".to_owned()];
    full.extend_from_slice(argv);
    ArgvProbe::try_parse_from(full).unwrap().serve
}

/// A complete managed argv rooted at `root`. The two fds are placeholders;
/// rows that actually read from them overwrite the parsed fields with real
/// descriptors.
fn managed_argv(root: &Path) -> Vec<String> {
    let path = |name: &str| root.join(name).display().to_string();
    vec![
        "--managed-by-hypnos".to_owned(),
        "--contract-version".to_owned(),
        CONTRACT_VERSION.to_string(),
        "--vault-name".to_owned(),
        VAULT_NAME.to_owned(),
        "--data-dir".to_owned(),
        path("data"),
        "--http-socket".to_owned(),
        path("http.sock"),
        "--ctl-socket".to_owned(),
        path("ctl.sock"),
        "--hypnos-socket".to_owned(),
        path("sup.sock"),
        "--ready-fd".to_owned(),
        "7".to_owned(),
        "--credentials-fd".to_owned(),
        "9".to_owned(),
    ]
}

/// Drops `flag`, plus the value after it when the flag takes one. The value
/// test keeps `--managed-by-hypnos` (which takes none) removable by the same
/// helper as every other flag.
fn without_flag(argv: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < argv.len() {
        if argv[index] == flag {
            index += 1;
            if index < argv.len() && !argv[index].starts_with("--") {
                index += 1;
            }
            continue;
        }
        out.push(argv[index].clone());
        index += 1;
    }
    out
}

fn with_flag_value(argv: &[String], flag: &str, value: &str) -> Vec<String> {
    let mut out = argv.to_vec();
    for index in 0..out.len() {
        if out[index] == flag && index + 1 < out.len() {
            out[index + 1] = value.to_owned();
        }
    }
    out
}

/// Opens a vault the way managed mode will, so a seeding open and a managed
/// open cannot disagree about dimensions or map size.
fn open_vault(dir: &Path) -> Arc<oneiron::Vault> {
    Arc::new(oneiron::Vault::open(dir, oneiron::VaultConfig::server()).unwrap())
}

fn sync_server(vault: Arc<oneiron::Vault>) -> Arc<SyncServer> {
    Arc::new(SyncServer::new(vault, SyncServerConfig::default()).unwrap())
}

fn credentials(dek: u8, token: u8) -> Credentials {
    let mut frame = Vec::new();
    write_credentials(&mut frame, &[dek; DEK_LEN], &[token; TOKEN_LEN]).unwrap();
    read_credentials(&frame[..]).unwrap()
}

fn wake_ledger(vault: &Arc<oneiron::Vault>, sup: &Path, creds: &Credentials) -> WakeLedger {
    WakeLedger::load(
        Arc::clone(vault),
        VAULT_NAME.to_owned(),
        sup.to_path_buf(),
        creds,
    )
    .unwrap()
}

/// Writes `bytes` to a file and hands back an owned descriptor over it, which
/// is how a supervisor-delivered fd looks from inside the child.
fn fd_over_bytes(path: &Path, bytes: &[u8]) -> RawFd {
    std::fs::write(path, bytes).unwrap();
    std::fs::File::open(path).unwrap().into_raw_fd()
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn sockets_dir(root: &Path) -> PathBuf {
    let dir = root.join("run");
    std::fs::create_dir_all(&dir).unwrap();
    // Deliberately world-readable to start with, so asserting 0700 afterwards
    // proves this code tightened it rather than inheriting a tight tempdir.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

async fn http_get_over_unix(path: &Path, target: &str) -> String {
    http_over_unix(
        path,
        &format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
    .await
}

/// How long a row waits for the server to answer at all. Generous: a managed
/// boot binds its socket before it starts accepting, so the first connection
/// can sit in the backlog while the boot finishes its opening ledger push.
const HTTP_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long it waits for more of an answer already in progress. Short: the
/// tail of a response follows its first bytes immediately or not at all.
const HTTP_QUIET_TIMEOUT: Duration = Duration::from_millis(200);

/// One raw HTTP request over a served unix socket, status line and body
/// together.
///
/// Reads until the peer closes OR the socket falls quiet. A refusal answered on
/// a connection the server keeps open — the WebSocket handshake row, which has
/// to ask for `Connection: Upgrade` and so cannot also ask for `close` — never
/// reaches EOF, and a `read_to_end` there would hang the row instead of failing
/// it.
async fn http_over_unix(path: &Path, request: &str) -> String {
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = Vec::new();
    loop {
        let patience = if response.is_empty() {
            HTTP_FIRST_BYTE_TIMEOUT
        } else {
            HTTP_QUIET_TIMEOUT
        };
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(patience, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => response.extend_from_slice(&chunk[..read]),
            Ok(Err(error)) => panic!("managed http read failed: {error}"),
        };
    }
    String::from_utf8_lossy(&response).into_owned()
}

/// A JSON write, as the bytes a client actually puts on the wire.
fn json_post_request(target: &str, body: &str) -> String {
    format!(
        "POST {target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    )
}

/// The write the freeze rows drive: a real core conversation create, at a
/// caller-chosen id so the read-back afterwards is an exact lookup rather than
/// a search that could pass on somebody else's row.
fn conversation_write(id: &str) -> String {
    json_post_request(
        "/v1/core/conversations",
        &format!(r#"{{"id":"{id}","body":{{"name":"freeze probe"}}}}"#),
    )
}

/// A fixed, non-sentinel entity id, so a read-back cannot collide with anything
/// the vault mints for itself.
fn probe_entity_id(tag: u8) -> String {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x7e;
    bytes[15] = tag;
    oneiron::EntityId::from_bytes(bytes).unwrap().to_hex()
}

/// A well-formed WebSocket handshake, so a refusal of it cannot be explained
/// away as a malformed request.
const WS_UPGRADE_REQUEST: &str = concat!(
    "GET /ws HTTP/1.1\r\n",
    "Host: localhost\r\n",
    "Connection: Upgrade\r\n",
    "Upgrade: websocket\r\n",
    "Sec-WebSocket-Version: 13\r\n",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
    "\r\n"
);

/// One ctl request line in, one response line out.
///
/// Writes are tolerated rather than asserted: an over-cap line is rejected
/// whole and the peer closes, so the tail of the write can legitimately fail.
/// The response is what the row is about.
async fn ctl_roundtrip(path: &Path, line: &str) -> String {
    let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
    let _ = stream.write_all(line.as_bytes()).await;
    let _ = stream.write_all(b"\n").await;
    let _ = stream.flush().await;
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out).await;
    out.trim().to_owned()
}

fn ctl_response(line: &str) -> CtlResponse {
    serde_json::from_str(line)
        .unwrap_or_else(|error| panic!("unparsable ctl reply {line:?}: {error}"))
}

/// A supervisor that answers on its ledger socket. The first `silent_attempts`
/// connections are closed with no ack; the rest are acked. Returns the raw
/// lines it received, so a caller can validate what the engine actually sent.
fn spawn_mock_supervisor(
    listener: tokio::net::UnixListener,
    silent_attempts: usize,
    total_attempts: usize,
) -> tokio::task::JoinHandle<Vec<String>> {
    tokio::spawn(async move {
        let mut lines = Vec::new();
        for attempt in 0..total_attempts {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let (reader, mut writer) = stream.into_split();
            let mut reader = tokio::io::BufReader::new(reader);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_ok() {
                lines.push(line.trim().to_owned());
            }
            if attempt >= silent_attempts {
                let ack = serde_json::to_string(&LedgerAck {
                    ok: true,
                    error: None,
                })
                .unwrap();
                let _ = writer.write_all(ack.as_bytes()).await;
                let _ = writer.write_all(b"\n").await;
                let _ = writer.flush().await;
            }
        }
        lines
    })
}

async fn wait_for_ready(path: &Path) {
    for _ in 0..400 {
        if std::fs::read(path).is_ok_and(|bytes| bytes == [READY_BYTE]) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("ready byte never arrived at {}", path.display());
}

// ---------------------------------------------------------------------------
// E1 — serve-mode scaffold
// ---------------------------------------------------------------------------

/// Off by default. This is the whole guarantee that today's operators are
/// untouched, so it gets its own row rather than riding on another assertion.
#[test]
fn serve_without_the_switch_is_never_managed() {
    assert!(
        ManagedArgs::from_serve_args(&ServeArgs::default())
            .unwrap()
            .is_none()
    );

    // Even a fully populated managed argv group is inert without the switch.
    let dir = tempfile::tempdir().unwrap();
    let argv = without_flag(&managed_argv(dir.path()), "--managed-by-hypnos");
    let args = parse_serve(&argv);
    assert!(!args.managed_by_hypnos);
    assert!(ManagedArgs::from_serve_args(&args).unwrap().is_none());
}

#[test]
fn a_full_managed_argv_validates() {
    let dir = tempfile::tempdir().unwrap();
    let managed = ManagedArgs::from_serve_args(&parse_serve(&managed_argv(dir.path())))
        .unwrap()
        .unwrap();

    assert_eq!(managed.vault_name, VAULT_NAME);
    assert_eq!(managed.data_dir, dir.path().join("data"));
    assert_eq!(managed.http_socket, dir.path().join("http.sock"));
    assert_eq!(managed.ctl_socket, dir.path().join("ctl.sock"));
    assert_eq!(managed.hypnos_socket, dir.path().join("sup.sock"));
    assert_eq!(managed.ready_fd, 7);
    assert_eq!(managed.credentials_fd, 9);
}

#[test]
fn each_missing_required_flag_fails_loudly() {
    let dir = tempfile::tempdir().unwrap();
    let full = managed_argv(dir.path());

    for dropped in [
        "--contract-version",
        "--vault-name",
        "--data-dir",
        "--http-socket",
        "--ctl-socket",
        "--hypnos-socket",
        "--ready-fd",
        "--credentials-fd",
    ] {
        let argv = without_flag(&full, dropped);
        let error = ManagedArgs::from_serve_args(&parse_serve(&argv)).unwrap_err();
        let expected = dropped.trim_start_matches("--");
        assert!(
            matches!(&error, ManagedError::MissingFlag { flag } if *flag == expected),
            "dropping {dropped} gave: {error}"
        );
        assert!(error.to_string().contains(dropped));
    }
}

#[test]
fn an_unknown_contract_version_is_refused_before_any_io() {
    let dir = tempfile::tempdir().unwrap();
    let full = managed_argv(dir.path());

    let bad = with_flag_value(&full, "--contract-version", "2");
    let error = ManagedArgs::from_serve_args(&parse_serve(&bad)).unwrap_err();
    assert!(
        matches!(
            error,
            ManagedError::UnknownContractVersion {
                found: 2,
                expected: CONTRACT_VERSION
            }
        ),
        "unexpected: {error}"
    );

    // Version first: an engine spawned against a wire it cannot speak must exit
    // before anything asks it to look at a descriptor or a directory, so the
    // version refusal has to win over every other complaint in the same argv.
    let mut worse = without_flag(&bad, "--data-dir");
    worse = without_flag(&worse, "--credentials-fd");
    worse.push("--host".to_owned());
    worse.push("127.0.0.1".to_owned());
    let error = ManagedArgs::from_serve_args(&parse_serve(&worse)).unwrap_err();
    assert!(
        matches!(error, ManagedError::UnknownContractVersion { .. }),
        "the contract version must be checked first, got: {error}"
    );
}

#[test]
fn managed_mode_refuses_the_unmanaged_configuration_layers() {
    let dir = tempfile::tempdir().unwrap();
    let full = managed_argv(dir.path());

    for (flag, value, named) in [
        ("--host", "127.0.0.1", "host"),
        ("--port", "9090", "port"),
        ("--config", "/nonexistent/oneiron.toml", "config"),
    ] {
        let mut argv = full.clone();
        argv.push(flag.to_owned());
        argv.push(value.to_owned());
        let error = ManagedArgs::from_serve_args(&parse_serve(&argv)).unwrap_err();
        assert!(
            matches!(&error, ManagedError::ConflictingFlag { flag, .. } if *flag == named),
            "{flag} should conflict, got: {error}"
        );
        // A refusal that does not name the conflict leaves the operator
        // guessing which of eleven flags is the problem.
        assert!(error.to_string().contains(named), "{error}");
    }
}

/// The flags managed mode does not read are refused, not dropped.
///
/// `serve_config` forces `auth_secret: None` and takes its defaults, so every
/// serve flag outside its four inputs used to be accepted by clap and thrown
/// away — an operator who typed `--auth-secret` got neither the setting nor an
/// error. Silence there is the worst of both: the engine is not configured the
/// way the command line says it is, and nothing says so.
#[test]
fn a_flag_managed_mode_never_reads_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let mut argv = managed_argv(dir.path());
    argv.push("--auth-secret".to_owned());
    argv.push("hunter2".to_owned());

    let error = ManagedArgs::from_serve_args(&parse_serve(&argv)).unwrap_err();
    assert!(
        matches!(&error, ManagedError::ConflictingFlag { flag, .. } if *flag == "auth-secret"),
        "--auth-secret must conflict in managed mode, got: {error}"
    );
    assert!(error.to_string().contains("auth-secret"), "{error}");
    // A refusal that quotes the value would put the secret in whatever read
    // the exit status.
    assert!(!error.to_string().contains("hunter2"), "{error}");

    // The allowlisted flags still ride argv: refusing all of them would be a
    // different bug wearing the same green.
    let mut allowed = managed_argv(dir.path());
    allowed.push("--dimensions".to_owned());
    allowed.push("512".to_owned());
    let args = parse_serve(&allowed);
    let managed = ManagedArgs::from_serve_args(&args).unwrap().unwrap();
    assert_eq!(managed.serve_config(&args).dimensions, 512);
}

#[test]
fn a_vault_name_that_is_not_a_dns_label_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let argv = with_flag_value(&managed_argv(dir.path()), "--vault-name", "Not_A_Label");
    let error = ManagedArgs::from_serve_args(&parse_serve(&argv)).unwrap_err();
    assert!(
        matches!(error, ManagedError::InvalidVaultName { .. }),
        "unexpected: {error}"
    );
}

/// Non-negative is not the whole precondition: each delivered descriptor is
/// adopted with unique ownership, so two inputs naming one number is a bug that
/// closes a live descriptor or writes the ready byte into a frame somebody is
/// still reading. All three inputs are checked pairwise, before any adoption.
#[test]
fn aliased_descriptors_are_refused_before_any_of_them_is_adopted() {
    let dir = tempfile::tempdir().unwrap();

    // `--ready-fd` and `--credentials-fd` on the same number.
    let argv = with_flag_value(&managed_argv(dir.path()), "--credentials-fd", "7");
    let error = ManagedArgs::from_serve_args(&parse_serve(&argv)).unwrap_err();
    assert!(
        matches!(&error, ManagedError::AliasedFd { fd: 7, .. }),
        "unexpected: {error}"
    );
    // A refusal that does not name both sides leaves the operator guessing
    // which of the three inputs collided.
    assert!(error.to_string().contains("--ready-fd"), "{error}");
    assert!(error.to_string().contains("--credentials-fd"), "{error}");

    // The inherited listener is the third owner of the same numbering. Checked
    // through the refusal `ServeListener::for_managed` calls rather than by
    // setting HYPNOS_LISTEN_FD: this harness runs its rows on parallel threads,
    // and a process-wide environment write here would race the row that pins
    // the unset case into failing for a reason that is not about it.
    let managed = ManagedArgs::from_serve_args(&parse_serve(&managed_argv(dir.path())))
        .unwrap()
        .unwrap();
    for aliased in [managed.ready_fd, managed.credentials_fd] {
        let error = managed.refuse_listen_fd_alias(aliased).unwrap_err();
        assert!(
            matches!(&error, ManagedError::AliasedFd { .. }),
            "listen fd {aliased} aliases an argv fd, got: {error}"
        );
        assert!(error.to_string().contains(HYPNOS_LISTEN_FD), "{error}");
    }

    // A descriptor of its own is what the supervisor actually passes, and it
    // still goes through: refusing every inherited listener would be a
    // different bug wearing the same green.
    managed
        .refuse_listen_fd_alias(managed.ready_fd + managed.credentials_fd + 1)
        .unwrap();
}

#[test]
fn a_negative_descriptor_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut argv = without_flag(&managed_argv(dir.path()), "--ready-fd");
    argv.push("--ready-fd=-1".to_owned());
    let error = ManagedArgs::from_serve_args(&parse_serve(&argv)).unwrap_err();
    assert!(
        matches!(
            error,
            ManagedError::InvalidFd {
                flag: "ready-fd",
                value: -1
            }
        ),
        "unexpected: {error}"
    );
}

#[test]
fn vault_path_stays_the_alias_for_the_data_directory() {
    let dir = tempfile::tempdir().unwrap();
    let mut argv = without_flag(&managed_argv(dir.path()), "--data-dir");
    argv.push("--vault-path".to_owned());
    argv.push(dir.path().join("data").display().to_string());

    let managed = ManagedArgs::from_serve_args(&parse_serve(&argv))
        .unwrap()
        .unwrap();
    assert_eq!(managed.data_dir, dir.path().join("data"));
}

/// The managed configuration is argv and nothing else: no config file, no
/// `ONEIRON_*` environment, no XDG layer. `auth_secret` staying `None` is the
/// load-bearing half — bearer auth terminates at the supervisor, and a child
/// that grew its own opinion from the environment would be a second, weaker
/// answer to "who may talk to this vault".
#[test]
fn managed_configuration_comes_from_argv_alone() {
    let dir = tempfile::tempdir().unwrap();
    let args = parse_serve(&managed_argv(dir.path()));
    let managed = ManagedArgs::from_serve_args(&args).unwrap().unwrap();
    let config = managed.serve_config(&args);

    assert!(config.auth_secret.is_none());
    assert!(config.allow_unauthenticated);
    assert_eq!(config.vault_path, dir.path().join("data"));
    // The usual dictionary resolver probes HOME and the XDG roots; managed
    // mode does not get to read either, so an unset flag means an empty list
    // rather than a discovered one.
    assert!(config.dict_search_paths.is_empty());
    assert_eq!(config.log_level, "info");
}

// ---------------------------------------------------------------------------
// E2 — inherited fd bind
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_dupd_inherited_listener_serves_http_and_its_path_survives() {
    let dir = tempfile::tempdir().unwrap();
    let run = sockets_dir(dir.path());
    let path = run.join("http.sock");

    // The supervisor's side: a real bound, listening unix socket, handed over
    // as a dup'd descriptor.
    let supervisor_listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let inode_before = std::fs::metadata(&path).unwrap().ino();
    let inherited = supervisor_listener.try_clone().unwrap().into_raw_fd();
    drop(supervisor_listener);

    let bound = ServeListener::InheritedFd(inherited).bind().await.unwrap();
    assert!(
        bound.owned_path().is_none(),
        "an inherited socket path is never ours to remove"
    );

    let shutdown = ManagedShutdown::new();
    let app = axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));
    let signal = shutdown.triggered();
    let served = tokio::spawn(async move { bound.serve_until(app, signal).await });

    let response = http_get_over_unix(&path, "/health").await;
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {response}"
    );
    assert!(response.ends_with("ok"), "unexpected body: {response}");

    shutdown.trigger();
    served.await.unwrap().unwrap();

    assert!(
        path.exists(),
        "the child must never unlink an inherited socket path"
    );
    // An engine that unlinked and rebound would still pass `exists()` while
    // having stranded every connection queued on the original inode.
    assert_eq!(
        std::fs::metadata(&path).unwrap().ino(),
        inode_before,
        "the child must never rebind an inherited socket path"
    );
}

#[tokio::test]
async fn an_absent_listen_fd_self_binds_on_the_http_socket() {
    assert!(
        std::env::var(HYPNOS_LISTEN_FD).is_err(),
        "this row is about the unset case; the test environment must not preset {HYPNOS_LISTEN_FD}"
    );

    let dir = tempfile::tempdir().unwrap();
    let run = sockets_dir(dir.path());
    let managed = ManagedArgs::from_serve_args(&parse_serve(&managed_argv(&run)))
        .unwrap()
        .unwrap();

    let resolved = ServeListener::for_managed(&managed).unwrap();
    assert_eq!(resolved, ServeListener::UnixPath(run.join("http.sock")));

    let bound = resolved.bind().await.unwrap();
    assert_eq!(bound.owned_path(), Some(run.join("http.sock").as_path()));
    assert_eq!(mode_of(&run.join("http.sock")), 0o600);
    assert_eq!(mode_of(&run), 0o700);
}

/// Binding replaces a stale socket and refuses everything else.
///
/// The path is argv, and binding used to unlink whatever was at it. That makes
/// `--ctl-socket` one character off from a config or vault file an irreversible
/// delete of that file, with the engine then serving happily over its corpse.
/// Both halves are pinned here: a stale socket is still replaced (a refusal
/// that swallowed the restart case would be a worse bug), and a regular file is
/// refused with its bytes intact.
#[tokio::test]
async fn a_socket_bind_replaces_a_stale_socket_and_refuses_a_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let run = sockets_dir(dir.path());

    // A socket left behind by a previous run: ours to replace.
    let stale = run.join("ctl.sock");
    let previous = std::os::unix::net::UnixListener::bind(&stale).unwrap();
    let stale_inode = std::fs::metadata(&stale).unwrap().ino();
    drop(previous);
    let _ctl = ManagedCtl::bind(&stale).unwrap();
    assert_ne!(
        std::fs::metadata(&stale).unwrap().ino(),
        stale_inode,
        "a stale socket must be replaced by this process's own"
    );

    // A mistyped path landing on real data: not ours, and not recoverable if
    // this gets it wrong.
    let occupied = run.join("vault.conf");
    std::fs::write(&occupied, b"secret-config").unwrap();
    let Err(error) = ManagedCtl::bind(&occupied) else {
        panic!("binding over a regular file must be refused");
    };
    assert!(
        matches!(&error, ManagedError::SocketPathOccupied { .. }),
        "unexpected: {error}"
    );
    assert!(error.to_string().contains("regular file"), "{error}");
    assert_eq!(
        std::fs::read(&occupied).unwrap(),
        b"secret-config",
        "a refused bind must leave the file it refused to unlink exactly as it was"
    );
}

// ---------------------------------------------------------------------------
// E3 — credentials fd and DEK gate
// ---------------------------------------------------------------------------

#[test]
fn the_credential_gate_fails_closed_on_a_malformed_frame() {
    let dir = tempfile::tempdir().unwrap();

    for (name, bytes) in [
        ("short", vec![0u8; CREDENTIALS_LEN - 1]),
        ("long", vec![0u8; CREDENTIALS_LEN + 1]),
        ("empty", Vec::new()),
    ] {
        let fd = fd_over_bytes(&dir.path().join(name), &bytes);
        // Destructured rather than `unwrap_err()`, which would need
        // `Credentials: Debug` to render the unexpected-Ok case. That bound is
        // exactly what this crate refuses to grant: a derived `Debug` would put
        // the DEK and the spawn token one `{:?}` away from a log line.
        let Err(error) = read_managed_credentials(fd) else {
            panic!("the {name} frame must be refused");
        };
        assert!(
            matches!(error, ManagedError::CredentialsRejected { .. }),
            "{name} frame should be refused, got: {error}"
        );
    }

    let mut frame = Vec::new();
    write_credentials(&mut frame, &[0x11; DEK_LEN], &[0x22; TOKEN_LEN]).unwrap();
    let fd = fd_over_bytes(&dir.path().join("good"), &frame);
    let credentials = read_managed_credentials(fd).unwrap();
    assert_eq!(credentials.dek, [0x11; DEK_LEN]);
    assert_eq!(credentials.token, [0x22; TOKEN_LEN]);
}

#[test]
fn a_markerless_vault_is_refused_as_a_real_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(&dir.path().join("data"));
    let creds = credentials(0x11, 0x22);

    let error = check_managed_open_gates(&vault, VAULT_NAME, &creds).unwrap_err();
    assert!(
        matches!(error, ManagedError::ManagedRealTenantRefused { .. }),
        "unexpected: {error}"
    );
    // The refusal has to name what is missing. A bare "denied" would leave the
    // real-tenant gap invisible to whoever hits it next.
    let message = error.to_string();
    assert!(message.contains("fscrypt"), "{message}");
    assert!(message.contains("per-vault UID"), "{message}");
    assert!(message.contains(CANARY_MARKER_KEY), "{message}");
    assert!(message.contains("tripwire"), "{message}");

    // A present-but-blank marker row is not consent either.
    vault.sync_state_put(CANARY_MARKER_KEY, &[]).unwrap();
    assert!(check_managed_open_gates(&vault, VAULT_NAME, &creds).is_err());

    // Nothing was sealed on the way out.
    assert!(vault.sync_state_get(DEK_MAC_KEY).unwrap().is_none());
}

#[test]
fn a_canary_vault_seals_its_dek_and_refuses_a_different_one() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(&dir.path().join("data"));
    vault
        .sync_state_put(CANARY_MARKER_KEY, CANARY_MARKER_VALUE)
        .unwrap();

    let sealed = credentials(0x11, 0x22);
    check_managed_open_gates(&vault, VAULT_NAME, &sealed).unwrap();
    let mac = vault
        .sync_state_get(DEK_MAC_KEY)
        .unwrap()
        .expect("the first managed open seals the DEK MAC");
    assert_eq!(mac.len(), 32);

    // The same DEK verifies against the sealed MAC and does not reseal it.
    check_managed_open_gates(&vault, VAULT_NAME, &sealed).unwrap();
    assert_eq!(
        vault.sync_state_get(DEK_MAC_KEY).unwrap().as_deref(),
        Some(mac.as_slice())
    );

    // A tampered DEK is refused, before any content is read.
    let wrong = credentials(0x99, 0x22);
    let error = check_managed_open_gates(&vault, VAULT_NAME, &wrong).unwrap_err();
    assert!(
        matches!(error, ManagedError::DekMacMismatch { .. }),
        "unexpected: {error}"
    );
    assert!(error.to_string().contains("before reading any content"));
    assert_eq!(
        vault.sync_state_get(DEK_MAC_KEY).unwrap().as_deref(),
        Some(mac.as_slice()),
        "a refused open must not reseal the vault under the DEK it refused"
    );
}

// ---------------------------------------------------------------------------
// E4 — ctl socket and pre-reap quiescence
// ---------------------------------------------------------------------------

struct CtlFixture {
    _dir: tempfile::TempDir,
    run: PathBuf,
    ctl_path: PathBuf,
    state: Arc<ManagedState>,
    server: Arc<SyncServer>,
    shutdown: ManagedShutdown,
    task: tokio::task::JoinHandle<()>,
}

fn spawn_ctl_fixture() -> CtlFixture {
    let dir = tempfile::tempdir().unwrap();
    let run = sockets_dir(dir.path());
    let vault = open_vault(&run.join("data"));
    let server = sync_server(Arc::clone(&vault));
    let creds = credentials(0x11, 0x22);
    let ledger = wake_ledger(&vault, &run.join("sup.sock"), &creds);
    let state = Arc::new(ManagedState::new(
        VAULT_NAME.to_owned(),
        Arc::clone(&server),
        ledger,
    ));

    let ctl_path = run.join("ctl.sock");
    let ctl = ManagedCtl::bind(&ctl_path).unwrap();
    let shutdown = ManagedShutdown::new();
    let signal = shutdown.triggered();
    let ctl_state = Arc::clone(&state);
    let task = tokio::spawn(async move { ctl.serve(ctl_state, signal).await });

    CtlFixture {
        _dir: dir,
        run,
        ctl_path,
        state,
        server,
        shutdown,
        task,
    }
}

#[tokio::test]
async fn ctl_socket_answers_the_contract_verbs() {
    let fixture = spawn_ctl_fixture();

    // The socket the supervisor connects to is owner-only, in an owner-only
    // directory: nothing else on the box gets to speak these verbs.
    assert_eq!(mode_of(&fixture.ctl_path), 0o600);
    assert_eq!(mode_of(&fixture.run), 0o700);

    match ctl_response(&ctl_roundtrip(&fixture.ctl_path, r#"{"op":"ping"}"#).await) {
        CtlResponse::Ping {
            ok,
            vault,
            pid,
            contract_version,
        } => {
            assert!(ok);
            assert_eq!(vault, VAULT_NAME);
            assert_eq!(pid, std::process::id());
            assert_eq!(contract_version, CONTRACT_VERSION);
        }
        other => panic!("expected a ping reply, got {other:?}"),
    }

    // Before the freeze, writes are allowed.
    fixture.state.guard_write().unwrap();

    match ctl_response(&ctl_roundtrip(&fixture.ctl_path, r#"{"op":"prepare_reap"}"#).await) {
        CtlResponse::PrepareReap {
            quiescent,
            ledger_rev,
            next_wake,
        } => {
            assert!(
                quiescent,
                "a drained lease table on an idle vault is quiescent"
            );
            assert!(ledger_rev >= 1, "the freeze export advances the revision");
            validate_wake_entries(&next_wake).unwrap();
        }
        other => panic!("expected a prepare_reap reply, got {other:?}"),
    }

    // The freeze flipped, and it refuses new writes with a type a caller can
    // act on rather than a message it has to read.
    assert!(fixture.state.is_frozen());
    let refused = fixture.state.guard_write().unwrap_err();
    assert!(
        matches!(refused, ManagedError::WritesFrozen),
        "unexpected: {refused}"
    );

    match ctl_response(&ctl_roundtrip(&fixture.ctl_path, r#"{"op":"reap_abort"}"#).await) {
        CtlResponse::Ok { ok } => assert!(ok),
        other => panic!("expected an ok reply, got {other:?}"),
    }
    assert!(!fixture.state.is_frozen());
    fixture.state.guard_write().unwrap();

    // alarm_due reaches the reconciler hook.
    let alarm = r#"{"op":"alarm_due","id":"nightly","reason_tag":"cron"}"#;
    match ctl_response(&ctl_roundtrip(&fixture.ctl_path, alarm).await) {
        CtlResponse::Ok { ok } => assert!(ok),
        other => panic!("expected an ok reply, got {other:?}"),
    }
    let observed = fixture.state.observed_alarms().await;
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].id, "nightly");
    assert_eq!(observed[0].reason_tag, "cron");

    fixture.shutdown.trigger();
    fixture.task.await.unwrap();
    drop(fixture.server);
}

#[tokio::test]
async fn ctl_rejects_over_cap_and_out_of_bounds_lines_whole() {
    let fixture = spawn_ctl_fixture();

    // Over the line cap. Truncating would let a shorter, different request
    // through than the supervisor sent, which is worse than none at all.
    let padding = "x".repeat(MAX_CTL_LINE + 16);
    let oversized = format!(r#"{{"op":"alarm_due","id":"{padding}","reason_tag":"cron"}}"#);
    match ctl_response(&ctl_roundtrip(&fixture.ctl_path, &oversized).await) {
        CtlResponse::Ok { ok } => assert!(!ok, "an over-cap line must be refused"),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // Within the cap, but outside the contract's field bounds: deserialization
    // alone does not enforce the wire limits, so `CtlRequest::validate` has to.
    let empty_id = r#"{"op":"alarm_due","id":"","reason_tag":"cron"}"#;
    match ctl_response(&ctl_roundtrip(&fixture.ctl_path, empty_id).await) {
        CtlResponse::Ok { ok } => assert!(!ok, "an out-of-bounds alarm must be refused"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    let control_bytes = r#"{"op":"alarm_due","id":"a\u0001b","reason_tag":"cron"}"#;
    match ctl_response(&ctl_roundtrip(&fixture.ctl_path, control_bytes).await) {
        CtlResponse::Ok { ok } => assert!(!ok, "control bytes in an id must be refused"),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // Not one of them reached the reconciler.
    assert!(fixture.state.observed_alarms().await.is_empty());

    fixture.shutdown.trigger();
    fixture.task.await.unwrap();
    drop(fixture.server);
}

// ---------------------------------------------------------------------------
// E5 — wake ledger export
// ---------------------------------------------------------------------------

/// The contract types say `UnixTs` is seconds. A millisecond stamp for the
/// same instant is three orders of magnitude larger and would sail past any
/// "is it a number" assertion, so the magnitude is checked explicitly.
#[test]
fn exported_wake_times_ride_the_wire_as_unix_seconds() {
    let response = CtlResponse::PrepareReap {
        quiescent: true,
        ledger_rev: 42,
        next_wake: vec![
            WakeEntry {
                id: "job_ready".to_owned(),
                at: Schedule::Exact { at: 1_767_225_600 },
                reason_tag: "job_ready".to_owned(),
            },
            WakeEntry {
                id: "sync_deadline".to_owned(),
                at: Schedule::Window {
                    start: 1_767_225_600,
                    end: 1_767_225_660,
                },
                reason_tag: "lease_expiry".to_owned(),
            },
        ],
    };

    let json: serde_json::Value = serde_json::to_value(&response).unwrap();
    assert_eq!(json["quiescent"], true);
    assert_eq!(json["ledger_rev"], 42);
    assert_eq!(json["next_wake"][0]["at"]["kind"], "exact");
    assert_eq!(json["next_wake"][0]["at"]["at"], 1_767_225_600u64);
    assert_eq!(json["next_wake"][1]["at"]["kind"], "window");
    assert_eq!(json["next_wake"][1]["at"]["start"], 1_767_225_600u64);
    assert_eq!(json["next_wake"][1]["at"]["end"], 1_767_225_660u64);

    let at = json["next_wake"][0]["at"]["at"].as_u64().unwrap();
    assert!(
        at < 100_000_000_000,
        "wake stamp {at} is milliseconds, not unix seconds"
    );
}

#[tokio::test]
async fn the_job_ready_head_probe_reaches_the_export_in_seconds() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(&dir.path().join("data"));
    let server = sync_server(Arc::clone(&vault));
    let creds = credentials(0x11, 0x22);
    let ledger = wake_ledger(&vault, &dir.path().join("sup.sock"), &creds);

    // An idle vault asks to be woken for nothing.
    assert!(ledger.export(&server).unwrap().is_empty());

    // A durable queue row is work waiting, so the head of it is due.
    let queue = oneiron::sync::SyncQueue::new(Arc::clone(&vault)).unwrap();
    queue.push("2026-01", b"synthetic-update").unwrap();

    let entries = ledger.export(&server).unwrap();
    validate_wake_entries(&entries).unwrap();
    let job_ready = entries
        .iter()
        .find(|entry| entry.id == "job_ready")
        .expect("a pending queue row must export a job_ready wake");
    match job_ready.at {
        Schedule::Exact { at } => assert!(
            at > 1_600_000_000 && at < 100_000_000_000,
            "wake stamp {at} is not unix seconds"
        ),
        Schedule::Window { .. } => panic!("the job_ready head is due at an instant, not a window"),
    }
}

#[tokio::test]
async fn ledger_rev_persists_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(&dir.path().join("data"));
    let server = sync_server(Arc::clone(&vault));
    let creds = credentials(0x11, 0x22);
    let sup = dir.path().join("sup.sock");

    let ledger = wake_ledger(&vault, &sup, &creds);
    assert_eq!(ledger.rev(), 0);

    let (rev, entries) = ledger.export_at_freeze(&server).await.unwrap();
    assert_eq!(rev, 1);
    validate_wake_entries(&entries).unwrap();

    // The same entries again are not a change, so the revision does not churn.
    let (again, _) = ledger.export_at_freeze(&server).await.unwrap();
    assert_eq!(again, 1);
    drop(ledger);

    // Restart: a new ledger over the same vault resumes the supervisor's
    // ordering instead of replaying it from zero.
    let reloaded = wake_ledger(&vault, &sup, &creds);
    assert_eq!(reloaded.rev(), 1);
    assert_eq!(
        vault.sync_state_get(LEDGER_REV_KEY).unwrap().as_deref(),
        Some(&1u64.to_le_bytes()[..])
    );
}

#[tokio::test]
async fn an_on_change_push_validates_and_honours_the_ack() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(&dir.path().join("data"));
    let server = sync_server(Arc::clone(&vault));
    let creds = credentials(0x11, 0x22);
    let sup = dir.path().join("sup.sock");

    let listener = tokio::net::UnixListener::bind(&sup).unwrap();
    let supervisor = spawn_mock_supervisor(listener, 0, 1);

    let ledger = wake_ledger(&vault, &sup, &creds);
    assert!(
        ledger.push_if_changed(&server).await.unwrap(),
        "the first export is a change"
    );
    assert!(
        !ledger.push_if_changed(&server).await.unwrap(),
        "an unchanged export costs the supervisor nothing"
    );

    let lines = supervisor.await.unwrap();
    assert_eq!(lines.len(), 1, "push-on-change, not push-on-tick");
    let update: LedgerUpdate = serde_json::from_str(&lines[0]).unwrap();
    // What the engine sent must pass the same validator the supervisor runs.
    update.validate().unwrap();
    assert_eq!(update.op, "ledger_update");
    assert_eq!(update.vault, VAULT_NAME);
    assert_eq!(update.rev, 1);
    // The token authenticates the push; it must never reach a diagnostic.
    assert_eq!(format!("{:?}", update.token), "TokenHex(<redacted>)");
    assert!(!format!("{ledger:?}").contains(update.token.expose()));
}

// ---------------------------------------------------------------------------
// E6 — SIGTERM graceful quiesce
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failing_push_is_retried_exactly_once_after_200ms() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(&dir.path().join("data"));
    let creds = credentials(0x11, 0x22);
    let sup = dir.path().join("sup.sock");

    let listener = tokio::net::UnixListener::bind(&sup).unwrap();
    let supervisor = spawn_mock_supervisor(listener, 1, 2);

    let ledger = wake_ledger(&vault, &sup, &creds);
    let started = std::time::Instant::now();
    assert!(ledger.push_with_retry(7, &[]).await);
    let elapsed = started.elapsed();

    assert_eq!(
        supervisor.await.unwrap().len(),
        2,
        "exactly one retry, never a loop"
    );
    assert!(
        elapsed >= Duration::from_millis(200),
        "the retry must wait out the backoff, waited {elapsed:?}"
    );
}

#[tokio::test]
async fn a_supervisor_that_never_acks_does_not_hold_the_exit_open() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(&dir.path().join("data"));
    let creds = credentials(0x11, 0x22);
    let sup = dir.path().join("sup.sock");

    let listener = tokio::net::UnixListener::bind(&sup).unwrap();
    let supervisor = spawn_mock_supervisor(listener, 2, 2);

    let ledger = wake_ledger(&vault, &sup, &creds);
    assert!(
        !ledger.push_with_retry(9, &[]).await,
        "a push nobody acked is not accepted"
    );
    assert_eq!(
        supervisor.await.unwrap().len(),
        2,
        "two attempts, then proceed"
    );
}

/// How long a row waits on a push that must not hang. Far past the engine's own
/// push deadline, so this bound only fails a push that never comes back at all
/// rather than one that is merely slower than the row expected.
const NO_HANG_BOUND: Duration = Duration::from_secs(30);

/// A connected, silent supervisor is the one that used to park this forever.
///
/// The row above covers a supervisor that closes without acking: that is an
/// EOF, and EOF is an answer. This one accepts the connection and then says
/// nothing at all, holding the socket open — so connect, write and the ack read
/// all succeed-or-block rather than fail, and every one of them was unbounded.
/// The opening push sits between the ready byte and the HTTP serve and the
/// final push is the last thing before exit, so parking here is a boot that
/// never serves or an exit that never happens.
#[tokio::test]
async fn a_connected_supervisor_that_never_acks_is_abandoned_on_a_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(&dir.path().join("data"));
    let creds = credentials(0x11, 0x22);
    let sup = dir.path().join("sup.sock");

    let listener = tokio::net::UnixListener::bind(&sup).unwrap();
    // Accepted and held: never read, never acked, never closed.
    let supervisor = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let ledger = wake_ledger(&vault, &sup, &creds);
    let outcome = tokio::time::timeout(NO_HANG_BOUND, ledger.push_once(11, &[]))
        .await
        .expect("a silent supervisor must not hold the push open");
    let Err(error) = outcome else {
        panic!("an unacked push is not a successful one");
    };
    assert!(
        matches!(error, ManagedError::LedgerAckTimeout { .. }),
        "unexpected: {error}"
    );

    // And the retry policy still ends: one retry over the same silence, then
    // proceed without the supervisor.
    let proceeded = tokio::time::timeout(NO_HANG_BOUND, ledger.push_with_retry(11, &[]))
        .await
        .expect("the retry policy must not hold the exit open either");
    assert!(!proceeded, "a push nobody acked is not accepted");

    supervisor.abort();
}

/// The shutdown snapshot has to be rev-ordered, or it is not delivered.
///
/// `LedgerUpdate` is a rev-ordered full replacement, so a supervisor that
/// ignores `rev <= last_acked` — the ordering the contract asks it to keep —
/// drops a final push that reuses the revision it already acked. Boot seals
/// the entries at rev 1; a job that becomes ready with no mid-run push behind
/// it is exactly the case where the last thing this process says is also the
/// only thing that carries the new state.
#[tokio::test]
async fn the_final_push_advances_the_rev_when_the_entries_moved() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(&dir.path().join("data"));
    let server = sync_server(Arc::clone(&vault));
    let creds = credentials(0x11, 0x22);
    let sup = dir.path().join("sup.sock");

    let listener = tokio::net::UnixListener::bind(&sup).unwrap();
    let supervisor = spawn_mock_supervisor(listener, 0, 2);

    let ledger = wake_ledger(&vault, &sup, &creds);
    let state = Arc::new(ManagedState::new(
        VAULT_NAME.to_owned(),
        Arc::clone(&server),
        ledger,
    ));

    // Boot's push: the supervisor acks it and now holds rev 1.
    assert!(
        state.ledger().push_if_changed(&server).await.unwrap(),
        "the opening export is a change"
    );

    // Work arrives and nothing pushes it — the run is over.
    oneiron::sync::SyncQueue::new(Arc::clone(&vault))
        .unwrap()
        .push("2026-01", b"synthetic-update")
        .unwrap();

    final_ledger_push(&state, &server).await;

    let lines = supervisor.await.unwrap();
    assert_eq!(lines.len(), 2, "the final push must reach the supervisor");
    let boot: LedgerUpdate = serde_json::from_str(&lines[0]).unwrap();
    let shutdown: LedgerUpdate = serde_json::from_str(&lines[1]).unwrap();
    assert_ne!(
        shutdown.entries, boot.entries,
        "this row is only meaningful while the shutdown entries differ"
    );
    assert!(
        shutdown.rev > boot.rev,
        "the shutdown snapshot rode rev {} against an acked rev {}, so a \
         rev-ordered supervisor drops it",
        shutdown.rev,
        boot.rev
    );
}

#[tokio::test]
async fn managed_shutdown_closes_ctl_and_leaves_the_inherited_socket_alone() {
    let dir = tempfile::tempdir().unwrap();
    let run = sockets_dir(dir.path());
    let http_path = run.join("http.sock");

    let supervisor_listener = std::os::unix::net::UnixListener::bind(&http_path).unwrap();
    let inode_before = std::fs::metadata(&http_path).unwrap().ino();
    let inherited = supervisor_listener.try_clone().unwrap().into_raw_fd();
    drop(supervisor_listener);
    let bound = ServeListener::InheritedFd(inherited).bind().await.unwrap();

    let fixture = spawn_ctl_fixture();
    // A reap was in flight when the signal landed.
    fixture.state.freeze();
    assert!(fixture.state.guard_write().is_err());

    let shutdown = ManagedShutdown::new();
    let app = axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));
    let signal = shutdown.triggered();
    let served = tokio::spawn(async move { bound.serve_until(app, signal).await });

    shutdown.trigger();
    fixture.shutdown.trigger();
    served.await.unwrap().unwrap();
    fixture.task.await.unwrap();

    // The ctl socket is ours, so it goes.
    assert!(
        !fixture.ctl_path.exists(),
        "ctl.sock is this process's own path and must be removed"
    );
    // The HTTP socket is the supervisor's, so it stays, unchanged.
    assert!(http_path.exists());
    assert_eq!(std::fs::metadata(&http_path).unwrap().ino(), inode_before);

    // An interrupted reap must not outlive the process that started it.
    fixture.state.unfreeze();
    fixture.state.guard_write().unwrap();
    drop(fixture.server);
}

#[tokio::test]
async fn shutdown_is_observed_even_when_it_lands_before_anyone_subscribes() {
    let shutdown = ManagedShutdown::new();
    assert!(!shutdown.is_triggered());
    shutdown.trigger();
    assert!(shutdown.is_triggered());

    // Subscribing after the fact still resolves: a listener spawned during the
    // shutdown window must not keep serving because it missed the edge.
    tokio::time::timeout(Duration::from_secs(5), shutdown.triggered())
        .await
        .expect("a late subscriber must still observe the trigger");
}

#[tokio::test]
async fn the_sigterm_handler_installs_without_firing() {
    let shutdown = ManagedShutdown::new();
    spawn_sigterm_shutdown(shutdown.clone()).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !shutdown.is_triggered(),
        "installing the handler must not trip shutdown by itself"
    );
}

// ---------------------------------------------------------------------------
// Spawn order — the ready byte is the supervisor's only evidence
// ---------------------------------------------------------------------------

/// A managed boot rooted at `root`, with real descriptors for the two fds.
fn managed_boot_args(root: &Path) -> (ServeArgs, PathBuf) {
    let ready_path = root.join("ready");
    let credentials_path = root.join("creds");
    let mut frame = Vec::new();
    write_credentials(&mut frame, &[0x11; DEK_LEN], &[0x22; TOKEN_LEN]).unwrap();

    let mut args = parse_serve(&managed_argv(root));
    args.credentials_fd = Some(fd_over_bytes(&credentials_path, &frame));
    args.ready_fd = Some(std::fs::File::create(&ready_path).unwrap().into_raw_fd());
    (args, ready_path)
}

#[tokio::test]
async fn ready_byte_lands_only_after_sockets_credentials_and_gates() {
    let dir = tempfile::tempdir().unwrap();
    let run = sockets_dir(dir.path());

    // A markerless vault: the open gates refuse, so the boot never reaches the
    // ready byte. Seed and release it so the managed open gets the env.
    drop(open_vault(&run.join("data")));

    let (args, ready_path) = managed_boot_args(&run);
    let managed = ManagedArgs::from_serve_args(&args).unwrap().unwrap();
    let error = serve_managed(&args, managed).await.unwrap_err();

    assert!(
        error.to_string().contains("tripwire"),
        "unexpected: {error}"
    );
    assert!(
        std::fs::read(&ready_path).unwrap().is_empty(),
        "no ready byte may be written before the open gates pass"
    );
    assert!(
        !run.join("ctl.sock").exists(),
        "ctl.sock is bound after the gates, not before"
    );
}

#[tokio::test]
async fn a_canary_vault_boots_managed_and_signals_ready() {
    let dir = tempfile::tempdir().unwrap();
    let run = sockets_dir(dir.path());

    {
        let vault = open_vault(&run.join("data"));
        vault
            .sync_state_put(CANARY_MARKER_KEY, CANARY_MARKER_VALUE)
            .unwrap();
    }

    let (args, ready_path) = managed_boot_args(&run);
    let managed = ManagedArgs::from_serve_args(&args).unwrap().unwrap();
    let boot = tokio::spawn(async move { serve_managed(&args, managed).await });

    wait_for_ready(&ready_path).await;
    // The byte means all three held, so all three are checked at the moment it
    // landed rather than eventually.
    assert!(
        run.join("http.sock").exists(),
        "http socket bound before ready"
    );
    assert!(
        run.join("ctl.sock").exists(),
        "ctl socket bound before ready"
    );

    match ctl_response(&ctl_roundtrip(&run.join("ctl.sock"), r#"{"op":"ping"}"#).await) {
        CtlResponse::Ping {
            ok,
            vault,
            contract_version,
            ..
        } => {
            assert!(ok);
            assert_eq!(vault, VAULT_NAME);
            assert_eq!(contract_version, CONTRACT_VERSION);
        }
        other => panic!("expected a ping reply, got {other:?}"),
    }

    // Serving over the self-bound socket: managed mode needs no auth secret,
    // because bearer auth terminates at the supervisor.
    let response = http_get_over_unix(&run.join("http.sock"), "/health").await;
    assert!(
        response.starts_with("HTTP/1.1 "),
        "the managed listener must answer HTTP: {response}"
    );

    boot.abort();
}

/// The reap freeze, on the surface the supervisor actually routes traffic to.
///
/// A `guard_write()` call on a fixture proves the gate refuses. It does not
/// prove that anything asks it to, and those two states are indistinguishable
/// from the object side — which is how the freeze shipped enforcing nothing.
/// Only a real write over the real socket separates them, so this row boots
/// `serve_managed`, writes over the served HTTP path, and drives the freeze
/// through the real ctl verbs. Without the gate on that path, `quiescent: true`
/// is advisory: the engine keeps committing durable writes after telling the
/// supervisor it stopped.
#[tokio::test]
async fn a_served_write_is_refused_while_frozen_and_accepted_again_after_abort() {
    let dir = tempfile::tempdir().unwrap();
    let run = sockets_dir(dir.path());
    {
        let vault = open_vault(&run.join("data"));
        vault
            .sync_state_put(CANARY_MARKER_KEY, CANARY_MARKER_VALUE)
            .unwrap();
    }

    let (args, ready_path) = managed_boot_args(&run);
    let managed = ManagedArgs::from_serve_args(&args).unwrap().unwrap();
    let boot = tokio::spawn(async move { serve_managed(&args, managed).await });
    wait_for_ready(&ready_path).await;

    let http = run.join("http.sock");
    let ctl = run.join("ctl.sock");
    let before = probe_entity_id(0x01);
    let during = probe_entity_id(0x02);

    // Unfrozen, the served write path commits for real — the entity reads back
    // — so the refusal below is a change of behaviour rather than a surface
    // that never worked in the first place.
    let accepted = http_over_unix(&http, &conversation_write(&before)).await;
    assert!(accepted.starts_with("HTTP/1.1 200 OK"), "{accepted}");
    let read_back = http_get_over_unix(&http, &format!("/api/entity/{before}")).await;
    assert!(read_back.starts_with("HTTP/1.1 200 OK"), "{read_back}");

    // The supervisor asks for quiescence.
    match ctl_response(&ctl_roundtrip(&ctl, r#"{"op":"prepare_reap"}"#).await) {
        CtlResponse::PrepareReap { quiescent, .. } => {
            assert!(quiescent, "an idle canary vault reports quiescent");
        }
        other => panic!("expected a prepare_reap reply, got {other:?}"),
    }

    // The same write, over the same socket, now gets the typed refusal.
    let refused = http_over_unix(&http, &conversation_write(&during)).await;
    assert!(
        refused.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{refused}"
    );
    assert!(refused.contains(WRITES_FROZEN_TAG), "{refused}");
    assert!(
        refused.contains(&ManagedError::WritesFrozen.to_string()),
        "the served refusal must carry the typed error, not a lookalike: {refused}"
    );
    // Never a silent accept: nothing was committed under that id.
    let absent = http_get_over_unix(&http, &format!("/api/entity/{during}")).await;
    assert!(absent.starts_with("HTTP/1.1 404"), "{absent}");
    // The sync socket is a write path too. Its frames ride past every
    // per-request gate, so a frozen engine refuses the handshake itself.
    let upgrade = http_over_unix(&http, WS_UPGRADE_REQUEST).await;
    assert!(upgrade.contains(WRITES_FROZEN_TAG), "{upgrade}");
    // Reads are not writes: a frozen engine still answers them.
    let health = http_get_over_unix(&http, "/api/health").await;
    assert!(health.starts_with("HTTP/1.1 200 OK"), "{health}");

    // An aborted reap hands the write path back.
    match ctl_response(&ctl_roundtrip(&ctl, r#"{"op":"reap_abort"}"#).await) {
        CtlResponse::Ok { ok } => assert!(ok),
        other => panic!("expected an ok reply, got {other:?}"),
    }
    let accepted = http_over_unix(&http, &conversation_write(&during)).await;
    assert!(accepted.starts_with("HTTP/1.1 200 OK"), "{accepted}");
    let read_back = http_get_over_unix(&http, &format!("/api/entity/{during}")).await;
    assert!(read_back.starts_with("HTTP/1.1 200 OK"), "{read_back}");

    boot.abort();
}

/// A session upgraded before the freeze is a writer the freeze cannot reach.
///
/// The per-request gate refuses new POSTs and new handshakes, and neither
/// touches a sync session that was already open: its frames arrive on a socket
/// no middleware runs over, and `prepare_reap` is not shutdown — it closes
/// nothing. So `quiescent: true` with one of those still live is the same
/// broken promise the freeze exists to prevent, just one connection earlier.
/// This row opens the session first, then asks.
#[tokio::test]
async fn a_sync_session_upgraded_before_the_freeze_denies_quiescence() {
    let dir = tempfile::tempdir().unwrap();
    let run = sockets_dir(dir.path());
    {
        let vault = open_vault(&run.join("data"));
        vault
            .sync_state_put(CANARY_MARKER_KEY, CANARY_MARKER_VALUE)
            .unwrap();
    }

    let (args, ready_path) = managed_boot_args(&run);
    let managed = ManagedArgs::from_serve_args(&args).unwrap().unwrap();
    let boot = tokio::spawn(async move { serve_managed(&args, managed).await });
    wait_for_ready(&ready_path).await;

    let http = run.join("http.sock");
    let ctl = run.join("ctl.sock");

    // Unfrozen, the handshake is accepted: the session exists before there is
    // any freeze to refuse it. A refusal here would make the assertion below
    // pass for the wrong reason.
    let upgrade = http_over_unix(&http, WS_UPGRADE_REQUEST).await;
    assert!(
        upgrade.starts_with("HTTP/1.1 101"),
        "the pre-freeze handshake must be admitted: {upgrade}"
    );

    match ctl_response(&ctl_roundtrip(&ctl, r#"{"op":"prepare_reap"}"#).await) {
        CtlResponse::PrepareReap {
            quiescent,
            ledger_rev,
            ..
        } => {
            assert!(
                !quiescent,
                "a sync session upgraded before the freeze can still commit, so this is not quiescent"
            );
            // The freeze still happened and the ledger still exported: this is
            // a narrower claim, not a failed verb.
            assert!(ledger_rev >= 1, "the freeze still exports a revision");
        }
        other => panic!("expected a prepare_reap reply, got {other:?}"),
    }

    boot.abort();
}

/// The ready byte is exactly the contract's byte, not a newline or a length.
#[test]
fn signal_ready_writes_the_contract_byte() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ready");
    let fd = std::fs::File::create(&path).unwrap().into_raw_fd();
    signal_ready(fd).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), vec![READY_BYTE]);
}
