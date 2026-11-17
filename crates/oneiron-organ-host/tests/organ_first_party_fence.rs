//! A first-party organ starts inside the filesystem fence where the host
//! has one (FIX [FIRST-PARTY-ORGAN-PROC-REACH], ARCH-0075). It runs as the
//! engine's own uid, so unfenced it could read the engine's environment
//! through `/proc/<pid>/environ`, open the engine's OOM score to raise it,
//! and open the vault's files. Fenced, it opens its program and the null
//! device and none of those. Linux only, on a host with Landlock ABI 3:
//! elsewhere a first-party organ starts unfenced, and the test says it
//! skipped.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use oneiron::{Vault, VaultConfig};
use oneiron_organ_host::{CallClass, HostConfig, OrganCall, OrganHost, OrganSpec};
use oneiron_organ_protocol::Value;

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-organ-probe");

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    (dir, vault)
}

/// The probe's opener (`--open-paths`) as a first-party organ.
fn opener() -> OrganSpec {
    let mut spec = OrganSpec::first_party("probe", PROBE);
    spec.args = vec!["--open-paths".into()];
    spec.verbs = vec!["probe.open".to_owned()];
    spec
}

fn host(spec: OrganSpec) -> OrganHost {
    let host = OrganHost::new(HostConfig::default());
    host.install(spec);
    host
}

/// What the organ's open of each `(path, write)` answered: 0, or the errno
/// that refused it.
fn opens(host: &OrganHost, vault: &Vault, paths: &[(String, bool)]) -> Vec<i64> {
    let paths = paths
        .iter()
        .map(|(path, write)| {
            Value::Map(vec![
                ("path".into(), path.as_str().into()),
                ("write".into(), (*write).into()),
            ])
        })
        .collect::<Vec<_>>();
    let call = OrganCall {
        organ: "probe".into(),
        verb: "probe.open".into(),
        schema: 1,
        args: Value::Map(vec![("paths".into(), Value::Array(paths))]),
        body: None,
        inputs: Vec::new(),
        class: CallClass::Agent,
        deadline: Duration::from_secs(10),
        grant: "g".into(),
    };
    let outcome = host.call(vault, call).expect("the organ answers");
    outcome
        .report
        .as_array()
        .expect("one answer for each path")
        .iter()
        .map(|errno| errno.as_i64().expect("an errno"))
        .collect()
}

/// Every regular file under `dir`.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("read the vault dir") {
            let entry = entry.expect("a vault dir entry");
            let kind = entry.file_type().expect("its file type");
            if kind.is_dir() {
                dirs.push(entry.path());
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
    }
    files
}

/// Whether this host fences a first-party organ; says so where it does not.
fn fenced_here() -> bool {
    let fenced = oneiron_organ_host::filesystem_confined();
    if !fenced {
        eprintln!(
            "SKIPPED: this host has no Landlock ABI 3, so a first-party organ starts unfenced here"
        );
    }
    fenced
}

#[test]
fn a_first_party_organ_opens_no_proc_entry_and_no_vault_file_of_the_engine() {
    if !fenced_here() {
        return;
    }
    let (dir, vault) = vault();
    let host = host(opener());
    // What its fence lets it open: its own program, and the null device its
    // stdio is.
    let allowed = [(PROBE.to_owned(), false), ("/dev/null".to_owned(), true)];
    assert_eq!(
        opens(&host, &vault, &allowed),
        [0, 0],
        "the organ opens what its fence lets it",
    );
    // The engine here is this test process: the organ is its child, under
    // its uid.
    let engine = std::process::id();
    let mut theirs = vec![
        (format!("/proc/{engine}/environ"), false),
        (format!("/proc/{engine}/oom_score_adj"), true),
    ];
    let files = files_under(dir.path());
    assert!(
        !files.is_empty(),
        "the vault keeps files under {}",
        dir.path().display(),
    );
    for file in files {
        let file = file.to_string_lossy().into_owned();
        theirs.push((file.clone(), false));
        theirs.push((file, true));
    }
    assert_eq!(
        opens(&host, &vault, &theirs),
        vec![i64::from(libc::EACCES); theirs.len()],
        "the organ's fence refuses each of the engine's files and /proc entries: {theirs:?}",
    );
}

#[test]
fn a_first_party_organ_writes_the_dirs_its_spec_grants_and_no_other() {
    if !fenced_here() {
        return;
    }
    let (_dir, vault) = vault();
    let granted = tempfile::tempdir().expect("granted dir");
    let other = tempfile::tempdir().expect("other dir");
    let mut spec = opener();
    spec.write_dirs = vec![granted.path().to_owned()];
    let host = host(spec);
    let made = granted.path().join("made");
    let planted = other.path().join("planted");
    let paths = [
        (made.to_string_lossy().into_owned(), true),
        (planted.to_string_lossy().into_owned(), true),
        (other.path().to_string_lossy().into_owned(), false),
    ];
    assert_eq!(
        opens(&host, &vault, &paths),
        [0, i64::from(libc::EACCES), i64::from(libc::EACCES)],
        "the organ makes a file in the dir its spec grants, and none elsewhere: {paths:?}",
    );
    assert!(made.is_file(), "the granted dir holds the organ's file");
    assert!(
        !planted.exists(),
        "the other dir holds nothing of the organ's"
    );
}
