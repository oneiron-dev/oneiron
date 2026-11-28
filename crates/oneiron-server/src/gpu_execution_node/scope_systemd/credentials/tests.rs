//! The tests of job credentials (FIX NODE-JOB-CREDENTIALS): T1 to T10 of its
//! PLAN, on files under /tmp owned by the test's own account.

use std::os::unix::fs::{PermissionsExt as _, symlink};

use super::*;
use crate::gpu_execution_node::scope_systemd::unit_file::{
    UnitInputs, render_control_service, render_job_unit, sandbox_properties,
};

/// A job instance: 32 lower-hex digits.
const INSTANCE: &str = "0123456789abcdef0123456789abcdef";

/// That instance's unit.
const UNIT: &str = "oneiron-job@0123456789abcdef0123456789abcdef.service";

/// The issuer every node file here names.
const ISSUER: &str = "5d1e3c8a9b7f4e21a0c6d2b8f3e9a714";

/// One credential line for the template `probe`.
const TOKEN: &str = r#"credentials = { token = "/etc/oneiron/credentials/probe/token" }"#;

/// A second template that does not require the file wall.
const UNWALLED: &str = r#"
[execution_node.templates.other]
repo = "/srv/git/other.git"
entries = ["run.sh"]
interpreter = ["/usr/bin/bash"]
max_secs = 600
memory_gib = 8
disk_gib = 4
require = ["network_closed"]
"#;

/// A node file: `node_extra` in `[execution_node]`, and the template
/// `probe` with `probe_extra` in its table.
fn node_text(node_extra: &str, probe_extra: &str) -> String {
    format!(
        r#"[execution_node]
enabled = true
issuers = ["{ISSUER}"]
state_dir = "/var/lib/oneiron/jobs"
work_dir = "/data/oneiron-jobs"
{node_extra}

[execution_node.templates.probe]
repo = "/srv/git/probe.git"
entries = ["tools/*.sh"]
interpreter = ["/usr/bin/bash"]
max_secs = 600
memory_gib = 8
disk_gib = 4
{probe_extra}
"#
    )
}

fn settings(text: &str) -> ExecutionNodeSettings {
    ExecutionNodeSettings::parse(text).expect("the node file")
}

fn me() -> (u32, u32) {
    // SAFETY: geteuid and getegid have no preconditions.
    unsafe { (libc::geteuid(), libc::getegid()) }
}

/// A directory under /tmp: the file check walks the whole path, and
/// /tmp is root's (sticky) on every Linux test host.
fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("oneiron-credentials-test")
        .tempdir_in("/tmp")
        .expect("a directory under /tmp")
}

fn write_file(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("a file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("its mode");
    path
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .expect("the path")
        .permissions()
        .mode()
        & 0o7777
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("the directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn credentials(pairs: &[(&str, &PathBuf)]) -> BTreeMap<String, PathBuf> {
    pairs
        .iter()
        .map(|(name, path)| ((*name).to_owned(), (*path).clone()))
        .collect()
}

fn inputs() -> UnitInputs {
    UnitInputs {
        binary: "/usr/bin/oneiron".into(),
        node_file: "/etc/oneiron/execution-node.toml".into(),
        engine_account: "oneiron".to_owned(),
        job_account: "oneiron-job".to_owned(),
        state_dir: "/var/lib/oneiron/jobs".into(),
        work_dir: "/data/oneiron-jobs".into(),
        protected: vec!["/var/lib/oneiron".into()],
        runtime_max_secs: 172_800,
        stop_grace_secs: 10,
        start_timeout_secs: 60,
    }
}

// T1
#[test]
fn a_template_without_credentials_keeps_its_digest_and_naming_a_file_changes_it() {
    let digest = |probe_extra: &str| {
        settings(&node_text("", probe_extra)).templates["probe"]
            .digest()
            .expect("a digest")
    };
    let plain = digest("");
    assert_eq!(plain, digest("credentials = {}"));
    assert_ne!(plain, digest(TOKEN));
}

// T2
#[test]
fn the_node_file_refuses_a_credential_name_or_path_it_cannot_hold() {
    let long = "n".repeat(65);
    let cases = [
        (r#"token = "etc/oneiron/token""#.to_owned(), "absolute path"),
        (r#"token = "/etc/oneiron/../shadow""#.to_owned(), "no '..'"),
        (
            r#""a/b" = "/etc/oneiron/token""#.to_owned(),
            "must be 1 to 64",
        ),
        (
            r#"".." = "/etc/oneiron/token""#.to_owned(),
            "must be 1 to 64",
        ),
        (r#""" = "/etc/oneiron/token""#.to_owned(), "must be 1 to 64"),
        (
            format!(r#"{long} = "/etc/oneiron/token""#),
            "must be 1 to 64",
        ),
        // The service manager skips a dot file of the staged directory.
        (
            r#"".token" = "/etc/oneiron/token""#.to_owned(),
            "not starting with '.'",
        ),
    ];
    for (credential, why) in cases {
        let text = node_text("", &format!("credentials = {{ {credential} }}"));
        let refused = ExecutionNodeSettings::parse(&text).expect_err(&credential);
        assert!(
            refused.starts_with("execution_node.templates.probe: credentials")
                && refused.contains(why),
            "{credential}: {refused}"
        );
    }
}

// T3
#[test]
fn the_job_unit_loads_the_staged_directory_and_the_handler_holds_it() {
    let unit = render_job_unit(&inputs());
    assert!(
        unit.contains("\nLoadCredential=job:/run/oneiron-credentials/%i\n"),
        "{unit}"
    );
    assert!(unit_loads_credentials(&unit));
    // The probe unit of `execution-node check` loads nothing.
    assert!(
        sandbox_properties(&inputs(), "%i")
            .iter()
            .all(|(name, _)| name != "LoadCredential")
    );
    let service = render_control_service(&inputs());
    assert!(
        service.contains(
            "\nRuntimeDirectory=oneiron-credentials\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n"
        ),
        "{service}"
    );
    assert!(control_service_stages(&service));
    // A unit and a handler written before credentials.
    let before: String = unit
        .lines()
        .filter(|line| !line.starts_with("LoadCredential="))
        .map(|line| format!("{line}\n"))
        .collect();
    assert!(!unit_loads_credentials(&before));
    assert!(!control_service_stages(
        &service.replace("RuntimeDirectory=oneiron-credentials\n", "")
    ));
}

// T4
#[test]
fn staging_copies_each_named_file_owner_only_into_a_fresh_directory() {
    let (uid, gid) = me();
    let sources = scratch();
    let root = scratch();
    let token = write_file(sources.path(), "token", b"secret-one", 0o400);
    let second = write_file(sources.path(), "second", b"secret-two\n", 0o600);
    // A copy left from an earlier start goes first.
    std::fs::create_dir(root.path().join(INSTANCE)).expect("an old copy");
    write_file(&root.path().join(INSTANCE), "stale", b"old", 0o400);
    let dir = fresh_dir(root.path(), INSTANCE, (uid, gid)).expect("the staged directory");
    let skipped = copy_into(
        borrow(&dir),
        &credentials(&[("token", &token), ("second", &second)]),
        uid,
        (uid, gid),
    );
    assert!(skipped.is_empty(), "{skipped:?}");
    let staged = root.path().join(INSTANCE);
    assert_eq!(mode(&staged), 0o700);
    assert_eq!(listing(&staged), ["second", "token"]);
    for (name, bytes) in [
        ("token", &b"secret-one"[..]),
        ("second", &b"secret-two\n"[..]),
    ] {
        assert_eq!(std::fs::read(staged.join(name)).expect("the copy"), bytes);
        assert_eq!(mode(&staged.join(name)), 0o400, "{name}");
    }
}

// T5
#[test]
fn staging_leaves_out_an_open_file_a_link_and_a_file_past_the_cap_and_says_why() {
    let (uid, gid) = me();
    let sources = scratch();
    let root = scratch();
    let cap = usize::try_from(CREDENTIALS_TOTAL_BYTES_MAX).expect("the cap");
    let open = write_file(sources.path(), "open", b"x", 0o640);
    let real = write_file(sources.path(), "real", b"x", 0o400);
    let link = sources.path().join("link");
    symlink(&real, &link).expect("a link");
    let big = write_file(sources.path(), "big", &vec![b'x'; cap + 1], 0o400);
    let dir = fresh_dir(root.path(), INSTANCE, (uid, gid)).expect("the staged directory");
    let skipped = copy_into(
        borrow(&dir),
        &credentials(&[("big", &big), ("link", &link), ("open", &open)]),
        uid,
        (uid, gid),
    );
    assert_eq!(skipped.len(), 3, "{skipped:?}");
    assert!(
        skipped[0].starts_with("big: ") && skipped[0].contains("past the"),
        "{skipped:?}"
    );
    assert!(
        skipped[1].starts_with("link: ") && skipped[1].contains("a link"),
        "{skipped:?}"
    );
    assert!(
        skipped[2].starts_with("open: ") && skipped[2].contains("gives group or others access"),
        "{skipped:?}"
    );
    assert!(listing(&root.path().join(INSTANCE)).is_empty());
    // The cap holds for a job's files together.
    let first = write_file(sources.path(), "first", &vec![b'a'; cap / 2 + 1], 0o400);
    let then = write_file(sources.path(), "then", &vec![b'b'; cap / 2 + 1], 0o400);
    let dir = fresh_dir(root.path(), INSTANCE, (uid, gid)).expect("the staged directory");
    let skipped = copy_into(
        borrow(&dir),
        &credentials(&[("first", &first), ("then", &then)]),
        uid,
        (uid, gid),
    );
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    assert!(
        skipped[0].starts_with("then: ") && skipped[0].contains("past the"),
        "{skipped:?}"
    );
    assert_eq!(listing(&root.path().join(INSTANCE)), ["first"]);
}

// T6
#[test]
fn a_template_with_no_credential_stages_an_empty_directory() {
    let (uid, gid) = me();
    let root = scratch();
    let dir = fresh_dir(root.path(), INSTANCE, (uid, gid)).expect("the staged directory");
    assert!(copy_into(borrow(&dir), &BTreeMap::new(), uid, (uid, gid)).is_empty());
    let staged = root.path().join(INSTANCE);
    assert!(staged.is_dir());
    assert!(listing(&staged).is_empty());
}

// T7
#[test]
fn prepare_refuses_a_credential_the_service_manager_did_not_load_and_names_it() {
    let (uid, _) = me();
    let sources = scratch();
    let loaded = scratch();
    let token = write_file(sources.path(), "token", b"one", 0o400);
    let open = write_file(sources.path(), "open", b"two", 0o644);
    let again = write_file(sources.path(), "again", b"three", 0o400);
    write_file(loaded.path(), "job_token", b"one", 0o400);
    assert_eq!(
        check_loaded(loaded.path(), &credentials(&[("token", &token)]), uid),
        Ok(())
    );
    let why = check_loaded(
        loaded.path(),
        &credentials(&[("open", &open), ("token", &token)]),
        uid,
    )
    .expect_err("open was not loaded");
    assert!(
        why.starts_with("credential_not_loaded: open: ")
            && why.contains("gives group or others access"),
        "{why}"
    );
    // A file that passes its check but was not loaded is named too.
    let why = check_loaded(
        loaded.path(),
        &credentials(&[("again", &again), ("token", &token)]),
        uid,
    )
    .expect_err("again was not loaded");
    assert!(
        why.starts_with("credential_not_loaded: again: ") && why.contains("job_again is not there"),
        "{why}"
    );
}

// T8
#[test]
fn the_workload_gets_the_loaded_directory_only_with_credentials() {
    let named = settings(&node_text("", TOKEN));
    let plain = settings(&node_text("", ""));
    let mut env = BTreeMap::from([("PATH".to_owned(), "/usr/bin".to_owned())]);
    let mut read = vec![PathBuf::from("/usr")];
    grant_exec(&mut env, &mut read, UNIT, &plain.templates["probe"]);
    assert_eq!(env.len(), 1);
    assert_eq!(read, [PathBuf::from("/usr")]);
    grant_exec(&mut env, &mut read, UNIT, &named.templates["probe"]);
    let dir = "/run/credentials/oneiron-job@0123456789abcdef0123456789abcdef.service";
    assert_eq!(
        env.get("CREDENTIALS_DIRECTORY").map(String::as_str),
        Some(dir)
    );
    assert_eq!(read, [PathBuf::from("/usr"), PathBuf::from(dir)]);
}

// T9
#[test]
fn withdraw_removes_the_staged_copy_and_passes_when_it_is_gone() {
    let (uid, gid) = me();
    let sources = scratch();
    let root = scratch();
    let token = write_file(sources.path(), "token", b"secret", 0o400);
    let dir = fresh_dir(root.path(), INSTANCE, (uid, gid)).expect("the staged directory");
    assert!(
        copy_into(
            borrow(&dir),
            &credentials(&[("token", &token)]),
            uid,
            (uid, gid)
        )
        .is_empty()
    );
    drop(dir);
    assert_eq!(withdraw_at(root.path(), INSTANCE), Ok(()));
    assert!(!root.path().join(INSTANCE).exists());
    assert_eq!(withdraw_at(root.path(), INSTANCE), Ok(()));
    // A name that is not a job instance removes nothing.
    assert!(withdraw_at(root.path(), "").is_err());
    assert!(root.path().is_dir());
}

// T10
#[test]
fn a_credentialed_job_needs_every_template_of_the_node_walled() {
    let unwalled = settings(&(node_text("", TOKEN) + UNWALLED));
    let why = walled_node(&unwalled).expect_err("other has no wall");
    assert!(
        why.starts_with("credentials_need_walled_node: template other "),
        "{why}"
    );
    assert_eq!(
        check_for_launch(&unwalled, &unwalled.templates["probe"], UNIT, ""),
        Err(why)
    );
    // A template that names no credential is not held by the guard.
    let plain = settings(&(node_text("", "") + UNWALLED));
    assert_eq!(
        check_for_launch(&plain, &plain.templates["probe"], UNIT, ""),
        Ok(Vec::new())
    );
    // The owner turns the guard off on a node that runs one job at a time.
    let off = settings(&(node_text("credentials_need_walled_node = false", TOKEN) + UNWALLED));
    assert_eq!(walled_node(&off), Ok(()));
    // Walled: the other template keeps the default `require`, which has
    // the file wall. Past the guard, a unit installed before credentials
    // is refused.
    let walled = settings(
        &(node_text("", TOKEN) + &UNWALLED.replace("require = [\"network_closed\"]\n", "")),
    );
    assert_eq!(walled_node(&walled), Ok(()));
    let outdated = check_for_launch(&walled, &walled.templates["probe"], UNIT, "")
        .expect_err("no LoadCredential line");
    assert!(outdated.starts_with("template_outdated: "), "{outdated}");
    assert!(
        install_lines(&walled, "probe")[0]
            .starts_with("template probe credential token /etc/oneiron/credentials/probe/token: ")
    );
    assert!(
        install_lines(&unwalled, "probe")
            .last()
            .is_some_and(|line| line.starts_with("template probe: credentials_need_walled_node: "))
    );
}
