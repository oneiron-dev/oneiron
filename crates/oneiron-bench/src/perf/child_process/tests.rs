//! ONE-1579 / ONE-1963 ready-child regressions: the readiness boundary, the
//! bounded shutdown path, and the digest and refusal that make a full run's
//! ready child the artifact it was built from.

use super::*;

fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn immediate_program() -> Option<PathBuf> {
    first_existing(&["/bin/true", "/usr/bin/true"])
}

/// The program that will actually be spawned is hashed BEFORE any spawn,
/// including a plan-supplied one — otherwise the ready-children axis could
/// not say which binary held the ten vaults.
#[test]
fn the_program_that_will_be_spawned_is_hashed_before_the_first_spawn() {
    let Some(program) = immediate_program() else {
        if cfg!(target_os = "linux") {
            panic!("a linux host must provide `true` for the child-digest regression");
        }
        return;
    };
    let plan = ChildCommandPlan {
        program: program.display().to_string(),
        args: Vec::new(),
    };
    let resolved = resolve_and_hash_child_program(RunMode::SyntheticSmoke, Some(&plan))
        .expect("a smoke may name its own child program");

    assert_eq!(resolved.path.as_deref(), Some(program.as_path()));
    assert!(
        !resolved.harness_owned,
        "a plan-supplied program is not the harness's own child"
    );
    let digest = resolved
        .blake3
        .value()
        .expect("the resolved program is hashed");
    assert_eq!(digest.len(), 64, "blake3 renders as 64 hex characters");
    assert_eq!(
        digest,
        &super::super::git_sha::hash_file_blake3(&program).expect("the program hashes"),
        "the certificate digest must be blake3 over the program's exact bytes"
    );

    // An unresolvable program is `not_ready` with its reason, never a
    // silently absent digest.
    let missing = ChildCommandPlan {
        program: "/nonexistent/oneiron-bench-child".to_owned(),
        args: Vec::new(),
    };
    let resolved = resolve_and_hash_child_program(RunMode::SyntheticSmoke, Some(&missing))
        .expect("resolution itself still succeeds");
    assert!(!resolved.blake3.is_measured());
    assert!(matches!(resolved.blake3, Cell::NotReady { .. }));
}
