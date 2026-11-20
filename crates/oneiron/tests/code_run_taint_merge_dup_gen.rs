//! CODE-RUN-TAINT-MERGE-DUP-GEN: a code run that stores a result over
//! sources tainted by two generations of one secret is not refused. The
//! merged taint keeps one ref per secret, at the lowest generation seen (the
//! fail-closed direction, as the exhaust and BYOA unions do).
//!
//! Red on main: the merge dedupes by whole-ref equality, so both generations
//! enter and the taint-ref check refuses `duplicate secret_ref in taint
//! refs`. Green with the fix: the inherit succeeds and the stored refs hold
//! the one secret once, at generation 1.
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test code_run_taint_merge_dup_gen`.
#![cfg(oneiron_test_support)]

use oneiron::code_run::CodeRunRawOutput;
use oneiron::secret_lease::SecretTaintRef;
use oneiron::test_doors::code_run_taint_merge::inherit_result_marks;
use oneiron::{EntityId, Result, Vault, VaultConfig};

/// One taint ref over `name` at `generation`.
fn taint(name: &str, generation: u32) -> SecretTaintRef {
    SecretTaintRef {
        secret_ref: name.to_owned(),
        generation,
    }
}

/// A fresh vault with an owner run and two source runs. The `[seed; 16]` ids
/// avoid the pinned bytes a fresh vault already holds.
fn fixture() -> (tempfile::TempDir, Vault, EntityId, EntityId, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = EntityId::from_bytes([0xC1; 16]).expect("owner id");
    let first = EntityId::from_bytes([0xC2; 16]).expect("first source id");
    let second = EntityId::from_bytes([0xC3; 16]).expect("second source id");
    (dir, vault, owner, first, second)
}

/// Two generations of one secret across two sources merge to one ref at the
/// lowest generation instead of refusing the store.
#[test]
fn merge_across_a_rotation_keeps_one_ref_at_the_lowest_generation() -> Result<()> {
    let (_dir, vault, owner, first, second) = fixture();

    let first_raw = b"first source body";
    let second_raw = b"second source body";
    let merged_raw = b"merged body";
    let first_output = CodeRunRawOutput::from_bytes("outputs/first.txt", first_raw)?;
    let second_output = CodeRunRawOutput::from_bytes("outputs/second.txt", second_raw)?;
    let merged_output = CodeRunRawOutput::from_bytes("outputs/merged.txt", merged_raw)?;
    vault.put_code_run_raw_output_tainted(
        Some(first),
        &first_output,
        first_raw,
        &[taint("cabinet", 1)],
    )?;
    vault.put_code_run_raw_output_tainted(
        Some(second),
        &second_output,
        second_raw,
        &[taint("cabinet", 2)],
    )?;
    vault.put_code_run_raw_output(Some(owner), &merged_output, merged_raw)?;

    inherit_result_marks(
        &vault,
        owner,
        &merged_output,
        &[(first, first_output), (second, second_output)],
    )?;

    assert_eq!(
        vault.code_run_raw_output_taint_refs(Some(owner), &merged_output)?,
        vec![taint("cabinet", 1)],
    );
    Ok(())
}

/// An older generation arriving over a newer stored one lowers the stored
/// ref: the merge persists a generation change, not only a longer list.
#[test]
fn merge_lowers_a_stored_newer_generation() -> Result<()> {
    let (_dir, vault, owner, first, _second) = fixture();

    let first_raw = b"first source body";
    let merged_raw = b"merged body";
    let first_output = CodeRunRawOutput::from_bytes("outputs/first.txt", first_raw)?;
    let merged_output = CodeRunRawOutput::from_bytes("outputs/merged.txt", merged_raw)?;
    vault.put_code_run_raw_output_tainted(
        Some(first),
        &first_output,
        first_raw,
        &[taint("cabinet", 1)],
    )?;
    vault.put_code_run_raw_output_tainted(
        Some(owner),
        &merged_output,
        merged_raw,
        &[taint("cabinet", 2)],
    )?;

    inherit_result_marks(&vault, owner, &merged_output, &[(first, first_output)])?;

    assert_eq!(
        vault.code_run_raw_output_taint_refs(Some(owner), &merged_output)?,
        vec![taint("cabinet", 1)],
    );
    Ok(())
}

/// Distinct secrets still union: the per-secret merge drops no secret. This
/// control passes on main as well as with the fix.
#[test]
fn merge_of_distinct_secrets_keeps_every_ref() -> Result<()> {
    let (_dir, vault, owner, first, second) = fixture();

    let first_raw = b"first source body";
    let second_raw = b"second source body";
    let merged_raw = b"merged body";
    let first_output = CodeRunRawOutput::from_bytes("outputs/first.txt", first_raw)?;
    let second_output = CodeRunRawOutput::from_bytes("outputs/second.txt", second_raw)?;
    let merged_output = CodeRunRawOutput::from_bytes("outputs/merged.txt", merged_raw)?;
    vault.put_code_run_raw_output_tainted(
        Some(first),
        &first_output,
        first_raw,
        &[taint("cabinet", 1)],
    )?;
    vault.put_code_run_raw_output_tainted(
        Some(second),
        &second_output,
        second_raw,
        &[taint("drawer", 7)],
    )?;
    vault.put_code_run_raw_output(Some(owner), &merged_output, merged_raw)?;

    inherit_result_marks(
        &vault,
        owner,
        &merged_output,
        &[(first, first_output), (second, second_output)],
    )?;

    assert_eq!(
        vault.code_run_raw_output_taint_refs(Some(owner), &merged_output)?,
        vec![taint("cabinet", 1), taint("drawer", 7)],
    );
    Ok(())
}
