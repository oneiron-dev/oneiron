//! The census check, a substrate invariant: no restore loosens a decision the
//! engine makes from restored rows, and one that loosens none restores. Every
//! decision the guard asks has a case here.
use crate::{Result, Vault};
use std::collections::BTreeSet;
use std::path::PathBuf;

mod audience;
mod campaign;
mod consent;
mod counterparty;
mod reads;
mod skills;
mod tasks;

/// A write to the live vault since the backup.
type Write = Box<dyn FnOnce(&Vault) -> Result<()>>;

/// One census case: a live vault with a backup of it, a write since the
/// backup that leaves the decision's answer as it was, and one that a
/// restore would undo, loosening it.
pub(super) struct Case {
    /// The guard row the case is for, as a refusal names it.
    row: &'static str,
    vault: Vault,
    image: PathBuf,
    routine: Write,
    loosening: Write,
    /// The vault's directory and the backups', kept until the case ends.
    dirs: (tempfile::TempDir, tempfile::TempDir),
}

impl Case {
    /// Backs up `vault` as it stands, for the two writes that follow.
    pub(super) fn after_backup(
        row: &'static str,
        (dir, vault): (tempfile::TempDir, Vault),
        routine: impl FnOnce(&Vault) -> Result<()> + 'static,
        loosening: impl FnOnce(&Vault) -> Result<()> + 'static,
    ) -> Result<Self> {
        let backups = tempfile::tempdir()?;
        let image = backups.path().join("backup");
        vault.snapshot_checkpoint(&image, 100)?;
        Ok(Self {
            row,
            vault,
            image,
            routine: Box::new(routine),
            loosening: Box::new(loosening),
            dirs: (dir, backups),
        })
    }
}

/// Every census case.
const CASES: &[fn() -> Result<Case>] = &[
    counterparty::send_contacts,
    counterparty::do_not_contact,
    counterparty::send_overrides,
    campaign::campaign_compliance,
    audience::record_audiences,
    audience::disclosure_clamps,
    audience::disclosure_tiers,
    audience::leader_chats,
    audience::project_verdicts,
    reads::relationship_reads,
    reads::claim_grants,
    reads::claim_grants_under_the_seeded_default,
    reads::note_reads,
    reads::diary_links,
    reads::record_positions,
    tasks::task_authority,
    tasks::stale_asks,
    tasks::settled_asks,
    tasks::asks_settled_since,
    tasks::dispatchable_agents,
    tasks::resident_wakes,
    tasks::agent_ceilings,
    tasks::ask_holders,
    skills::skill_activations,
    consent::mail_reputation,
    consent::shared_coreference,
    consent::delivery_windows,
    consent::booking_publications,
    consent::principal_autonomy,
    consent::esign_ceremonies,
];

#[test]
fn no_restore_loosens_a_decision_and_one_that_loosens_none_restores() {
    let mut covered = BTreeSet::new();
    let mut failures = Vec::new();
    for (index, case) in CASES.iter().enumerate() {
        match run(*case) {
            Ok(row) => {
                covered.insert(row);
            }
            Err(failure) => failures.push(format!("case {index}: {failure}")),
        }
    }
    for (row, _) in super::DECISIONS {
        if !covered.contains(row) {
            failures.push(format!("{row}: no passing census case"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A restore asked from inside the live vault's own write transaction, over a
/// vault with no manifest in force, is refused. Judging that vault by the
/// default its next open seeds takes its writer, which the caller holds; the
/// restore used to wait on itself there (Astra R5).
#[test]
fn a_restore_inside_the_live_vaults_write_transaction_refuses_rather_than_waits() {
    let (dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let backups = tempfile::tempdir().expect("backup dir");
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100).expect("backup");
    let (done, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let restored = vault.with_write_txn(|_| {
            Ok(Vault::restore_checkpoint_keeping_authority(
                &image,
                &backups.path().join("restored"),
                vault.config.clone(),
                &vault,
                1_000,
            )
            .map(drop))
        });
        let refused = matches!(restored, Ok(Err(crate::Error::ConcurrentWrite(_))));
        let _ = done.send((refused, format!("{restored:?}")));
        drop((dir, backups));
    });
    let (refused, restored) = outcome
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the restore waited on the write transaction its caller holds");
    assert!(refused, "not refused as a concurrent write: {restored}");
}

/// Runs one census case, naming its row when it holds.
fn run(case: fn() -> Result<Case>) -> std::result::Result<&'static str, String> {
    let Case {
        row,
        vault,
        image,
        routine,
        loosening,
        dirs,
    } = case().map_err(|error| format!("setting up: {error}"))?;
    let restore = |name: &str| {
        Vault::restore_checkpoint_keeping_authority(
            &image,
            &dirs.1.path().join(name),
            vault.config.clone(),
            &vault,
            1_000,
        )
        .map(drop)
    };
    routine(&vault).map_err(|error| format!("{row}: the routine write failed: {error}"))?;
    restore("routine").map_err(|error| {
        format!(
            "{row}: a routine write since the backup refused the restore: {error}{}",
            unread(&vault, &image, &dirs.1.path().join("unguarded"))
        )
    })?;
    loosening(&vault).map_err(|error| format!("{row}: the loosening write failed: {error}"))?;
    match restore("loosened") {
        Ok(()) => Err(format!("{row}: a restore that loosens it went ahead")),
        Err(error) if error.to_string().contains(row) => Ok(row),
        Err(error) => Err(format!("{row}: refused for another reason: {error}")),
    }
}

/// The decisions whose readers fail outright between `vault` and an
/// unguarded restore of `image`, for a refusal that names none.
fn unread(vault: &Vault, image: &std::path::Path, destination: &std::path::Path) -> String {
    let restored = match Vault::restore_checkpoint(
        image,
        destination,
        vault.config.clone(),
        super::super::RestoreReason::Restore,
        1_000,
    ) {
        Ok((restored, _)) => restored,
        Err(error) => return format!(" (an unguarded restore fails too: {error})"),
    };
    let failed: Vec<String> = super::DECISIONS
        .iter()
        .filter_map(|(row, check)| {
            check(vault, &restored)
                .err()
                .map(|error| format!("{row} reads: {error}"))
        })
        .collect();
    format!(" [{}]", failed.join("; "))
}
