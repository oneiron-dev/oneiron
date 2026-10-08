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
    audience::relationship_members,
    audience::disclosure_clamps,
    audience::disclosure_tiers,
    audience::leader_chats,
    audience::project_verdicts,
    reads::relationship_reads,
    reads::claim_grants,
    reads::note_reads,
    reads::record_positions,
    tasks::task_authority,
    tasks::stale_asks,
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
fn no_restore_loosens_a_decision_and_one_that_loosens_none_restores() -> Result<()> {
    let mut covered = BTreeSet::new();
    for case in CASES {
        let Case {
            row,
            vault,
            image,
            routine,
            loosening,
            dirs,
        } = case()?;
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
        routine(&vault)?;
        if let Err(error) = restore("routine") {
            panic!("{row}: a routine write since the backup refused the restore: {error}");
        }
        loosening(&vault)?;
        let error = restore("loosened")
            .err()
            .unwrap_or_else(|| panic!("{row}: a restore that loosens it went ahead"));
        assert!(error.to_string().contains(row), "{row}: {error}");
        covered.insert(row);
    }
    for (row, _) in super::DECISIONS {
        assert!(covered.contains(row), "{row} has no census case");
    }
    Ok(())
}
