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

/// A real bug: the rows below read their claims through the predicate list,
/// which refuses past a fixed count, so a vault holding more claims of one
/// of these predicates than that could not be restored at all. The guard now
/// walks them one claim at a time. Test builds lower the list's cap; each
/// row's claim is copied from the census case that writes it through its own
/// door, or built where no case writes one. Booking publications are the one
/// row left out: only the owner's memory door may write one, so a copy is
/// refused; that row reads through the same walk.
#[test]
fn a_vault_holding_more_claims_of_a_predicate_than_a_list_holds_restores() -> Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
    use crate::{EntityId, TimeRange, VaultConfig};
    let stored = |case: fn() -> Result<Case>, predicate: &str| -> Result<ClaimBody> {
        let case = case()?;
        let txn = case.vault.store.env.read_txn()?;
        let mut claims = case.vault.claims_with_predicate_in_txn(&txn, predicate)?;
        claims
            .pop()
            .map(|(_, claim)| claim)
            .ok_or(crate::Error::EntityNotFound)
    };
    let person = crate::test_util::entity(0x51);
    let built = |predicate: &str, value: rmpv::Value| {
        ClaimBody::new(
            predicate,
            ClaimSubject::Entity(person),
            value,
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
    };
    let claims = [
        stored(
            consent::shared_coreference,
            crate::claim::PREDICATE_COREFERENCE_SHARE_CONSENT,
        )?,
        stored(
            consent::delivery_windows,
            crate::delivery_window::PREDICATE_DELIVERY_WINDOW_QUIET,
        )?,
        stored(
            counterparty::do_not_contact,
            crate::campaign::claims::PREDICATE_COMM_DO_NOT_CONTACT,
        )?,
        stored(
            counterparty::send_overrides,
            crate::comm::PREDICATE_COMM_SEND_OVERRIDE,
        )?,
        built(
            crate::campaign::compliance::PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS,
            rmpv::Value::Map(vec![("sender_identity".into(), true.into())]),
        )?,
        built(
            crate::federation::PREDICATE_RELATIONSHIP_PERSON_REF,
            person.to_hex().into(),
        )?,
    ];
    let (dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let at = TimeRange { start: 1, end: 1 };
    vault.put_entity(&person, ENTITY_TYPE_PERSON, at, 1, b"person")?;
    let mut batch = vault.batch();
    for (row, claim) in claims.iter().enumerate() {
        let body = crate::claim::encode_claim_body(claim)?;
        for n in 0..=crate::ports::MAX_PREDICATE_LIST_ROWS {
            let mut id = [0x01, 0x52, row as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            id[8..].copy_from_slice(&(n as u64).to_be_bytes());
            batch =
                batch.put_replicated(&EntityId::from_bytes(id)?, ENTITY_TYPE_CLAIM, at, 1, &body);
        }
    }
    batch.commit()?;
    let backups = tempfile::tempdir()?;
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100)?;
    Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("restored"),
        vault.config.clone(),
        &vault,
        1_000,
    )?;
    drop(dir);
    Ok(())
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
