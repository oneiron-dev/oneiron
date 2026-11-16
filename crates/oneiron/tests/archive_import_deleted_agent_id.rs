//! A deleted agent stays deleted across a whole-vault archive import (FIX
//! AGENT-DEF-ARCHIVE-IMPORT-DELETED-ID; Engine RULING AGENT-DEF-ARCHIVE-IMPORT-DELETED-ID = A).
//!
//! The import refused a row whose id collides with a deleted entity only while the deleted
//! row's bytes remained. At an agent id whose row a hard delete purged, an archived definition
//! landed again (Imported, disabled and Proposed, but keeping its archived lifecycle and model
//! choices), through the actorless door the server CLI uses when the vault's owner does not
//! authenticate among them. Now every door refuses an AGENT_DEF row at an agent id this vault
//! holds as deleted, with the refusal it already gave while the bytes remained. The actorless,
//! actor and owner doors all run the one import loop the check sits in.
//!
//! Public doors only:
//! `cargo test --locked -p oneiron --all-features --test archive_import_deleted_agent_id`.

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::{DeleteReason, EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;

const DELETED_COLLISION: &str =
    "invalid config: whole-vault import: import ID collides with a deleted entity";

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open the vault");
    (dir, vault)
}

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "archived agent fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![("definedVia".into(), "define_agent".into())]),
        None,
        true,
        None,
    )
}

/// A vault holding one agent definition, the agent's id, and a whole-vault archive that
/// holds it.
fn vault_with_archived_agent() -> (tempfile::TempDir, Vault, EntityId, Vec<u8>) {
    let (dir, vault) = open_vault();
    let agent = EntityId::now();
    vault
        .put_agent_definition(
            &agent,
            &definition("archived-agent"),
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .expect("the agent is defined");
    let archive = vault
        .export_whole_vault(true)
        .expect("the whole-vault archive")
        .bytes()
        .to_vec();
    (dir, vault, agent, archive)
}

/// Deletes `agent` for `reason`, imports `archive` back, and returns the import's refusal.
fn delete_then_import(
    vault: &Vault,
    agent: EntityId,
    reason: DeleteReason,
    archive: &[u8],
) -> Option<String> {
    vault
        .delete_entity_with_reason(&agent, reason)
        .expect("the agent is deleted");
    assert!(
        vault.get(&agent).expect("the row read").is_none(),
        "FIXTURE: the deleted agent reads as gone"
    );
    vault
        .import_whole_vault_archive(archive)
        .err()
        .map(|error| error.to_string())
}

#[test]
fn a_hard_deleted_agent_does_not_come_back_from_an_archive() {
    let (_dir, vault, agent, archive) = vault_with_archived_agent();

    let refusal = delete_then_import(&vault, agent, DeleteReason::UserHardDelete, &archive);

    assert!(
        vault.get(&agent).expect("the row read").is_none(),
        "an agent whose row a hard delete purged stays deleted after an archive import"
    );
    assert_eq!(
        refusal.as_deref(),
        Some(DELETED_COLLISION),
        "the import refuses the purged agent's id as it refuses a deleted row whose bytes remain"
    );
}

/// Guard: while the deleted row's bytes remain (a plain delete keeps a shell), the import
/// refused the id before this fix, with the same refusal.
#[test]
fn a_deleted_agent_whose_row_remains_is_refused_as_before() {
    let (_dir, vault, agent, archive) = vault_with_archived_agent();

    let refusal = delete_then_import(&vault, agent, DeleteReason::UserDelete, &archive);

    assert!(
        vault.get(&agent).expect("the row read").is_none(),
        "a deleted agent stays deleted after an archive import"
    );
    assert_eq!(refusal.as_deref(), Some(DELETED_COLLISION));
}

/// Guard: an archive's agent at an id this vault never held still lands.
#[test]
fn an_agent_this_vault_never_held_lands_from_an_archive() {
    let (_dir, _source, agent, archive) = vault_with_archived_agent();
    let (_fresh_dir, fresh) = open_vault();

    fresh
        .import_whole_vault_archive(&archive)
        .expect("the archive lands in a fresh vault");

    assert!(
        fresh.get(&agent).expect("the row read").is_some(),
        "an agent this vault never held lands from an archive"
    );
}
