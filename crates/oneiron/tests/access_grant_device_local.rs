//! An ACCESS_GRANT row never leaves the install that wrote it (Engine RULING
//! R2E-ACCESS-GRANT-PREMISE = B, 16 Nov 07:53). A peer's row, from an own
//! device or a federation peer, is refused at replay before it lands, and a
//! whole-vault archive brings none back, so no install believes a grant
//! another install wrote. Fable pass 28's SR-5 asked for grant acts on the
//! authority log for this row on the premise that it travels; it does not, so
//! a forged or replayed row confers nothing anywhere already.
//!
//! A change that lets ACCESS_GRANT travel turns this file red, and must bring
//! the grant's acts with it (pass 28: a row gives nothing by itself; a reader
//! gives what the fold's counted acts say).
//!
//! Public paths only.
//! `cargo test --locked -p oneiron --all-features --test access_grant_device_local`.
#![cfg(feature = "sync")]

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
    encode_access_grant_body,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_ACCESS_GRANT;
use oneiron::sync::FederationAdmissionRole;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::{EntityId, ErrorKind, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// An active grant: `principal` reads the MESSAGEs of `conversation`.
fn message_read_grant(principal: EntityId, conversation: EntityId) -> AccessGrant {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    AccessGrant {
        authority_scope,
        principal_ref: principal,
        scope: AccessGrantScope::ConversationMessages {
            conversation_ref: conversation,
        },
        capability: AccessGrantCapability::MessagesRead,
        status: AccessGrantStatus::Active,
        created_at: 1,
        revoked_at: None,
        expires_at: None,
        companion_bounds: None,
    }
}

fn open(dir: &std::path::Path) -> Result<Vault, Box<dyn std::error::Error>> {
    Ok(Vault::open(dir, VaultConfig::device())?)
}

/// Catches an ACCESS_GRANT row that travels: a peer's well-formed grant row,
/// replayed at the own-device tier and at each federated tier, is refused,
/// and no row lands at its id. Own-device replay is trust-blind, so its
/// refusal is the replica write's own: a kind no replica writes.
#[test]
fn a_peers_access_grant_row_lands_at_no_replay_tier() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open(dir.path())?;
    let body = encode_access_grant_body(&message_read_grant(EntityId::now(), EntityId::now()))?;
    for tier in [
        ImportTier::OwnDevice,
        ImportTier::Federated(FederationAdmissionRole::Member),
        ImportTier::Federated(FederationAdmissionRole::Guest),
    ] {
        let id = EntityId::now();
        let replayed = replay_entity(
            &vault,
            ReplicatedEntity {
                id,
                entity_type: ENTITY_TYPE_ACCESS_GRANT,
                occurred: TimeRange { start: 1, end: 1 },
                learned_at: 1,
                row_version: 0,
                body: &body,
            },
            tier,
        );
        assert!(
            replayed.is_err(),
            "a peer's ACCESS_GRANT row is refused at {tier:?}"
        );
        if matches!(tier, ImportTier::OwnDevice) {
            assert_eq!(
                replayed.as_ref().err().map(oneiron::Error::kind),
                Some(ErrorKind::MaintenanceKindNotWritable),
                "{replayed:?}"
            );
        }
        assert_eq!(vault.get_raw(&id)?, None, "nothing lands at {tier:?}");
    }
    Ok(())
}

/// Catches an archive that restores a grant: a whole-vault archive carrying an
/// ACCESS_GRANT row omits it on import, and the importing vault holds no row
/// at its id.
#[test]
fn a_whole_vault_archive_brings_no_access_grant_back() -> TestResult {
    let source_dir = tempfile::tempdir()?;
    let source = open(source_dir.path())?;
    let grant = EntityId::now();
    source.create_access_grant(
        &grant,
        &message_read_grant(EntityId::now(), EntityId::now()),
    )?;
    assert!(
        source.get_raw(&grant)?.is_some(),
        "the source holds the grant"
    );
    let archive = source.export_whole_vault(false)?;

    // A fresh destination whose engine-seed seconds differ from the source's,
    // so its seeds never collide with the archive's (copied from
    // `whole_vault_restore_edited_seed_skills.rs`).
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let target_dir = tempfile::tempdir()?;
    let target = open(target_dir.path())?;
    let receipt = target.import_whole_vault_archive(archive.bytes())?;
    assert!(
        receipt.omitted_entities >= 1,
        "the grant is omitted: {receipt:?}"
    );
    assert_eq!(target.get_raw(&grant)?, None, "no grant row is restored");
    Ok(())
}
