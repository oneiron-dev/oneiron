//! Canonical recovery and signed-history import leave out the authority rows
//! the source's own fold never applied (census L7-19; identity.md, "Open,
//! Engine's next PR": "Import and canonical-recovery preflight fail on a row
//! stored before #1449 that the new door would hold").
//!
//! A vault written before every store door held a stranger's row may store
//! one: a row signed by a key no row of its history admitted, which its own
//! fold never applied, and an owner row naming it as a parent, which that
//! fold never applied either. The door of the vault that recovers such a
//! window, or imports such a history, holds the stranger's row, and before
//! the fix the whole recovery or import refused. Now both leave out those
//! two rows and land the rest, and the stranger gains no standing.

#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use loro::LoroDoc;
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityEntryHash, AuthorityFold,
    AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier,
    AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep, ROLE_ADMIN, ROLE_AGENT, ROLE_OWNER,
    authority_entry_hash, authority_log_entity_id, authority_transcript, genesis_vault_id,
};
use oneiron::recovery::{RecoveryBudget, capture_canonical_window, recover_vault_window};
use oneiron::sync::WindowKey;
use oneiron::sync::bridge::Materializer;
use oneiron::test_doors::authority_stored_damage::put_authority_log_entries_past_the_store_door;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 2, end: 2 };

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn device(key: AuthorityKey, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent: Option<&AuthorityLogEntry>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let key = key_of(signer);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes: parent
            .map(|parent| vec![authority_entry_hash(parent).expect("parent hash")])
            .unwrap_or_default(),
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry
}

/// `signer` enrols the agent key `enrolled` on `parent`. Agent-only: the
/// vault door refuses any other client enrollment.
fn enrollment(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    enrolled: &SigningKey,
) -> AuthorityLogEntry {
    signed(
        Some(vault_id),
        seq,
        Some(parent),
        AuthorityOp::EnrollDevice {
            device: device(key_of(enrolled), ROLE_AGENT),
        },
        signer,
    )
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

fn id_of(entry: &AuthorityLogEntry) -> EntityId {
    authority_log_entity_id(entry).expect("row id")
}

fn applied(fold: &AuthorityFold) -> BTreeSet<AuthorityEntryHash> {
    fold.valid_entries.iter().copied().collect()
}

/// A vault whose log a pre-#1449 store left holding a stranger's row: the
/// owner's genesis and an agent enrollment, the stranger's row on them, and
/// an owner row naming the stranger's row as its parent.
struct PreDoorVault {
    _dir: tempfile::TempDir,
    source: Vault,
    owner_key: AuthorityKey,
    agent_key: AuthorityKey,
    stranger_key: AuthorityKey,
    genesis: AuthorityLogEntry,
    agent_enrollment: AuthorityLogEntry,
    stranger_row: AuthorityLogEntry,
    row_on_the_stranger: AuthorityLogEntry,
}

fn pre_door_vault() -> PreDoorVault {
    let owner = SigningKey::from_bytes(&[191; 32]);
    let agent = SigningKey::from_bytes(&[192; 32]);
    let stranger = SigningKey::from_bytes(&[193; 32]);
    let ghost = SigningKey::from_bytes(&[194; 32]);
    let second_agent = SigningKey::from_bytes(&[195; 32]);

    let (dir, source) = open_vault();
    let genesis = signed(
        None,
        0,
        None,
        AuthorityOp::Genesis {
            device: device(key_of(&owner), ROLE_OWNER | ROLE_ADMIN),
            genesis_nonce: [196; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
        },
        &owner,
    );
    let vault_id = genesis_vault_id(&genesis).expect("vault id");
    let agent_enrollment = enrollment(vault_id, &genesis, &owner, 1, &agent);
    source
        .put_authority_log_entries(&[(genesis.clone(), AT, 2), (agent_enrollment.clone(), AT, 2)])
        .expect("the owner's history lands");

    let stranger_row = enrollment(vault_id, &agent_enrollment, &stranger, 1, &ghost);
    let row_on_the_stranger = enrollment(vault_id, &stranger_row, &owner, 2, &second_agent);
    let held = source
        .put_authority_log_entry(&stranger_row, AT, 2)
        .expect_err("today's door holds the stranger's row");
    eprintln!("the door holds the stranger's row: {:?}", held.kind());
    put_authority_log_entries_past_the_store_door(
        &source,
        &[
            (stranger_row.clone(), AT, 2),
            (row_on_the_stranger.clone(), AT, 2),
        ],
    )
    .expect("a pre-#1449 store kept both rows");

    let fold = source.authority_fold().expect("source fold");
    assert_eq!(
        applied(&fold),
        [&genesis, &agent_enrollment]
            .into_iter()
            .map(|entry| authority_entry_hash(entry).expect("hash"))
            .collect::<BTreeSet<_>>(),
        "the source's own fold applies the owner's two rows alone: {:?}",
        fold.issues
    );
    PreDoorVault {
        _dir: dir,
        source,
        owner_key: key_of(&owner),
        agent_key: key_of(&agent),
        stranger_key: key_of(&stranger),
        genesis,
        agent_enrollment,
        stranger_row,
        row_on_the_stranger,
    }
}

/// The recovered or imported vault holds the owner's two rows and neither
/// row the source's fold never applied, and its fold gives the stranger no
/// standing.
fn assert_lands_without_the_strangers_rows(fixture: &PreDoorVault, target: &Vault) {
    assert_eq!(
        target
            .get_authority_log_entry(&id_of(&fixture.agent_enrollment))
            .expect("read"),
        Some(fixture.agent_enrollment.clone()),
        "the owner's enrollment lands"
    );
    assert_eq!(
        target
            .get_authority_log_entry(&id_of(&fixture.stranger_row))
            .expect("read"),
        None,
        "the stranger's row is left out"
    );
    assert_eq!(
        target
            .get_authority_log_entry(&id_of(&fixture.row_on_the_stranger))
            .expect("read"),
        None,
        "the row standing on it is left out"
    );
    let fold = target.authority_fold().expect("target fold");
    assert_eq!(
        applied(&fold),
        applied(&fixture.source.authority_fold().expect("source fold")),
        "the target applies what the source applied: {:?}",
        fold.issues
    );
    assert!(fold.roster.contains_key(&fixture.owner_key));
    assert!(fold.roster.contains_key(&fixture.agent_key));
    assert!(
        !fold.roster.contains_key(&fixture.stranger_key),
        "the stranger gains no standing"
    );
}

#[test]
fn a_window_holding_a_strangers_pre_door_row_recovers_without_it() {
    let fixture = pre_door_vault();
    let window = WindowKey::from_timestamp(2);
    let doc = LoroDoc::new();
    let rows = [
        &fixture.genesis,
        &fixture.agent_enrollment,
        &fixture.stranger_row,
        &fixture.row_on_the_stranger,
    ];
    for entry in rows {
        let id = id_of(entry);
        let raw = fixture
            .source
            .get_raw(&id)
            .expect("read")
            .expect("the source stores the row");
        doc.get_map("entities")
            .insert(&id.to_hex(), raw.as_slice())
            .expect("window row");
    }
    doc.commit();
    let snapshot =
        capture_canonical_window(&fixture.source, window.as_str(), &doc).expect("capture");
    assert_eq!(
        snapshot.entity_blobs.len(),
        4,
        "the artifact carries the stranger's row and the row standing on it"
    );

    let (_target_dir, target) = open_vault();
    target
        .put_authority_log_entry(&fixture.genesis, AT, 2)
        .expect("the recovering vault holds the genesis");
    let manifest_dir = tempfile::tempdir().expect("manifest dir");
    recover_vault_window(
        &target,
        &Materializer::new(),
        manifest_dir.path().join("manifest"),
        &snapshot,
        RecoveryBudget::default(),
    )
    .expect("the window recovers without the rows its source's fold never applied");
    assert_lands_without_the_strangers_rows(&fixture, &target);
}

#[test]
fn a_signed_history_holding_a_strangers_pre_door_row_imports_without_it() {
    let fixture = pre_door_vault();
    let history = fixture
        .source
        .export_signed_authority_history()
        .expect("export");
    assert_eq!(
        history.len(),
        4,
        "the export carries the stranger's row and the row standing on it"
    );

    let (_target_dir, target) = open_vault();
    let imported = target
        .import_signed_authority_history(&history)
        .expect("the history imports without the rows its source's fold never applied");
    assert_eq!(
        imported,
        vec![id_of(&fixture.genesis), id_of(&fixture.agent_enrollment)],
        "the import stages the owner's two rows alone"
    );
    assert_lands_without_the_strangers_rows(&fixture, &target);
}
