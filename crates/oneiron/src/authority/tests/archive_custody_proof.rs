//! Archive custody proofs measured from another machine's carried rows
//! (census L5-22 PR 2).

use super::machine_identity::{host, own_encryption_key};
use super::support::ed_key;
use super::*;
use crate::{OpenOptions, Vault, VaultConfig, VaultStorageId};

struct ArchiveCustodyFixture {
    owen: Vault,
    owen_dir: tempfile::TempDir,
    _yuki: Vault,
    _yuki_dir: tempfile::TempDir,
    owen_machine: EntityId,
    owen_key: [u8; 32],
    yuki_machine: EntityId,
    yuki_key: [u8; 32],
    checkpoint: [u8; 32],
    manifest: AuthorityArchiveManifest,
    fetch: AuthorityHistoryFetch,
    pages: Vec<AuthorityHistoryPage>,
}

fn archive_custody_fixture() -> ArchiveCustodyFixture {
    let host = host();
    let owen = &host.vault;
    let request = owen
        .machine_enrolment_request(host.vault_id, own_encryption_key(owen, host.vault_id))
        .unwrap();
    let owen_machine = request.machine;
    let owen_key = request.machine_key;
    // The first install has no carrier yet: the owner's pairing answer
    // enrols its own request through the explicit bootstrap arm.
    let link = owen
        .issue_machine_pairing_link(
            &host.issuer,
            &host.owner,
            ActSurface::ThisInstall,
            crate::federation::Scope::top(),
            3600,
            PairingPrincipal::default(),
            MachineOwnership::Yours,
        )
        .unwrap();
    let pairing_key = ed_key(76);
    let binding_key = pairing_key.verifying_key().to_bytes();
    let holder = owen_machine.to_hex();
    let signature = pairing_key
        .sign(&pairing_binding_transcript(&link.code, &binding_key, &holder).unwrap())
        .to_bytes();
    owen.redeem_machine_pairing_link(
        &host.issuer,
        &link.code,
        &holder,
        binding_key,
        &signature,
        &request,
    )
    .unwrap();
    assert_eq!(
        owen.authority_fold()
            .unwrap()
            .machine_proof_key(owen_machine),
        Some(owen_key),
        "the builder's fold proves its own machine on its install key",
    );

    let root = owen.ensure_host_root_slip(&host.issuer).unwrap();
    let mut claims = root.claims.clone();
    claims.slip_id = [141; 32];
    claims.records = BTreeSet::from(["record:archive-custody".to_owned()]);
    owen.mint_capability_slip(&host.issuer, claims).unwrap();
    let checkpoint = owen.write_authority_checkpoint_v2(&host.issuer).unwrap();
    let pin = owen.authority_checkpoint_pin([7; 32]).unwrap().unwrap();
    assert_eq!(pin.checkpoint, checkpoint);
    let bundle = owen
        .authority_checkpoint_bundle(&checkpoint)
        .unwrap()
        .unwrap();
    let image = AuthorityCheckpointV2::decode(&bundle.image).unwrap();
    assert!(image.covers_sealed_row(), "the image covers a sealed row");
    assert_eq!(
        image.archive_manifests.len(),
        1,
        "the builder advertises exactly one archive manifest",
    );
    let manifest = image.archive_manifests[0].clone();
    assert_eq!(
        manifest.custodians,
        vec![AuthorityArchiveCustodian {
            machine: owen_machine,
            proof_key: owen_key,
        }],
        "the manifest names the builder's own proved machine",
    );

    let yuki_dir = crate::test_support::restore_tempdir();
    let yuki = Vault::open_owned_with(
        yuki_dir.path(),
        VaultConfig::default(),
        OpenOptions::default().adopt_storage_id(VaultStorageId::from_verified_pin(&pin)),
    )
    .unwrap();
    let adopted = match image.building_pin {
        Some(root) => yuki.adopt_recovered_authority_checkpoint(
            &pin,
            &bundle.image,
            &bundle.attestations,
            pin.digest().unwrap(),
            root,
        ),
        None => yuki.adopt_authority_checkpoint(&pin, &bundle.image, &bundle.attestations),
    }
    .unwrap();
    assert_eq!(adopted, checkpoint);
    let request = yuki
        .machine_enrolment_request(host.vault_id, own_encryption_key(&yuki, host.vault_id))
        .unwrap();
    let yuki_machine = request.machine;
    let yuki_key = request.machine_key;
    owen.enroll_machine(
        &host.owner,
        ActSurface::ThisInstall,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        None,
    )
    .unwrap();
    assert_eq!(
        owen.authority_fold()
            .unwrap()
            .machine_proof_key(yuki_machine),
        Some(yuki_key),
        "the builder's fold proves the serving machine on its own install key",
    );

    let fetch = AuthorityHistoryFetch {
        vault_id: None,
        selection: AuthorityHistorySelection::Covered {
            checkpoint,
            archive: Some(manifest.archive),
            lower_exclusive: None,
            upper_inclusive: None,
        },
        parent_closure: false,
        held: BTreeSet::new(),
        cursor: None,
        limit: AUTHORITY_HISTORY_PAGE_MAX,
    };
    let mut request = fetch.clone();
    let mut pages = Vec::new();
    loop {
        let page = yuki
            .authority_history_page_for_peer(
                &request,
                PeerMachine::Proven {
                    machine: owen_machine,
                    key: owen_key,
                },
            )
            .unwrap();
        request.cursor = page.next;
        pages.push(page);
        if request.cursor.is_none() {
            break;
        }
    }
    assert_eq!(
        pages.iter().map(|page| page.rows.len()).sum::<usize>(),
        manifest.rows.len(),
        "the serving machine carries every manifest row",
    );
    ArchiveCustodyFixture {
        owen: host.vault,
        owen_dir: host._dir,
        _yuki: yuki,
        _yuki_dir: yuki_dir,
        owen_machine,
        owen_key,
        yuki_machine,
        yuki_key,
        checkpoint,
        manifest,
        fetch,
        pages,
    }
}

fn refusal(result: crate::error::Result<AuthorityArchiveCustodyProof>) -> &'static str {
    match result {
        Err(crate::error::Error::Record(crate::error::RecordError::InvalidAuthorityLogBody(
            reason,
        ))) => reason,
        Err(error) => panic!("expected an invalid authority log body, got {error:?}"),
        Ok(proof) => panic!("expected a refusal, got {proof:?}"),
    }
}

/// T-PROOF (census L5-22 PR 2): complete pages record the serving machine's
/// proof and its manifest row count, durably across a restart.
#[test]
fn a_custodians_pages_record_a_proof_naming_it_with_the_manifest_row_count() {
    let fixture = archive_custody_fixture();
    let result = fixture.owen.record_archive_custody_proof(
        PeerMachine::Proven {
            machine: fixture.yuki_machine,
            key: fixture.yuki_key,
        },
        &fixture.fetch,
        &fixture.pages,
    );
    let proofs = fixture.owen.authority_archive_custody_proofs().unwrap();
    assert!(
        proofs.len() == 1
            && proofs[0].custodian == fixture.yuki_machine
            && proofs[0].custodian_key == fixture.yuki_key
            && proofs[0].archive == fixture.manifest.archive
            && proofs[0].checkpoint == fixture.checkpoint
            && proofs[0].rows == fixture.manifest.rows.len() as u64,
        "the proof names B with the manifest's row count",
    );
    assert_eq!(result.unwrap(), proofs[0]);
    drop(fixture.owen);
    let owen = Vault::open(fixture.owen_dir.path(), VaultConfig::default()).unwrap();
    assert_eq!(
        owen.authority_archive_custody_proofs().unwrap(),
        proofs,
        "the proof stands after a restart",
    );
}

/// T-TAMPER (census L5-22 PR 2): a changed byte is not a manifest row and
/// leaves no custody proof behind.
#[test]
fn a_page_row_with_one_flipped_byte_records_no_proof() {
    let mut fixture = archive_custody_fixture();
    *fixture.pages[0].rows[0].last_mut().unwrap() ^= 1;
    let result = fixture.owen.record_archive_custody_proof(
        PeerMachine::Proven {
            machine: fixture.yuki_machine,
            key: fixture.yuki_key,
        },
        &fixture.fetch,
        &fixture.pages,
    );
    assert!(result.is_err(), "a tampered page row refuses the proof");
    assert_eq!(
        refusal(result),
        "a custody proof row the archive manifest does not list",
    );
    assert!(
        fixture
            .owen
            .authority_archive_custody_proofs()
            .unwrap()
            .is_empty(),
        "a refused proof writes nothing",
    );
}

/// T-SHORT (census L5-22 PR 2): local possession never fills a gap in the
/// serving machine's carried rows.
#[test]
fn pages_that_leave_out_a_row_refuse_on_the_vault_that_holds_every_row() {
    let mut fixture = archive_custody_fixture();
    for hash in &fixture.manifest.rows {
        assert!(
            fixture
                .owen
                .get_raw(&authority_log_entity_id_from_hash(hash).unwrap())
                .unwrap()
                .is_some(),
            "the builder holds every row of its own manifest",
        );
    }
    fixture
        .pages
        .iter_mut()
        .rev()
        .find(|page| !page.rows.is_empty())
        .unwrap()
        .rows
        .pop()
        .unwrap();
    let result = fixture.owen.record_archive_custody_proof(
        PeerMachine::Proven {
            machine: fixture.yuki_machine,
            key: fixture.yuki_key,
        },
        &fixture.fetch,
        &fixture.pages,
    );
    assert!(
        result.is_err(),
        "pages that leave out one row refuse the proof even where every row is held",
    );
    assert_eq!(
        refusal(result),
        "a custody proof short of the archive's rows"
    );
    assert!(
        fixture
            .owen
            .authority_archive_custody_proofs()
            .unwrap()
            .is_empty(),
        "a refused proof writes nothing",
    );
}

/// T-SELF (census L5-22 PR 2): a machine proved by the fold still cannot
/// record itself as its own archive custodian.
#[test]
fn a_machine_named_as_its_own_custodian_records_no_proof() {
    let fixture = archive_custody_fixture();
    assert_eq!(
        fixture
            .owen
            .authority_fold()
            .unwrap()
            .machine_proof_key(fixture.owen_machine),
        Some(fixture.owen_key),
        "the builder's fold proves its own machine on that key",
    );
    let result = fixture.owen.record_archive_custody_proof(
        PeerMachine::Proven {
            machine: fixture.owen_machine,
            key: fixture.owen_key,
        },
        &fixture.fetch,
        &fixture.pages,
    );
    assert!(
        result.is_err(),
        "a machine proves no archive custody to itself"
    );
    assert_eq!(
        refusal(result),
        "a machine proves no archive custody to itself"
    );
    assert!(
        fixture
            .owen
            .authority_archive_custody_proofs()
            .unwrap()
            .is_empty(),
        "a refused proof writes nothing",
    );
}

/// T-STRANGER (census L5-22 PR 2): a known machine under a key the fold
/// does not prove records no custody proof.
#[test]
fn a_custodian_key_the_fold_does_not_prove_records_no_proof() {
    let fixture = archive_custody_fixture();
    let key = ed_key(77).verifying_key().to_bytes();
    assert_ne!(key, fixture.yuki_key);
    let result = fixture.owen.record_archive_custody_proof(
        PeerMachine::Proven {
            machine: fixture.yuki_machine,
            key,
        },
        &fixture.fetch,
        &fixture.pages,
    );
    assert!(
        result.is_err(),
        "a custodian key the fold does not prove refuses the proof",
    );
    assert_eq!(
        refusal(result),
        "a custody proof names a machine not proved here on that key",
    );
    assert!(
        fixture
            .owen
            .authority_archive_custody_proofs()
            .unwrap()
            .is_empty(),
        "a refused proof writes nothing",
    );
}
