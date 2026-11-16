//! Cold offload of covered authority history behind its switch
//! (census L5-22 PR 3): the device drops what its home keeps.

use super::machine_identity::{Host, host, own_encryption_key};
use super::support::ed_key;
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::store::GateDecisionId;
use crate::{OpenOptions, Vault, VaultConfig, VaultStorageId};

/// A machine enrolled on Owen before the image, beside Owen and Yuki.
struct ExtraMachine {
    machine: EntityId,
    key: [u8; 32],
    role: MachineRole,
}

/// What the offload fixture builds: Owen's image, Yuki's adoption of it and
/// Yuki's hydration from Owen's pages.
struct ColdOffloadFixture {
    owen: Vault,
    _owen_dir: tempfile::TempDir,
    yuki: Vault,
    yuki_dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    owen_machine: EntityId,
    owen_key: [u8; 32],
    yuki_machine: EntityId,
    yuki_key: [u8; 32],
    checkpoint: [u8; 32],
    manifest: AuthorityArchiveManifest,
    covered: BTreeSet<AuthorityEntryHash>,
    fetch: AuthorityHistoryFetch,
    pages: Vec<AuthorityHistoryPage>,
    pin: AuthorityCheckpointPin,
    storage_id: VaultStorageId,
    root_claims: SlipClaims,
    next_root: Option<AuthorityKey>,
    extra: Vec<ExtraMachine>,
    world: Option<EntityId>,
    agent: Option<EntityId>,
    g1: Option<EntityId>,
    g1_raw: Option<Vec<u8>>,
    g2: Option<EntityId>,
}

/// The ways one offload test may diverge from the base fixture.
#[derive(Default)]
struct FixtureOptions {
    /// Mint a slip with records before the image, so it covers a sealed row.
    sealed: bool,
    /// Re-root Owen to a successor before the image, so the image covers the
    /// root edge.
    reroot: bool,
    /// Enrol one machine per role on Owen before the image.
    extra_machines: Vec<MachineRole>,
    /// Mint an owner-agent Grant, tighten a world under it, revoke it, and
    /// revoke an unrelated guest Grant, all before the image (finding 1).
    world_privacy: bool,
}

fn cold_offload_fixture() -> ColdOffloadFixture {
    cold_offload_fixture_with(FixtureOptions::default())
}

fn cold_offload_fixture_with(options: FixtureOptions) -> ColdOffloadFixture {
    let host = host();
    let owen = &host.vault;
    let root = owen
        .ensure_host_root_slip(&host.issuer)
        .expect("the builder holds its host root slip");
    let next = if options.reroot {
        Some(
            HostSlipIssuer::from_secret(b"cold offload successor root")
                .expect("the successor root issuer"),
        )
    } else {
        None
    };
    let mut reroot_edge = None;
    if let Some(next) = &next {
        // Adoption-eligible: re-root before any enrolment, so no root-signed
        // approval predates the move and the image holds nothing unresolved.
        let handoff = owen
            .re_root_authority(
                next.root_device(owen.privacy_posture()),
                host.issuer.public_key(),
                |bytes| Ok(host.issuer.sign_slip(bytes)),
            )
            .expect("the builder re-roots to its successor");
        reroot_edge = Some(authority_entry_hash(&handoff).expect("the re-root edge hashes"));
    }
    let enrol_issuer = next.as_ref().unwrap_or(&host.issuer);
    let request = owen
        .machine_enrolment_request(host.vault_id, own_encryption_key(owen, host.vault_id))
        .expect("the builder asks to join its own vault");
    let owen_machine = request.machine;
    let owen_key = request.machine_key;
    // The first install has no carrier yet: the owner's pairing answer
    // enrols its own request through the explicit bootstrap arm.
    let link = owen
        .issue_machine_pairing_link(
            enrol_issuer,
            &host.owner,
            ActSurface::ThisInstall,
            crate::federation::Scope::top(),
            3600,
            PairingPrincipal::default(),
            MachineOwnership::Yours,
        )
        .expect("the builder issues its own pairing link");
    let pairing_key = ed_key(76);
    let binding_key = pairing_key.verifying_key().to_bytes();
    let holder = owen_machine.to_hex();
    let signature = pairing_key
        .sign(
            &pairing_binding_transcript(&link.code, &binding_key, &holder)
                .expect("the pairing transcript"),
        )
        .to_bytes();
    owen.redeem_machine_pairing_link(
        enrol_issuer,
        &link.code,
        &holder,
        binding_key,
        &signature,
        &request,
    )
    .expect("the builder redeems its own pairing link");
    assert_eq!(
        owen.authority_fold()
            .expect("the builder folds")
            .machine_proof_key(owen_machine),
        Some(owen_key),
        "the builder's fold proves its own machine on its install key",
    );

    if options.sealed {
        let mut claims = root.claims.clone();
        claims.slip_id = [141; 32];
        claims.records = BTreeSet::from(["record:archive-custody".to_owned()]);
        owen.mint_capability_slip(&host.issuer, claims)
            .expect("the builder mints the sealed slip");
    }
    let mut extra = Vec::new();
    for role in &options.extra_machines {
        let dir = tempfile::tempdir().expect("an extra machine's install dir");
        let install =
            Vault::open(dir.path(), VaultConfig::default()).expect("an extra machine's install");
        let request = install
            .machine_enrolment_request(host.vault_id, own_encryption_key(&install, host.vault_id))
            .expect("an extra machine asks to join");
        owen.enroll_machine(&host.owner, ActSurface::ThisInstall, &request, *role, None)
            .expect("the owner enrols the extra machine");
        extra.push(ExtraMachine {
            machine: request.machine,
            key: request.machine_key,
            role: *role,
        });
    }
    let (world, agent, g1, g1_raw, g2) = if options.world_privacy {
        let world = owen
            .create_world(&host.owner, "agent privacy world", owen.now_recorded_at())
            .expect("the builder creates the agent privacy world");
        let agent = owen
            .ensure_agent_principal("cold-offload-agent")
            .expect("the builder ensures the agent principal");
        let mut scope = crate::federation::Scope::top();
        scope.worlds =
            crate::federation::ScopeAxis::Some(BTreeSet::from([crate::federation::ScopeId(world)]));
        scope.verbs = crate::federation::ScopeAxis::Some(BTreeSet::from([
            "read".to_owned(),
            "world_privacy_tighten".to_owned(),
        ]));
        let minted = owen
            .mint_agent_grant(
                &host.owner,
                ActSurface::ThisInstall,
                agent,
                scope,
                None,
                None,
                BTreeSet::new(),
                None,
                None,
            )
            .expect("the owner mints the agent its tighten Grant");
        assert!(minted.confers, "the tighten Grant confers at its mint",);
        let g1 = minted.standing.id;
        let g1_raw = owen
            .get_raw(&g1)
            .expect("the Grant row reads")
            .expect("the builder holds its live Grant row");
        owen.bind_host_actor_for_test(&host.issuer, agent, "agent")
            .expect("the builder binds the agent");
        let writer = owen
            .observed_write_actor(crate::WriteActor::new(agent, crate::EdgeActorClass::Agent))
            .expect("the builder observes the agent writer");
        let outcome = owen
            .agent_world_privacy(
                &writer,
                Vec::new(),
                world,
                WorldPrivacy {
                    read: ReadLocation::MyMachines,
                    ..WorldPrivacy::default()
                },
                None,
            )
            .expect("the agent tightens the world under its Grant");
        assert!(
            matches!(
                outcome,
                crate::policy_model::WorldPrivacyOutcome::Applied(_)
            ),
            "the agent tighten applied, not a proposal or ask",
        );
        let revoked = owen
            .revoke_agent_grant(&host.owner, ActSurface::ThisInstall, g1)
            .expect("the owner revokes the agent Grant");
        assert!(revoked.act.is_some(), "the owner revoke signs its act",);
        let guest = crate::federation::FederationGrant::ask_guest(
            EntityId::now(),
            EntityId::now(),
            EntityId::now(),
            EntityId::now(),
            BTreeSet::from([EntityId::now()]),
        )
        .expect("the guest Grant builds");
        let g2 = EntityId::now();
        let encoded = crate::federation::encode_federation_grant_body(&guest)
            .expect("the guest Grant encodes");
        let now = owen.now_recorded_at();
        owen.batch()
            .put_replicated(
                &g2,
                crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                None,
                &encoded,
            )
            .commit()
            .expect("the guest Grant lands");
        let guest_revoked = owen
            .revoke_guest_access(&host.owner, &host.issuer, g2)
            .expect("the owner revokes the unrelated guest Grant");
        assert!(guest_revoked.changed, "the guest revoke changed the Grant",);
        assert_ne!(g1, g2, "the guest Grant differs from the agent Grant");
        (Some(world), Some(agent), Some(g1), Some(g1_raw), Some(g2))
    } else {
        (None, None, None, None, None)
    };
    let write_issuer = next.as_ref().unwrap_or(&host.issuer);
    let checkpoint = owen
        .write_authority_checkpoint_v2(write_issuer)
        .expect("the builder writes its checkpoint");
    let pin = owen
        .authority_checkpoint_pin([7; 32])
        .expect("the pin reads")
        .expect("the builder's checkpoint reaches quorum");
    assert_eq!(
        pin.checkpoint, checkpoint,
        "the pin names the head the builder wrote",
    );
    let bundle = owen
        .authority_checkpoint_bundle(&checkpoint)
        .expect("the bundle reads")
        .expect("the builder keeps its attested bundle");
    let image = AuthorityCheckpointV2::decode(&bundle.image).expect("the image decodes");
    if options.sealed {
        assert!(
            image.covers_sealed_row(),
            "the sealed image covers a sealed row",
        );
    } else {
        assert!(
            !image.covers_sealed_row(),
            "the base image covers no sealed row",
        );
    }
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
    let covered: BTreeSet<AuthorityEntryHash> = image.covered.iter().copied().collect();
    assert_eq!(
        manifest.rows.iter().copied().collect::<BTreeSet<_>>(),
        covered,
        "the one archive lists every covered row",
    );
    if let Some(edge) = reroot_edge {
        assert!(covered.contains(&edge), "the image covers the re-root edge",);
    }
    if options.reroot {
        assert_eq!(
            image.unresolved,
            AuthorityCheckpointUnresolved::default(),
            "the re-root image holds nothing unresolved",
        );
    }

    let storage_id = VaultStorageId::from_verified_pin(&pin);
    let yuki_dir = crate::test_support::restore_tempdir();
    let yuki = Vault::open_owned_with(
        yuki_dir.path(),
        VaultConfig::default(),
        OpenOptions::default().adopt_storage_id(storage_id),
    )
    .expect("the device opens under the adopted storage id");
    let adopted = match image.building_pin {
        Some(root) => yuki.adopt_recovered_authority_checkpoint(
            &pin,
            &bundle.image,
            &bundle.attestations,
            pin.digest().expect("the pin digests"),
            root,
        ),
        None => yuki.adopt_authority_checkpoint(&pin, &bundle.image, &bundle.attestations),
    }
    .expect("the device adopts the image");
    assert_eq!(adopted, checkpoint, "the device adopts the head");
    let request = yuki
        .machine_enrolment_request(host.vault_id, own_encryption_key(&yuki, host.vault_id))
        .expect("the device asks to join");
    let yuki_machine = request.machine;
    let yuki_key = request.machine_key;
    owen.enroll_machine(
        &host.owner,
        ActSurface::ThisInstall,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        None,
    )
    .expect("the owner enrols the device");
    assert_eq!(
        owen.authority_fold()
            .expect("the builder folds")
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
    let mut paging = fetch.clone();
    let mut pages = Vec::new();
    loop {
        let page = owen
            .authority_history_page_for_peer(
                &paging,
                PeerMachine::Proven {
                    machine: yuki_machine,
                    key: yuki_key,
                },
            )
            .expect("the builder serves its archive");
        paging.cursor = page.next;
        pages.push(page);
        if paging.cursor.is_none() {
            break;
        }
    }
    assert_eq!(
        pages.iter().map(|page| page.rows.len()).sum::<usize>(),
        manifest.rows.len(),
        "the builder carries every manifest row",
    );
    if options.sealed {
        for hash in &covered {
            assert!(
                yuki.get_raw(&authority_log_entity_id_from_hash(hash).expect("the row id"))
                    .expect("the row reads")
                    .is_some(),
                "every covered authority row lands in the sealed adoption",
            );
        }
    } else {
        assert!(
            yuki.authority_history_verification(&covered)
                .expect("the coverage reads")
                .archive
                .held
                .is_empty(),
            "the unsealed adoption lands no covered row",
        );
        let blobs: Vec<Vec<u8>> = pages.iter().flat_map(|page| page.rows.clone()).collect();
        let mut overlays = CarriedOverlays::new();
        for page in &pages {
            overlays.extend(page.overlays.clone());
        }
        yuki.import_signed_authority_history(&blobs, &overlays)
            .expect("the device hydrates from the served pages");
        assert_eq!(
            yuki.authority_history_verification(&covered)
                .expect("the coverage reads")
                .archive
                .held,
            covered,
            "the device holds every covered row after hydration",
        );
    }
    assert_eq!(
        yuki.authority_fold()
            .expect("the device folds")
            .machine_proof_key(owen_machine),
        Some(owen_key),
        "the device's fold proves the builder on its install key",
    );
    let read = yuki.store.env.read_txn().expect("a read txn");
    assert!(
        !crate::gate::resolve_policy_manifest(&yuki.store, &read)
            .expect("the manifest resolves")
            .authority_history_offload_enabled(),
        "the offload switch starts off on the device",
    );
    drop(read);

    let Host {
        _dir: _owen_dir,
        vault: owen,
        issuer,
        owner,
        vault_id: _,
    } = host;
    ColdOffloadFixture {
        owen,
        _owen_dir,
        yuki,
        yuki_dir,
        issuer,
        owner,
        owen_machine,
        owen_key,
        yuki_machine,
        yuki_key,
        checkpoint,
        manifest,
        covered,
        fetch,
        pages,
        pin,
        storage_id,
        root_claims: root.claims.clone(),
        next_root: next.as_ref().map(HostSlipIssuer::public_key),
        extra,
        world,
        agent,
        g1,
        g1_raw,
        g2,
    }
}

/// Turns the `authority.history.offload` row on or off on `vault` through
/// the owner's manifest writer, as the owner would.
fn set_offload_switch(vault: &Vault, on: bool) {
    let person = vault
        .ensure_embedded_owner_actor()
        .expect("the fixture owner actor");
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("the fixture owner authenticates");
    vault
        .with_write_txn(|txn| {
            crate::gate::policy_manifest_doors::rewrite_default_manifest_field_as_owner_in_txn(
                vault,
                &owner,
                txn,
                "authority.history.offload",
                |_| Ok(rmpv::Value::Boolean(on)),
                "gate.allow.test_authority_history_offload",
            )
        })
        .expect("the offload switch writes");
    let read = vault.store.env.read_txn().expect("a read txn");
    assert_eq!(
        crate::gate::resolve_policy_manifest(&vault.store, &read)
            .expect("the manifest resolves")
            .authority_history_offload_enabled(),
        on,
        "the offload switch reads back as written",
    );
}

fn offload_refusal(result: crate::error::Result<Option<AuthorityHistoryOffload>>) -> &'static str {
    match result {
        Err(crate::error::Error::Record(crate::error::RecordError::InvalidAuthorityLogBody(
            reason,
        ))) => reason,
        Err(error) => panic!("expected an invalid authority log body, got {error:?}"),
        Ok(offload) => panic!("expected a refusal, got {offload:?}"),
    }
}

fn held_covered(
    vault: &Vault,
    covered: &BTreeSet<AuthorityEntryHash>,
) -> BTreeSet<AuthorityEntryHash> {
    vault
        .authority_history_verification(covered)
        .expect("the coverage reads")
        .archive
        .held
}

/// Replicates G1's live row to `vault`, then deletes it there, so `vault`
/// NOW-refuses G1 as Owen does: the smallest change that makes the agent act
/// NOW-refused and preserved on a device that only hydrated authority history.
fn replicate_g1_withdrawal(vault: &Vault, g1: EntityId, g1_raw: &[u8]) {
    let header =
        crate::batch::EntityMetadataHeader::parse(g1_raw).expect("the saved Grant row parses");
    let body = &g1_raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    vault
        .batch()
        .put_replicated(
            &g1,
            header.entity_type,
            TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            None,
            body,
        )
        .commit()
        .expect("the Grant row lands for its withdrawal");
    assert!(
        vault.delete_entity(&g1).expect("the Grant deletes"),
        "the replicated Grant row deletes",
    );
}

/// The sequence floors and receipted hashes for `rows` on `vault`: the growth
/// the put path counts, since a retained receipt makes re-arrival no new
/// growth.
fn sequence_receipts(
    vault: &Vault,
    rows: &[(AuthorityEntryHash, AuthorityLogEntry)],
) -> (
    BTreeMap<AuthorityEntryHash, u64>,
    BTreeSet<AuthorityEntryHash>,
) {
    let metas: Vec<crate::authority::fold_resume::RowMeta<'_>> = rows
        .iter()
        .map(|(hash, entry)| crate::authority::fold_resume::RowMeta::of(Some(*hash), entry))
        .collect();
    let txn = vault.store.env.read_txn().expect("a read txn");
    let (observations, receipted) =
        crate::authority::sequence_observation::authority_local_observations_receipted_in_txn(
            &vault.store,
            &txn,
            &metas,
        )
        .expect("the observations read");
    (observations.sequence_floors, receipted)
}

/// T-OFFLOAD (census L5-22 PR 3): with the switch on, a hydrated device
/// whose custody proof stands drops every covered row it holds, names the
/// archive and the row count, and keeps the record across a restart.
#[test]
fn an_offload_drops_every_covered_row_and_records_it() {
    let fixture = cold_offload_fixture();
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    set_offload_switch(&fixture.yuki, true);
    let offload = fixture
        .yuki
        .offload_authority_history(&fixture.checkpoint)
        .expect("the offload proceeds");
    let Some(offload) = offload else {
        panic!("an offload with a standing proof drops rows");
    };
    assert_eq!(
        offload.archives,
        vec![fixture.manifest.archive],
        "the offload names the archive whose proof stood",
    );
    assert_eq!(
        offload.evicted,
        fixture.manifest.rows.len() as u64,
        "the offload counts every manifest row",
    );
    assert!(
        held_covered(&fixture.yuki, &fixture.covered).is_empty(),
        "an offload drops every covered row it held",
    );
    assert_eq!(
        fixture
            .yuki
            .authority_history_verification(&fixture.covered)
            .expect("the coverage reads")
            .archive
            .offloaded,
        fixture.covered,
        "every covered row reads back as offloaded",
    );
    let records = fixture
        .yuki
        .authority_history_offloads()
        .expect("the offloads read");
    assert_eq!(
        records,
        vec![offload],
        "the device keeps the one offload record",
    );
    assert!(
        fixture
            .yuki
            .offload_authority_history(&fixture.checkpoint)
            .expect("a second offload reads")
            .is_none(),
        "a second offload under the same image finds nothing",
    );
    drop(fixture.yuki);
    let yuki = Vault::open_owned_with(
        fixture.yuki_dir.path(),
        VaultConfig::default(),
        OpenOptions::default().adopt_storage_id(fixture.storage_id),
    )
    .expect("the device reopens");
    assert_eq!(
        yuki.authority_history_offloads()
            .expect("the offloads read"),
        records,
        "the offload record stands after a restart",
    );
    assert!(
        held_covered(&yuki, &fixture.covered).is_empty(),
        "the eviction stands after a restart",
    );
}

/// T-FOLD-EQUAL (census L5-22 PR 3): the fold's valid entries and the
/// builder's proof key are the same before and after the offload, and a row
/// the device writes after it folds valid.
#[test]
fn the_fold_is_unchanged_across_an_offload_and_folds_a_new_row() {
    let fixture = cold_offload_fixture();
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    set_offload_switch(&fixture.yuki, true);
    let before = fixture
        .yuki
        .authority_fold()
        .expect("the fold answers before the offload");
    assert_eq!(
        before.machine_proof_key(fixture.owen_machine),
        Some(fixture.owen_key),
        "the device proves the builder before the offload",
    );
    let offload = fixture
        .yuki
        .offload_authority_history(&fixture.checkpoint)
        .expect("the offload proceeds");
    assert!(
        offload.is_some(),
        "an offload with a standing proof drops rows",
    );
    assert!(
        held_covered(&fixture.yuki, &fixture.covered).is_empty(),
        "an offload drops every covered row it held",
    );
    let after = fixture
        .yuki
        .authority_fold()
        .expect("the fold answers after the offload");
    assert_eq!(
        before.valid_entries, after.valid_entries,
        "an offload keeps the fold's valid entries",
    );
    assert_eq!(
        before.machine_proof_key(fixture.owen_machine),
        after.machine_proof_key(fixture.owen_machine),
        "an offload keeps the builder's proof key",
    );
    let mut claims = fixture.root_claims.clone();
    claims.slip_id = [223; 32];
    claims.records = BTreeSet::new();
    claims.channels = BTreeSet::new();
    let slip = fixture
        .yuki
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("the device mints after the offload");
    let folded = fixture
        .yuki
        .authority_fold()
        .expect("the fold answers after a new row");
    let minted = folded
        .slips
        .mints
        .get(&slip.claims.slip_id)
        .expect("the new mint is folded")
        .entry_hash;
    assert!(
        folded.valid_entries.contains(&minted),
        "a row the device writes after the offload folds valid",
    );
}

/// T-REARRIVAL (census L5-22 PR 3): the same pages imported again after the
/// offload land, every row is held again, and the sequence receipts show no
/// new growth.
#[test]
fn covered_rows_reimported_after_an_offload_land_without_new_growth() {
    let fixture = cold_offload_fixture();
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    set_offload_switch(&fixture.yuki, true);
    let before = fixture
        .yuki
        .authority_fold()
        .expect("the fold answers before the offload");
    let mut rows = Vec::new();
    for hash in &fixture.covered {
        let id = authority_log_entity_id_from_hash(hash).expect("the covered row id");
        let entry = fixture
            .yuki
            .get_authority_log_entry(&id)
            .expect("the covered row reads")
            .expect("the covered row is held before the offload");
        rows.push((*hash, entry));
    }
    let (floors_before, receipted_before) = sequence_receipts(&fixture.yuki, &rows);
    assert_eq!(
        receipted_before, fixture.covered,
        "every covered row holds its sequence receipt before the offload",
    );
    let offload = fixture
        .yuki
        .offload_authority_history(&fixture.checkpoint)
        .expect("the offload proceeds");
    assert!(
        offload.is_some(),
        "an offload with a standing proof drops rows",
    );
    let (floors_offloaded, receipted_offloaded) = sequence_receipts(&fixture.yuki, &rows);
    assert_eq!(
        receipted_offloaded, receipted_before,
        "an offload keeps every sequence receipt",
    );
    assert_eq!(
        floors_offloaded, floors_before,
        "an offload keeps every sequence floor",
    );
    let blobs: Vec<Vec<u8>> = fixture
        .pages
        .iter()
        .flat_map(|page| page.rows.clone())
        .collect();
    let mut overlays = CarriedOverlays::new();
    for page in &fixture.pages {
        overlays.extend(page.overlays.clone());
    }
    fixture
        .yuki
        .import_signed_authority_history(&blobs, &overlays)
        .expect("the same pages land again after the offload");
    assert_eq!(
        held_covered(&fixture.yuki, &fixture.covered),
        fixture.covered,
        "every covered row is held again after its re-arrival",
    );
    assert_eq!(
        fixture
            .yuki
            .authority_fold()
            .expect("the fold answers after the re-arrival")
            .valid_entries,
        before.valid_entries,
        "a row that arrives again rejoins the fold",
    );
    let (floors_after, receipted_after) = sequence_receipts(&fixture.yuki, &rows);
    assert_eq!(
        receipted_after, receipted_before,
        "a row that arrives again takes no new sequence receipt",
    );
    assert_eq!(
        floors_after, floors_before,
        "a row that arrives again keeps its sequence floor",
    );
}

/// T-SWITCH-OFF (census L5-22 PR 3): with the switch left off, the offload
/// refuses and every covered row stays held.
#[test]
fn an_offload_with_its_switch_off_refuses_and_keeps_every_row() {
    let fixture = cold_offload_fixture();
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    let result = fixture.yuki.offload_authority_history(&fixture.checkpoint);
    assert_eq!(
        offload_refusal(result),
        "authority history offload is disabled",
        "an offload with its switch off refuses",
    );
    assert_eq!(
        held_covered(&fixture.yuki, &fixture.covered),
        fixture.covered,
        "a refused offload keeps every covered row",
    );
}

/// T-NO-PROOF (census L5-22 PR 3): with the switch on but no custody proof,
/// the offload refuses and every covered row stays held.
#[test]
fn an_offload_without_a_custody_proof_refuses_and_keeps_every_row() {
    let fixture = cold_offload_fixture();
    set_offload_switch(&fixture.yuki, true);
    let result = fixture.yuki.offload_authority_history(&fixture.checkpoint);
    assert_eq!(
        offload_refusal(result),
        "a covered row no standing custody proof keeps",
        "an offload with no proof refuses",
    );
    assert_eq!(
        held_covered(&fixture.yuki, &fixture.covered),
        fixture.covered,
        "a refused offload keeps every covered row",
    );
}

/// T-PROOF-FOR-ANOTHER-IMAGE (census L5-22 PR 3): a proof recorded against
/// the first image keeps no row once the device adopted a second image with
/// another archive. It proves no cross-image deletion, not the checkpoint
/// check alone: the second image covers a new enrolment row, so its archive
/// id differs and the old archive lookup also refuses.
#[test]
fn a_proof_against_an_old_archive_keeps_no_row_after_readoption() {
    let fixture = cold_offload_fixture();
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    let second = fixture
        .owen
        .write_authority_checkpoint_v2(&fixture.issuer)
        .expect("the builder writes a second checkpoint");
    assert_ne!(second, fixture.checkpoint, "the second image is a new head",);
    let pin = fixture
        .owen
        .authority_checkpoint_pin([7; 32])
        .expect("the pin reads")
        .expect("the second checkpoint reaches quorum");
    assert_eq!(pin.checkpoint, second, "the pin names the second head");
    let bundle = fixture
        .owen
        .authority_checkpoint_bundle(&second)
        .expect("the bundle reads")
        .expect("the builder keeps its second bundle");
    let image = AuthorityCheckpointV2::decode(&bundle.image).expect("the image decodes");
    let adopted = match image.building_pin {
        Some(root) => fixture.yuki.adopt_recovered_authority_checkpoint(
            &pin,
            &bundle.image,
            &bundle.attestations,
            pin.digest().expect("the pin digests"),
            root,
        ),
        None => fixture
            .yuki
            .adopt_authority_checkpoint(&pin, &bundle.image, &bundle.attestations),
    }
    .expect("the device adopts the second image");
    assert_eq!(adopted, second, "the device adopts the second head");
    set_offload_switch(&fixture.yuki, true);
    let result = fixture.yuki.offload_authority_history(&second);
    assert_eq!(
        offload_refusal(result),
        "a covered row no standing custody proof keeps",
        "a proof against another image keeps no row",
    );
    assert_eq!(
        held_covered(&fixture.yuki, &fixture.covered),
        fixture.covered,
        "a refused offload keeps every covered row",
    );
}

/// T-SEALED-COVER (census L5-22 PR 3): an image that covers a sealed row
/// folds its stored log whole, so the offload refuses and the rows stay.
#[test]
fn an_offload_of_a_sealed_cover_refuses_and_folds_whole() {
    let fixture = cold_offload_fixture_with(FixtureOptions {
        sealed: true,
        ..FixtureOptions::default()
    });
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    set_offload_switch(&fixture.yuki, true);
    let result = fixture.yuki.offload_authority_history(&fixture.checkpoint);
    assert_eq!(
        offload_refusal(result),
        "an image that covers a sealed row folds its stored log whole",
        "an offload of a sealed cover refuses",
    );
    assert_eq!(
        held_covered(&fixture.yuki, &fixture.covered),
        fixture.covered,
        "a refused offload keeps every covered row",
    );
}

/// T-NOT-ADOPTED (census L5-22 PR 3): the builder, which adopted nothing,
/// refuses, and so does an image that is not the adopted head.
#[test]
fn offload_without_an_adoption_or_for_another_image_refuses() {
    let fixture = cold_offload_fixture();
    set_offload_switch(&fixture.owen, true);
    let result = fixture.owen.offload_authority_history(&fixture.checkpoint);
    assert_eq!(
        offload_refusal(result),
        "authority history offload needs an adopted checkpoint image",
        "an offload with no adoption refuses",
    );
    set_offload_switch(&fixture.yuki, true);
    let result = fixture.yuki.offload_authority_history(&[0; 32]);
    assert_eq!(
        offload_refusal(result),
        "authority history offload names an image that is not the adopted head",
        "an offload for another image refuses",
    );
}

/// T-CUSTODIAN-GONE (census L5-22 PR 3): once the builder's removal lands on
/// the device, its proof stands no longer and the offload refuses.
#[test]
fn an_offload_after_the_custodian_is_removed_refuses() {
    let fixture = cold_offload_fixture();
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    set_offload_switch(&fixture.yuki, true);
    fixture
        .owen
        .set_machine_role(
            &fixture.owner,
            ActSurface::ThisInstall,
            fixture.owen_machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the builder");
    let history = fixture
        .owen
        .export_signed_authority_history()
        .expect("the builder exports its history");
    fixture
        .yuki
        .import_signed_authority_history(&history, &CarriedOverlays::new())
        .expect("the removal lands on the device");
    assert_eq!(
        fixture
            .yuki
            .authority_fold()
            .expect("the device folds")
            .machine_proof_key(fixture.owen_machine),
        None,
        "the device proves the removed builder on no key",
    );
    let result = fixture.yuki.offload_authority_history(&fixture.checkpoint);
    assert_eq!(
        offload_refusal(result),
        "a covered row no standing custody proof keeps",
        "an offload after the custodian is gone refuses",
    );
    assert_eq!(
        held_covered(&fixture.yuki, &fixture.covered),
        fixture.covered,
        "a refused offload keeps every covered row",
    );
}

/// T-EXECUTION-NODE (census L5-22 PR 3): a durable copy never stands on
/// rented compute, so a proof from an execution node keeps no row.
#[test]
fn a_custody_proof_from_an_execution_node_keeps_no_row() {
    let fixture = cold_offload_fixture_with(FixtureOptions {
        extra_machines: vec![MachineRole::ExecutionNode],
        ..FixtureOptions::default()
    });
    assert_eq!(
        fixture.extra.len(),
        1,
        "the fixture enrolled the execution node",
    );
    let custodian = &fixture.extra[0];
    assert_eq!(
        custodian.role,
        MachineRole::ExecutionNode,
        "the extra machine is an execution node",
    );
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: custodian.machine,
                key: custodian.key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the execution node's pages");
    assert_eq!(
        fixture
            .yuki
            .authority_fold()
            .expect("the device folds")
            .machine_proof_role(custodian.machine),
        Some(MachineRole::ExecutionNode),
        "the device proves the custodian as an execution node",
    );
    set_offload_switch(&fixture.yuki, true);
    let result = fixture.yuki.offload_authority_history(&fixture.checkpoint);
    assert_eq!(
        offload_refusal(result),
        "a covered row no standing custody proof keeps",
        "a proof from an execution node keeps no row",
    );
    assert_eq!(
        held_covered(&fixture.yuki, &fixture.covered),
        fixture.covered,
        "a refused offload keeps every covered row",
    );
}

/// T-EXPORT-NAMES-OFFLOADED (census L5-22 PR 3, B1): a hydrated device
/// exports its full history, but after the offload the export refuses and
/// names the covered rows it no longer holds.
#[test]
fn a_full_export_after_an_offload_names_the_offloaded_prefix() {
    let fixture = cold_offload_fixture();
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    set_offload_switch(&fixture.yuki, true);
    assert!(
        !fixture
            .yuki
            .export_signed_authority_history()
            .expect("a hydrated device exports its full history")
            .is_empty(),
        "a hydrated device exports its rows",
    );
    let offload = fixture
        .yuki
        .offload_authority_history(&fixture.checkpoint)
        .expect("the offload proceeds");
    assert!(
        offload.is_some(),
        "an offload with a standing proof drops rows",
    );
    let error = fixture
        .yuki
        .export_signed_authority_history()
        .expect_err("a full export after an offload refuses");
    match error {
        crate::error::Error::Record(crate::error::RecordError::AuthorityHistoryRequired {
            vault_id,
            checkpoint,
            missing,
        }) => {
            assert_eq!(
                checkpoint,
                Some(fixture.checkpoint),
                "the refused export names the adopted image",
            );
            assert_eq!(
                missing.into_iter().collect::<BTreeSet<_>>(),
                fixture.covered,
                "the refused export names every covered row",
            );
            assert_eq!(
                vault_id,
                Some(fixture.pin.genesis),
                "the refused export names the vault",
            );
        }
        other => panic!("expected a missing-history refusal, got {other:?}"),
    }
}

/// T-ROOT-EDGES-CARRIED (census L5-22 PR 3, B3): after the offload, the root
/// edge still rides the signed bytes the adopted image carries for it.
#[test]
fn root_edges_ride_their_carried_bodies_after_an_offload() {
    let fixture = cold_offload_fixture_with(FixtureOptions {
        reroot: true,
        ..FixtureOptions::default()
    });
    let next = fixture
        .next_root
        .as_ref()
        .expect("the reroot fixture names its successor");
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    set_offload_switch(&fixture.yuki, true);
    assert_eq!(
        fixture
            .yuki
            .root_handoff_to(next)
            .expect("the handoff reads"),
        fixture
            .owen
            .root_handoff_to(next)
            .expect("the handoff reads"),
        "the device hands the root on as the builder does before the offload",
    );
    let offload = fixture
        .yuki
        .offload_authority_history(&fixture.checkpoint)
        .expect("the offload proceeds");
    assert!(
        offload.is_some(),
        "an offload with a standing proof drops rows",
    );
    let handoff = fixture
        .yuki
        .root_handoff_to(next)
        .expect("the handoff reads after the offload");
    assert_eq!(
        handoff,
        fixture
            .owen
            .root_handoff_to(next)
            .expect("the handoff reads"),
        "the root edge still rides its carried bytes after the offload",
    );
    assert!(!handoff.is_empty(), "the carried edge hands the root on",);
}

/// T-WORLD-PRIVACY-KEPT (census L5-22 PR 3, finding 1): an agent tighten that
/// past-grant standing preserves stays MyMachines across an offload when an
/// unrelated guest revoke is covered.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture plus its before and after reads"
)]
fn an_unrelated_guest_revoke_keeps_an_agents_tighten_across_an_offload() {
    let fixture = cold_offload_fixture_with(FixtureOptions {
        world_privacy: true,
        ..FixtureOptions::default()
    });
    let world = fixture.world.expect("the fixture names its world");
    let agent = fixture.agent.expect("the fixture names its agent");
    let g1 = fixture.g1.expect("the fixture names its agent Grant");
    let g1_raw = fixture
        .g1_raw
        .as_ref()
        .expect("the fixture keeps the Grant row");
    let g2 = fixture.g2.expect("the fixture names its guest Grant");
    assert_ne!(agent, g1, "the agent differs from its Grant");
    assert_ne!(g1, g2, "the guest Grant differs from the agent Grant");
    assert_eq!(
        fixture
            .owen
            .world_privacy(world)
            .expect("the builder reads world privacy")
            .read,
        crate::authority::EffectiveRead::MyMachines,
        "the builder answers the preserved tighten",
    );
    replicate_g1_withdrawal(&fixture.yuki, g1, g1_raw);
    {
        let txn = fixture.yuki.store.env.read_txn().expect("a read txn");
        assert!(
            crate::authority::grant_known_withdrawn_in_txn(&fixture.yuki.store, &txn, g1),
            "the device NOW-refuses the agent Grant",
        );
    }
    assert_eq!(
        fixture
            .yuki
            .world_privacy(world)
            .expect("the device reads world privacy")
            .read,
        crate::authority::EffectiveRead::MyMachines,
        "the device answers the preserved tighten before the offload",
    );
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    set_offload_switch(&fixture.yuki, true);
    let offload = fixture
        .yuki
        .offload_authority_history(&fixture.checkpoint)
        .expect("the offload proceeds");
    assert!(
        offload.is_some(),
        "an offload with a standing proof drops rows",
    );
    assert!(
        held_covered(&fixture.yuki, &fixture.covered).is_empty(),
        "an offload drops every covered row it held",
    );
    assert_eq!(
        fixture
            .yuki
            .world_privacy(world)
            .expect("the device reads world privacy")
            .read,
        crate::authority::EffectiveRead::MyMachines,
        "an unrelated guest revoke keeps the tighten across the offload",
    );
    let bundle = fixture
        .owen
        .authority_checkpoint_bundle(&fixture.checkpoint)
        .expect("the bundle reads")
        .expect("the builder keeps its bundle");
    let image = AuthorityCheckpointV2::decode(&bundle.image).expect("the image decodes");
    let bare_dir = crate::test_support::restore_tempdir();
    let bare = Vault::open_owned_with(
        bare_dir.path(),
        VaultConfig::default(),
        OpenOptions::default().adopt_storage_id(fixture.storage_id),
    )
    .expect("the bare device opens");
    let adopted = match image.building_pin {
        Some(root) => bare.adopt_recovered_authority_checkpoint(
            &fixture.pin,
            &bundle.image,
            &bundle.attestations,
            fixture.pin.digest().expect("the pin digests"),
            root,
        ),
        None => bare.adopt_authority_checkpoint(&fixture.pin, &bundle.image, &bundle.attestations),
    }
    .expect("the bare device adopts the image");
    assert_eq!(
        adopted, fixture.checkpoint,
        "the bare device adopts the head",
    );
    assert!(
        held_covered(&bare, &fixture.covered).is_empty(),
        "the bare adoption lands no covered row",
    );
    replicate_g1_withdrawal(&bare, g1, g1_raw);
    assert_eq!(
        bare.world_privacy(world)
            .expect("the bare device reads world privacy")
            .read,
        crate::authority::EffectiveRead::MyMachines,
        "the adopted device answers the tighten with no covered row held",
    );
}

/// T-ELECTED-HOME-KEEPS-LOG (census L5-22 PR 3, finding 2): the vault elected
/// home keeps every row; the offload refuses there.
#[test]
fn the_elected_home_keeps_its_whole_authority_log() {
    let fixture = cold_offload_fixture();
    let runner = crate::dreamer_runner::DreamerRunnerStore::new(&fixture.yuki);
    let local = runner
        .local_home_node_candidate(true, true, false)
        .expect("the device names its home candidacy");
    let designation = runner
        .elect_home_node(&[local], 1)
        .expect("the home election runs")
        .expect("the single candidacy elects a home");
    assert_eq!(
        designation.node_id, local.node_id,
        "the device elects its own node home",
    );
    {
        let txn = fixture.yuki.store.env.read_txn().expect("a read txn");
        let node = crate::identity::read_client_id_in_txn(&fixture.yuki, &txn)
            .expect("the client id reads")
            .expect("the device minted its node id");
        assert_eq!(
            node, local.node_id,
            "the elected node is this install's own id",
        );
    }
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    set_offload_switch(&fixture.yuki, true);
    let result = fixture.yuki.offload_authority_history(&fixture.checkpoint);
    assert_eq!(
        offload_refusal(result),
        "the vault's elected home keeps its whole authority log",
        "an offload on the elected home refuses",
    );
    assert_eq!(
        held_covered(&fixture.yuki, &fixture.covered),
        fixture.covered,
        "a refused offload keeps every covered row",
    );
    #[cfg(feature = "sync")]
    assert!(
        fixture
            .yuki
            .authority_offload_due()
            .expect("the due read runs")
            .is_none(),
        "the elected home owes no offload",
    );
}

/// T-WHOLE-EXPORT-NAMES-OFFLOADED (census L5-22 PR 3, finding 3): after the
/// offload, whole-vault archive and JSON exports refuse with the history they
/// lack.
#[test]
fn whole_vault_exports_after_an_offload_name_the_offloaded_prefix() {
    let fixture = cold_offload_fixture();
    match fixture.yuki.export_whole_vault(false) {
        Ok(export) => assert!(
            !export.bytes().is_empty(),
            "a hydrated device archives its vault",
        ),
        Err(error) => assert!(
            !matches!(
                error,
                crate::error::Error::Record(
                    crate::error::RecordError::AuthorityHistoryRequired { .. }
                )
            ),
            "a hydrated vault names no missing history",
        ),
    }
    match fixture.yuki.export_vault_json() {
        Ok(bytes) => assert!(!bytes.is_empty(), "a hydrated device exports its JSON"),
        Err(error) => assert!(
            !matches!(
                error,
                crate::error::Error::Record(
                    crate::error::RecordError::AuthorityHistoryRequired { .. }
                )
            ),
            "a hydrated vault names no missing history",
        ),
    }
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    set_offload_switch(&fixture.yuki, true);
    let offload = fixture
        .yuki
        .offload_authority_history(&fixture.checkpoint)
        .expect("the offload proceeds");
    assert!(
        offload.is_some(),
        "an offload with a standing proof drops rows",
    );
    let error = fixture
        .yuki
        .export_whole_vault(false)
        .expect_err("a whole-vault archive after an offload refuses");
    match error {
        crate::error::Error::Record(crate::error::RecordError::AuthorityHistoryRequired {
            vault_id,
            checkpoint,
            missing,
        }) => {
            assert_eq!(
                checkpoint,
                Some(fixture.checkpoint),
                "the refused archive names the adopted image",
            );
            assert_eq!(
                missing.into_iter().collect::<BTreeSet<_>>(),
                fixture.covered,
                "the refused archive names every covered row",
            );
            assert_eq!(
                vault_id,
                Some(fixture.pin.genesis),
                "the refused archive names the vault",
            );
        }
        other => panic!("expected a missing-history refusal, got {other:?}"),
    }
    let error = fixture
        .yuki
        .export_vault_json()
        .expect_err("a whole-vault JSON export after an offload refuses");
    match error {
        crate::error::Error::Record(crate::error::RecordError::AuthorityHistoryRequired {
            vault_id,
            checkpoint,
            missing,
        }) => {
            assert_eq!(
                checkpoint,
                Some(fixture.checkpoint),
                "the refused JSON names the adopted image",
            );
            assert_eq!(
                missing.into_iter().collect::<BTreeSet<_>>(),
                fixture.covered,
                "the refused JSON names every covered row",
            );
            assert_eq!(
                vault_id,
                Some(fixture.pin.genesis),
                "the refused JSON names the vault",
            );
        }
        other => panic!("expected a missing-history refusal, got {other:?}"),
    }
}

/// T-PUBLIC-BUILD-FROM-ADOPTED (census L5-22 PR 3, finding 4): after the
/// offload, the public checkpoint build starts from the adopted image.
#[test]
fn the_public_checkpoint_build_after_an_offload_starts_from_the_adopted_image() {
    let fixture = cold_offload_fixture();
    let before = fixture
        .yuki
        .build_authority_checkpoint_v2()
        .expect("the public build answers before the offload");
    assert_eq!(
        before.covered.iter().copied().collect::<BTreeSet<_>>(),
        fixture.covered,
        "the public build covers the adopted rows before the offload",
    );
    assert_eq!(
        before.unresolved,
        AuthorityCheckpointUnresolved::default(),
        "the public build holds nothing back before the offload",
    );
    fixture
        .yuki
        .record_archive_custody_proof(
            PeerMachine::Proven {
                machine: fixture.owen_machine,
                key: fixture.owen_key,
            },
            &fixture.fetch,
            &fixture.pages,
        )
        .expect("the device records the builder's custody proof");
    set_offload_switch(&fixture.yuki, true);
    let offload = fixture
        .yuki
        .offload_authority_history(&fixture.checkpoint)
        .expect("the offload proceeds");
    assert!(
        offload.is_some(),
        "an offload with a standing proof drops rows",
    );
    let after = fixture
        .yuki
        .build_authority_checkpoint_v2()
        .expect("the public build answers after the offload");
    assert_eq!(
        after.covered.iter().copied().collect::<BTreeSet<_>>(),
        fixture.covered,
        "the public build still covers the adopted rows after the offload",
    );
    assert_eq!(
        after.unresolved,
        AuthorityCheckpointUnresolved::default(),
        "the public build holds nothing back after the offload",
    );
}
