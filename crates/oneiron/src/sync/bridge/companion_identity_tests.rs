//! H161 (W2-T5): a type-74 admission seal counts only when this vault sealed
//! it, or a live machine the owner marked mine did. A peer's self-sealed
//! decision is stored and stays inert until its signer is enrolled as mine.

use ed25519_dalek::SigningKey;
use loro::LoroDoc;

use crate::authority::{
    HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineEncryptionKey, MachineOwnership, MachineRole,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::identity_topology::{
    AdmissionDisposition, AdmissionVerdict, EntityLifecycleState, IdentityOpEvidence,
    IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp, ProposalRuling,
    StoredIdentityOpAction, StoredIdentityOpEvent, SurvivorshipPlan,
    encode_identity_topology_event_body, fold_identity_topology_log, sealed_by_key_for_test,
};
use crate::registry::{
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_PERSON,
};
use crate::store::GateDecisionId;
use crate::sync::ingest::{EntityStep, IngestCtx, ingest_entity_in_txn};
use crate::temporal::TimeRange;
use crate::{EntityId, Result, Vault, VaultConfig};

struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    vault_id: [u8; 32],
}

/// A vault with a host root and a bound owner, as a server keeps it.
fn host() -> Host {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let issuer = crate::test_support::test_host_issuer();
    vault.ensure_host_root_slip(&issuer).unwrap();
    let person = crate::vault::embedded_owner_actor_id().unwrap();
    vault.bind_host_owner_for_test(&issuer, person).unwrap();
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let vault_id = vault.authority_fold().unwrap().vault_id.unwrap();
    Host {
        _dir: dir,
        vault,
        issuer,
        owner,
        vault_id,
    }
}

fn install() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    (dir, vault)
}

/// The owner pairs `install` into `host` with `role`; the machine it joins as.
fn enroll(host: &Host, install: &Vault, role: MachineRole) -> EntityId {
    let request = install
        .machine_enrolment_request(
            host.vault_id,
            MachineEncryptionKey {
                suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
                key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
            },
        )
        .unwrap();
    host.vault
        .enroll_machine(&host.issuer, &host.owner, &request, role)
        .unwrap();
    request.machine
}

fn put_person(vault: &Vault, person: EntityId) {
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"person fixture",
        )
        .unwrap();
}

/// `install` merges `loser` into `survivor` through its own local door.
fn merge_locally(install: &Vault, loser: EntityId, survivor: EntityId) {
    put_person(install, loser);
    put_person(install, survivor);
    let outcome = install
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![loser],
                survivor,
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "fixture rationale".to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            200,
        )
        .unwrap();
    assert!(matches!(outcome, IdentityOpOutcome::Applied { .. }));
}

/// One peer row through the shared ingest ladder, as Observer B delivers it.
fn deliver_blob(vault: &Vault, id: &EntityId, blob: &[u8]) -> Result<()> {
    let doc = LoroDoc::new();
    let tombstones = crate::sync::loro_support::TombstoneIndex::build(&doc.get_map("tombstones"));
    vault.with_write_txn(|wtxn| {
        let ctx = IngestCtx::new(
            vault,
            "2026-03",
            crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
            &tombstones,
        );
        match ingest_entity_in_txn(&ctx, wtxn, &id.to_hex(), Some(blob))? {
            EntityStep::Quarantine(refusal) => Err(refusal.err),
            _ => Ok(()),
        }
    })
}

/// Every row of `from`'s merge reaches `to`: both persons, then each type-74
/// row (the decision and its seal).
fn deliver_merge(to: &Vault, from: &Vault, loser: EntityId, survivor: EntityId) {
    for person in [loser, survivor] {
        deliver_blob(to, &person, &from.get_raw(&person).unwrap().unwrap()).unwrap();
    }
    for id in from
        .entities_by_type(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
        .unwrap()
    {
        deliver_blob(to, &id, &from.get_raw(&id).unwrap().unwrap()).unwrap();
        assert!(to.get_raw(&id).unwrap().is_some(), "the row is stored");
    }
}

fn shell_edge(vault: &Vault, loser: EntityId, survivor: EntityId) -> bool {
    vault
        .edge_exists(&loser, EdgeKind::MergedInto, &survivor)
        .unwrap()
}

/// The entity's state in the live ledger fold, not the stored edges.
fn folded_state(vault: &Vault, entity: EntityId) -> EntityLifecycleState {
    let rtxn = vault.store.env.read_txn().unwrap();
    let events = vault
        .fold_effective_identity_topology_events_in_txn(&rtxn)
        .unwrap();
    fold_identity_topology_log(&events)
        .states
        .get(&entity)
        .copied()
        .unwrap_or(EntityLifecycleState::Active)
}

fn authority_rows(vault: &Vault) -> Vec<EntityId> {
    vault.entities_by_type(ENTITY_TYPE_AUTHORITY_LOG).unwrap()
}

/// Another install of `host`'s vault: it holds the same authority log.
fn replica_of(host: &Host) -> (tempfile::TempDir, Vault) {
    let (dir, replica) = install();
    let entries: Vec<_> = authority_rows(&host.vault)
        .into_iter()
        .map(|id| {
            let raw = host.vault.get_raw(&id).unwrap().unwrap();
            let header = EntityMetadataHeader::parse(&raw).unwrap();
            let entry = crate::authority::decode_authority_log_entry_body(
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )
            .unwrap();
            (
                entry,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
            )
        })
        .collect();
    // The door judges each row against the rows staged before it (H72), so
    // stage the log parents first, as sync and import do.
    let mut staged = std::collections::BTreeSet::new();
    let (mut rest, mut ordered) = (entries, Vec::new());
    while !rest.is_empty() {
        let (ready, waiting): (Vec<_>, Vec<_>) = rest.into_iter().partition(|(entry, ..)| {
            entry
                .parent_hashes
                .iter()
                .all(|parent| staged.contains(parent))
        });
        assert!(!ready.is_empty(), "the host's log names a missing parent");
        staged.extend(
            ready
                .iter()
                .map(|(entry, ..)| crate::authority::authority_entry_hash(entry).unwrap()),
        );
        ordered.extend(ready);
        rest = waiting;
    }
    replica.put_authority_log_entries(&ordered).unwrap();
    assert_eq!(
        replica.authority_fold().unwrap().vault_id,
        Some(host.vault_id)
    );
    (dir, replica)
}

/// One type-74 row a peer minted, delivered as its replicated blob.
fn deliver_row(vault: &Vault, id: EntityId, row: &StoredIdentityOpEvent) {
    let mut blob = vec![ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT];
    for stamp in [row.at; 3] {
        blob.extend_from_slice(&stamp.to_be_bytes());
    }
    blob.extend_from_slice(&encode_identity_topology_event_body(row).unwrap());
    deliver_blob(vault, &id, &blob).unwrap();
    assert!(vault.get_raw(&id).unwrap().is_some(), "stored, not refused");
}

/// The sidecar row that carries `fact` for `core`.
fn fact_row(
    core: &StoredIdentityOpEvent,
    seq: u64,
    fact: AdmissionDisposition,
) -> StoredIdentityOpEvent {
    StoredIdentityOpEvent {
        seq,
        validated_at_write: false,
        invalidated: false,
        at: core.at,
        actor: None,
        source: core.source,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::AdmissionDisposition(fact),
    }
}

/// A peer's own `Auto` merge of two persons this vault holds, sealed by
/// `seal` (a key this vault never enrolled) or not sealed at all; the seal's
/// row and fact.
fn forged_merge(
    vault: &Vault,
    loser: EntityId,
    survivor: EntityId,
    seal: Option<&SigningKey>,
) -> Option<(EntityId, AdmissionDisposition)> {
    let core = StoredIdentityOpEvent {
        seq: 50,
        validated_at_write: false,
        invalidated: false,
        at: 200,
        actor: None,
        source: ClaimSource::Inferred,
        approval: ClaimApprovalStatus::Auto,
        confidence: 1.0,
        evidence: None,
        action: StoredIdentityOpAction::Merge {
            sources: vec![loser],
            survivor,
        },
    };
    let event = EntityId::now();
    deliver_row(vault, event, &core);
    let key = seal?;
    let fact = sealed_by_key_for_test(key, event, &core, AdmissionVerdict::Validated).unwrap();
    let id = EntityId::now();
    deliver_row(vault, id, &fact_row(&core, 51, fact.clone()));
    Some((id, fact))
}

/// The bug: a sync peer mints an `Auto` merge naming two existing persons and
/// seals it with a key it made up. The receiver stores both rows and never
/// draws the shell edge.
#[test]
fn a_merge_sealed_by_an_unknown_key_never_takes_effect() {
    let (_dir, vault) = install();
    let (loser, survivor) = (EntityId::now(), EntityId::now());
    put_person(&vault, loser);
    put_person(&vault, survivor);
    let stranger = SigningKey::generate(&mut rand_core::OsRng);
    forged_merge(&vault, loser, survivor, Some(&stranger));

    assert!(
        !shell_edge(&vault, loser, survivor),
        "a self-sealed merge must not draw a shell edge"
    );
    assert_eq!(folded_state(&vault, loser), EntityLifecycleState::Active);
}

/// The same forgery the other way: a stranger's signed refusal of a merge
/// this vault made must not undo it.
#[test]
fn a_refusal_sealed_by_an_unknown_key_never_undoes_a_merge() {
    let (_dir, vault) = install();
    let (loser, survivor) = (EntityId::now(), EntityId::now());
    merge_locally(&vault, loser, survivor);
    assert!(shell_edge(&vault, loser, survivor));
    let ids = vault
        .entities_by_type(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
        .unwrap();
    let rtxn = vault.store.env.read_txn().unwrap();
    let (event, core) = ids
        .into_iter()
        .filter_map(|id| {
            let row = vault.identity_topology_event_in_txn(&rtxn, &id).unwrap()?;
            matches!(row.action, StoredIdentityOpAction::Merge { .. }).then_some((id, row))
        })
        .next()
        .unwrap();
    drop(rtxn);
    let stranger = SigningKey::generate(&mut rand_core::OsRng);
    let fact = sealed_by_key_for_test(&stranger, event, &core, AdmissionVerdict::RefusedActorClass)
        .unwrap();
    deliver_row(
        &vault,
        EntityId::now(),
        &fact_row(&core, core.seq + 10, fact),
    );

    assert!(
        shell_edge(&vault, loser, survivor),
        "a stranger's refusal must not undo the merge"
    );
    assert_eq!(folded_state(&vault, loser), EntityLifecycleState::Merged);
}

/// Deleting a person a stranger's parked merge names must not seal that
/// merge on this vault's behalf: the owner's own merge of the other person
/// still goes through afterwards.
#[test]
fn a_participant_delete_never_seals_a_strangers_merge() {
    let stranger = SigningKey::generate(&mut rand_core::OsRng);
    for seal in [Some(&stranger), None] {
        let (_dir, vault) = install();
        let (loser, survivor) = (EntityId::now(), EntityId::now());
        put_person(&vault, loser);
        put_person(&vault, survivor);
        forged_merge(&vault, loser, survivor, seal);
        assert!(vault.delete_entity(&survivor).unwrap());

        assert_eq!(folded_state(&vault, loser), EntityLifecycleState::Active);
        merge_locally(&vault, loser, EntityId::now());
    }
}

/// A merge sealed by a second install counts on the host once the owner
/// paired that install as theirs, and on the install itself. A machine the
/// owner paired as rented or as an execution node is not theirs: its merge
/// stays inert on the host.
#[test]
fn a_merge_by_a_paired_machine_counts_only_when_the_owner_said_yours() {
    for (role, counts) in [
        (MachineRole::Owned(MachineOwnership::Yours), true),
        (MachineRole::Owned(MachineOwnership::Rented), false),
        (MachineRole::ExecutionNode, false),
    ] {
        let host = host();
        let (_dir, laptop) = install();
        enroll(&host, &laptop, role);
        let (loser, survivor) = (EntityId::now(), EntityId::now());
        merge_locally(&laptop, loser, survivor);
        assert!(shell_edge(&laptop, loser, survivor), "{role:?}");

        deliver_merge(&host.vault, &laptop, loser, survivor);
        assert_eq!(shell_edge(&host.vault, loser, survivor), counts, "{role:?}");
        assert_eq!(
            folded_state(&host.vault, loser),
            if counts {
                EntityLifecycleState::Merged
            } else {
                EntityLifecycleState::Active
            },
            "{role:?}"
        );
    }
}

/// Order independence: a replica that receives the merge before the
/// enrolment parks it, and draws the edge when the owner's enrolment of the
/// sealing machine reaches it through sync.
#[test]
fn an_enrolment_arriving_after_the_merge_brings_it_into_force() {
    let host = host();
    let (_replica_dir, replica) = replica_of(&host);
    let (_dir, laptop) = install();
    let (loser, survivor) = (EntityId::now(), EntityId::now());
    merge_locally(&laptop, loser, survivor);

    deliver_merge(&replica, &laptop, loser, survivor);
    assert!(
        !shell_edge(&replica, loser, survivor),
        "parked before enrolment"
    );
    assert_eq!(folded_state(&replica, loser), EntityLifecycleState::Active);

    let before = authority_rows(&host.vault);
    enroll(&host, &laptop, MachineRole::Owned(MachineOwnership::Yours));
    for id in authority_rows(&host.vault) {
        if !before.contains(&id) {
            deliver_blob(&replica, &id, &host.vault.get_raw(&id).unwrap().unwrap()).unwrap();
        }
    }
    assert!(
        shell_edge(&replica, loser, survivor),
        "the enrolment brings the parked merge into force"
    );
    assert_eq!(folded_state(&replica, loser), EntityLifecycleState::Merged);
}

/// The owner's own pairing and removal on this vault move the stored edges
/// at once, as the same rows arriving through sync do.
#[test]
fn a_local_enrolment_and_removal_move_the_stored_edges() {
    let host = host();
    let (_dir, laptop) = install();
    let (loser, survivor) = (EntityId::now(), EntityId::now());
    merge_locally(&laptop, loser, survivor);
    deliver_merge(&host.vault, &laptop, loser, survivor);
    assert!(
        !shell_edge(&host.vault, loser, survivor),
        "parked before enrolment"
    );

    let machine = enroll(&host, &laptop, MachineRole::Owned(MachineOwnership::Yours));
    assert!(
        shell_edge(&host.vault, loser, survivor),
        "a local enrolment brings it into force"
    );

    host.vault
        .set_machine_role(&host.issuer, &host.owner, machine, MachineRole::Removed)
        .unwrap();
    assert!(
        !shell_edge(&host.vault, loser, survivor),
        "a local removal takes it out of force"
    );
    assert_eq!(
        folded_state(&host.vault, loser),
        EntityLifecycleState::Active
    );
}

/// A peer's ruling on a proposal this vault parked is no outcome here while
/// no seal this vault counts binds it: no outcome receipt, and no ramp
/// history after a rebuild.
#[test]
fn a_strangers_ruling_is_no_outcome_receipt_or_ramp_history() {
    let (_dir, vault) = install();
    let (_stranger_dir, stranger) = install();
    let (loser, survivor) = (EntityId::now(), EntityId::now());
    put_person(&vault, loser);
    put_person(&vault, survivor);
    let IdentityOpOutcome::Parked { event: proposal } = vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![loser],
                survivor,
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "fixture rationale".to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite {
                approval: ClaimApprovalStatus::Proposed,
                ..IdentityOpWrite::auto(ClaimSource::Inferred)
            },
            200,
        )
        .unwrap()
    else {
        panic!("a proposed merge parks");
    };
    deliver_merge(&stranger, &vault, loser, survivor);
    let before = stranger
        .entities_by_type(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
        .unwrap();
    let (_, ruling) = stranger
        .resolve_identity_proposal(
            &proposal,
            ProposalRuling::Reject,
            &IdentityOpWrite::auto(ClaimSource::UserStated),
            300,
        )
        .unwrap();
    let StoredIdentityOpAction::ProposalResolution { scope, .. } = stranger
        .identity_topology_event(&ruling)
        .unwrap()
        .unwrap()
        .action
    else {
        panic!("a ruling row");
    };
    for id in stranger
        .entities_by_type(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
        .unwrap()
    {
        if !before.contains(&id) {
            deliver_blob(&vault, &id, &stranger.get_raw(&id).unwrap().unwrap()).unwrap();
        }
    }
    assert!(
        vault.get_raw(&ruling).unwrap().is_some(),
        "stored, not refused"
    );

    let outcomes = vault
        .receipts(
            crate::receipt::ReceiptQuery::new(10)
                .with_kind(crate::receipt::ReceiptKind::ProposalOutcome),
        )
        .unwrap();
    assert!(outcomes.is_empty(), "{outcomes:?}");
    vault.rebuild_ramp_stats_from_receipts().unwrap();
    assert!(
        vault
            .scope_stats(&crate::consent_graduation::RampScope::from(&scope))
            .unwrap()
            .is_none()
    );
}

fn lifecycle_receipts(vault: &Vault) -> usize {
    vault
        .receipts(
            crate::receipt::ReceiptQuery::new(10)
                .with_kind(crate::receipt::ReceiptKind::IdentityLifecycle),
        )
        .unwrap()
        .len()
}

/// A stranger's merge is no completed act where this vault reads the raw
/// ledger either: no lifecycle receipt, and erasing its survivor leaves no
/// shell the erase census counts. The vault's own merge still projects.
#[test]
fn a_strangers_merge_is_no_lifecycle_receipt_or_census_shell() {
    let stranger = SigningKey::generate(&mut rand_core::OsRng);
    for seal in [Some(&stranger), None] {
        let (_dir, vault) = install();
        let (loser, survivor) = (EntityId::now(), EntityId::now());
        put_person(&vault, loser);
        put_person(&vault, survivor);
        forged_merge(&vault, loser, survivor, seal);
        assert_eq!(lifecycle_receipts(&vault), 0);

        vault
            .delete_entity_with_reason(&survivor, crate::deletion::DeleteReason::UserHardDelete)
            .unwrap();
        assert_eq!(
            vault.count_dangling_redirect_payloads().unwrap(),
            0,
            "the loser was never a shell, so its own body is no leak"
        );
    }

    let (_dir, vault) = install();
    merge_locally(&vault, EntityId::now(), EntityId::now());
    assert_eq!(lifecycle_receipts(&vault), 1);
}

/// A restore that keeps the vault's current authority carries each seal's
/// marker with the decision it belongs to, and a decision made after the
/// image does not block it.
#[test]
fn a_restore_keeping_authority_keeps_own_merges_in_force() {
    let root = crate::test_support::restore_tempdir();
    let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let (loser, survivor) = (EntityId::now(), EntityId::now());
    merge_locally(&source, loser, survivor);
    let image = root.path().join("image");
    source.snapshot_checkpoint(&image, 100).unwrap();
    merge_locally(&source, EntityId::now(), EntityId::now());

    let (copy, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &root.path().join("copy"),
        VaultConfig::device(),
        &source,
        120,
    )
    .unwrap();
    assert!(shell_edge(&copy, loser, survivor));
    assert_eq!(folded_state(&copy, loser), EntityLifecycleState::Merged);
}

/// A vault's own merges stay in force on a copy restored beside it, which
/// joins as a new machine; a stranger vault that receives the same rows
/// never trusts them.
#[test]
fn own_merges_survive_a_beside_restore_and_never_bind_a_stranger() {
    let root = crate::test_support::restore_tempdir();
    let source = Vault::open(root.path().join("source"), VaultConfig::device()).unwrap();
    let (loser, survivor) = (EntityId::now(), EntityId::now());
    merge_locally(&source, loser, survivor);
    let image = root.path().join("image");
    source.snapshot_checkpoint(&image, 100).unwrap();
    let (copy, _) = Vault::restore_checkpoint_beside(
        &image,
        &root.path().join("copy"),
        VaultConfig::device(),
        &source.side_restore_source().unwrap(),
        120,
    )
    .unwrap();
    let machine = |vault: &Vault| vault.local_machine().unwrap().map(|machine| machine.id);
    assert!(machine(&copy).is_none() || machine(&copy) != machine(&source));
    assert!(shell_edge(&copy, loser, survivor));
    assert_eq!(folded_state(&copy, loser), EntityLifecycleState::Merged);

    let (_dir, stranger) = install();
    deliver_merge(&stranger, &source, loser, survivor);
    assert!(!shell_edge(&stranger, loser, survivor));
    assert_eq!(folded_state(&stranger, loser), EntityLifecycleState::Active);
}

/// Another pairing after the merge: an authority write while topology rows
/// exist records whose seals count, so a change after it starts from a
/// recorded digest, not from none.
fn record_standing(host: &Host) {
    let (_dir, other) = install();
    enroll(host, &other, MachineRole::ExecutionNode);
    assert!(
        host.vault
            .sync_state_get("it:mine_signers")
            .unwrap()
            .is_some()
    );
}

/// A restore that keeps current authority re-decides the image's shell edges
/// under the roster it carries in, both ways: a machine removed since the
/// image no longer holds its merge, and one marked mine since now does.
#[test]
fn a_restore_keeping_authority_redecides_edges_under_the_current_roster() {
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    for (then, now) in [
        (yours, MachineRole::Removed),
        (MachineRole::Owned(MachineOwnership::Rented), yours),
    ] {
        let host = host();
        let (_dir, laptop) = install();
        let machine = enroll(&host, &laptop, then);
        let (loser, survivor) = (EntityId::now(), EntityId::now());
        merge_locally(&laptop, loser, survivor);
        deliver_merge(&host.vault, &laptop, loser, survivor);
        assert_eq!(shell_edge(&host.vault, loser, survivor), then == yours);
        record_standing(&host);
        let root = crate::test_support::restore_tempdir();
        let image = root.path().join("image");
        host.vault.snapshot_checkpoint(&image, 100).unwrap();
        host.vault
            .set_machine_role(&host.issuer, &host.owner, machine, now)
            .unwrap();

        let (copy, _) = Vault::restore_checkpoint_keeping_authority(
            &image,
            &root.path().join("copy"),
            VaultConfig::default(),
            &host.vault,
            120,
        )
        .unwrap();
        assert_eq!(
            shell_edge(&copy, loser, survivor),
            now == yours,
            "{then:?} then {now:?}"
        );
        assert_eq!(
            folded_state(&copy, loser) == EntityLifecycleState::Merged,
            now == yours
        );
    }
}

/// Standing follows the posture a vault opens with. Reopened as a hosted
/// vault, whose root never vouches that a machine is the owner's, a paired
/// laptop's merge leaves force with no authority write in between, and it
/// comes back when the vault opens self-hosted again.
#[test]
fn a_reopen_under_another_posture_redecides_the_stored_edges() {
    let host = host();
    let (_laptop_dir, laptop) = install();
    enroll(&host, &laptop, MachineRole::Owned(MachineOwnership::Yours));
    let (loser, survivor) = (EntityId::now(), EntityId::now());
    merge_locally(&laptop, loser, survivor);
    deliver_merge(&host.vault, &laptop, loser, survivor);
    assert!(shell_edge(&host.vault, loser, survivor));
    record_standing(&host);

    let Host {
        _dir: dir, vault, ..
    } = host;
    drop(vault);
    let hosted = Vault::open(
        dir.path(),
        VaultConfig {
            privacy: crate::config::VaultPrivacyConfig {
                posture: crate::config::HostingPrivacyPosture::Hosted,
                data_key_custody: crate::config::VaultDataKeyCustody::HostManagedKms {
                    key_ref: "kms://example/placeholder".to_owned(),
                },
            },
            ..VaultConfig::default()
        },
    )
    .unwrap();
    assert!(!shell_edge(&hosted, loser, survivor));
    assert_eq!(folded_state(&hosted, loser), EntityLifecycleState::Active);

    drop(hosted);
    let local = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    assert!(shell_edge(&local, loser, survivor));
    assert_eq!(folded_state(&local, loser), EntityLifecycleState::Merged);
}

/// The host's generic sync_state door can neither vouch for a stranger's
/// seal nor touch whose seals this vault last counted: no door but the seal
/// writes that record.
#[test]
fn the_generic_sync_state_door_cannot_vouch_for_a_seal() {
    let (_dir, vault) = install();
    let (loser, survivor) = (EntityId::now(), EntityId::now());
    put_person(&vault, loser);
    put_person(&vault, survivor);
    let stranger = SigningKey::generate(&mut rand_core::OsRng);
    let (fact_id, fact) = forged_merge(&vault, loser, survivor, Some(&stranger)).unwrap();
    let mut seal = fact.signer_pk.to_vec();
    seal.extend_from_slice(&fact.signature);

    for (key, value) in [
        (format!("it:sealed:{}", fact_id.to_hex()), seal),
        ("it:mine_signers".to_owned(), vec![0; 32]),
    ] {
        assert!(
            matches!(
                vault.sync_state_put(&key, &value),
                Err(crate::Error::InvalidConfig(_))
            ),
            "{key}"
        );
        assert!(
            matches!(
                vault.sync_state_delete(&key),
                Err(crate::Error::InvalidConfig(_))
            ),
            "{key}"
        );
    }
    vault
        .with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
        .unwrap();
    assert!(!shell_edge(&vault, loser, survivor));
    assert_eq!(folded_state(&vault, loser), EntityLifecycleState::Active);
}
