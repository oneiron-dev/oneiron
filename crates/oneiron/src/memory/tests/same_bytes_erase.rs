//! Done-means for the opt-in same-bytes erase and the delete preview's shared-bytes impact
//! (owner ruling ERASE-SHARED = B): a default erase drops one record and its own hold on shared
//! bytes; the owner's flag erases every record in the vault holding the same bytes, each with
//! its own receipt; a shared vault holds another actor's record unless a GDPR request asks.

use super::*;
use crate::blob_artifact::blob_artifact_asset_entity_id;
use crate::deletion::{DeleteEntityOptions, DeleteEntityPreview, HeldBytes, LfsChunkImpact};
use crate::federation::{FederationGrantRole, InitialSharedMember};
use crate::origin::lfs::LfsOid;
use std::collections::{BTreeMap, BTreeSet};

const SHARED: &[u8] = b"bytes several records hold";
const ONLY_A: &[u8] = b"bytes only the first record holds";
const ONLY_B: &[u8] = b"bytes only the second record holds";
const OTHER: &[u8] = b"bytes an unrelated record holds";

const FLAG: EraseOptions<'static> = EraseOptions {
    reason: EraseReason::UserHardDelete,
    also_same_bytes: true,
    veto_starter: None,
};

/// The blob door's `blob.version` claims pass the gate only without the default manifest (see
/// `blob_door_round_trips_bytes_and_dedupes_head`).
fn blob_vault() -> (tempfile::TempDir, crate::Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::default())
}

/// The embedded owner's facade: the live owner of a personal vault, who alone sets the
/// same-bytes flag there.
fn owner_facade(vault: &crate::Vault) -> Memory<'_> {
    facade_for(vault, vault.ensure_embedded_owner_actor().expect("owner"))
}

/// A blob artifact `facade`'s actor registers and fills with `versions`, in order.
fn artifact(facade: &Memory<'_>, versions: &[&[u8]]) -> EntityId {
    let receipt = facade
        .put_blob_artifact(&BlobArtifactInput {
            id: None,
            name: "shared.bin".into(),
            media_type: "application/octet-stream".into(),
            occurred_at: 10,
            learned_at: None,
        })
        .expect("artifact");
    for (at, bytes) in (11..).zip(versions) {
        facade
            .append_blob_version(&receipt.id_hex, bytes, None, at, None)
            .expect("append version");
    }
    EntityId::from_hex(&receipt.id_hex).expect("artifact id")
}

fn asset(bytes: &[u8]) -> EntityId {
    blob_artifact_asset_entity_id(blake3::hash(bytes).as_bytes()).expect("asset id")
}

fn live(vault: &crate::Vault, id: &EntityId) -> bool {
    vault.get_raw(id).expect("read").is_some()
}

/// Tombstoned and purged: the row is gone and the local hard-delete marker names it.
fn erased(vault: &crate::Vault, id: &EntityId) -> bool {
    let txn = vault.store.env.read_txn().expect("read txn");
    vault.get_raw_in(&txn, id).expect("read").is_none()
        && vault
            .local_hard_delete_marker_exists_in_txn(&txn, id)
            .expect("marker")
}

fn version(vault: &crate::Vault, artifact: &EntityId, version: u64) -> Option<Vec<u8>> {
    vault
        .read_blob_artifact_version(artifact, version)
        .expect("read version")
}

/// A shared vault whose embedded owner and one member both write. Membership resolves its grant
/// scopes from the default manifest, so the fixture clears that manifest only once the members
/// exist.
fn shared_vault() -> (tempfile::TempDir, crate::Vault, EntityId, EntityId) {
    shared_vault_with(VaultConfig::default(), FederationGrantRole::Member)
}

/// [`shared_vault`] opened with `config`, its second writer holding `role`.
fn shared_vault_with(
    config: VaultConfig,
    role: FederationGrantRole,
) -> (tempfile::TempDir, crate::Vault, EntityId, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), config).expect("open vault");
    let proof = crate::test_util::embedded_owner_proof(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let member = put_person(&vault, 0xE2);
    vault
        .initialize_shared_vault(
            &proof,
            42,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(FederationGrantRole::Owner),
                },
                InitialSharedMember {
                    member_ref: member,
                    role: Some(role),
                },
            ],
            1,
        )
        .expect("shared vault");
    crate::test_util::clear_default_policy_manifest_for_legacy_tests(&vault);
    (dir, vault, owner, member)
}

/// The preview's row for `bytes`.
fn held<'p>(preview: &'p DeleteEntityPreview, bytes: &[u8]) -> &'p HeldBytes {
    preview
        .held_bytes()
        .iter()
        .find(|row| row.content_hash() == *blake3::hash(bytes).as_bytes())
        .expect("held row")
}

/// Rows of a same-bytes outcome by record.
fn rows(outcome: &EntityEraseOutcome) -> BTreeMap<EntityId, SameBytesOutcome> {
    outcome.same_bytes.iter().cloned().collect()
}

#[test]
fn without_the_flag_an_erase_leaves_shared_bytes_to_the_other_record() {
    for erase_door in [true, false] {
        let (_dir, vault) = blob_vault();
        let memory = facade_for(&vault, put_person(&vault, 0xE1));
        let a = artifact(&memory, &[SHARED]);
        let b = artifact(&memory, &[SHARED]);
        let preview = memory.preview_entity_delete(&a).expect("preview");
        let receipt = if erase_door {
            let outcome = memory
                .confirm_entity_erase(&preview, EraseOptions::default())
                .expect("erase");
            assert!(outcome.same_bytes.is_empty(), "no flag, no other record");
            outcome.first
        } else {
            memory
                .confirm_entity_delete(&preview, DeleteEntityOptions { purge: true })
                .expect("delete")
        };
        assert!(receipt.existed && receipt.receipt_ref.is_some());
        assert!(erased(&vault, &a));
        assert!(live(&vault, &b));
        assert_eq!(version(&vault, &b, 1), Some(SHARED.to_vec()));
    }
}

#[test]
fn the_flag_erases_every_record_holding_the_same_bytes_each_with_its_own_receipt() {
    let (_dir, vault) = blob_vault();
    let memory = owner_facade(&vault);
    let a = artifact(&memory, &[SHARED]);
    let b = artifact(&memory, &[ONLY_B, SHARED]);
    let c = artifact(&memory, &[SHARED]);
    let d = artifact(&memory, &[OTHER]);
    let preview = memory.preview_entity_delete(&a).expect("preview");
    let mut matches = vec![b, c];
    matches.sort_unstable();
    assert_eq!(preview.same_bytes_matches(), matches);

    let outcome = memory.confirm_entity_erase(&preview, FLAG).expect("erase");

    assert_eq!(
        outcome
            .same_bytes
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        matches,
        "one row per other holder, in id order; the unrelated record has none"
    );
    let mut receipts = BTreeSet::from([outcome.first.receipt_ref.clone().expect("receipt")]);
    for (id, row) in &outcome.same_bytes {
        let SameBytesOutcome::Erased(receipt) = row else {
            panic!("{id:?} was not erased: {row:?}");
        };
        receipts.insert(receipt.receipt_ref.clone().expect("receipt"));
    }
    assert_eq!(receipts.len(), 3, "each erased record has its own receipt");
    for id in [a, b, c] {
        assert!(erased(&vault, &id), "{id:?} outlived the same-bytes erase");
    }
    assert!(
        !live(&vault, &asset(SHARED)),
        "the shared bytes outlived every holder"
    );
    assert!(
        !live(&vault, &asset(ONLY_B)),
        "a record erased whole keeps nothing"
    );
    assert_eq!(version(&vault, &d, 1), Some(OTHER.to_vec()));
}

#[test]
fn only_a_live_vault_owner_confirms_a_same_bytes_erase() {
    let (_dir, vault, owner, member) = shared_vault();
    let mine = facade_for(&vault, owner);
    let theirs = facade_for(&vault, member);
    let a = artifact(&mine, &[SHARED]);
    let b = artifact(&mine, &[SHARED]);
    let m = artifact(&theirs, &[SHARED]);
    let previews = [
        mine.preview_entity_delete(&a).expect("owner preview"),
        theirs.preview_entity_delete(&m).expect("member preview"),
    ];
    let agent = vault.memory(owner, EdgeActorClass::Agent);

    for preview in &previews {
        for reason in [EraseReason::UserHardDelete, EraseReason::GdprDelete] {
            let options = EraseOptions {
                reason,
                also_same_bytes: true,
                veto_starter: None,
            };
            for (who, facade) in [("member", &theirs), ("agent", &agent)] {
                let refused = facade
                    .confirm_entity_erase(preview, options)
                    .expect_err(who);
                assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{who}");
            }
        }
    }
    for id in [a, b, m] {
        assert!(live(&vault, &id), "a refused flag erased {id:?}");
    }
    assert!(live(&vault, &asset(SHARED)));
}

#[test]
fn in_a_shared_vault_another_actors_record_is_held_not_erased() {
    let (_dir, vault, owner, member) = shared_vault();
    let mine = facade_for(&vault, owner);
    let a = artifact(&mine, &[SHARED]);
    let b = artifact(&facade_for(&vault, member), &[SHARED]);
    let c = artifact(&mine, &[SHARED]);
    let preview = mine.preview_entity_delete(&a).expect("preview");

    let outcome = mine.confirm_entity_erase(&preview, FLAG).expect("erase");

    let rows = rows(&outcome);
    assert_eq!(
        rows.get(&b),
        Some(&SameBytesOutcome::Held {
            reason: SameBytesHold::AnotherOwnersRecord,
            act_id: None,
        })
    );
    assert!(matches!(rows.get(&c), Some(SameBytesOutcome::Erased(_))));
    assert!(erased(&vault, &a) && erased(&vault, &c));
    assert!(live(&vault, &b));
    assert_eq!(version(&vault, &b, 1), Some(SHARED.to_vec()));
}

#[test]
fn a_gdpr_erase_takes_every_holder_without_waiting_for_another_owner() {
    let (_dir, vault, owner, member) = shared_vault();
    let mine = facade_for(&vault, owner);
    let a = artifact(&mine, &[SHARED]);
    let b = artifact(&facade_for(&vault, member), &[SHARED]);
    let c = artifact(&mine, &[SHARED]);
    let preview = mine.preview_entity_delete(&a).expect("preview");

    let outcome = mine
        .confirm_entity_erase(
            &preview,
            EraseOptions {
                reason: EraseReason::GdprDelete,
                also_same_bytes: true,
                veto_starter: None,
            },
        )
        .expect("erase");

    for (id, row) in &outcome.same_bytes {
        assert!(
            matches!(row, SameBytesOutcome::Erased(_)),
            "{id:?} was not erased: {row:?}"
        );
    }
    assert_eq!(outcome.same_bytes.len(), 2);
    for id in [a, b, c] {
        assert!(erased(&vault, &id), "{id:?} outlived the GDPR erase");
    }
    assert!(!live(&vault, &asset(SHARED)));
}

#[test]
fn the_preview_tells_a_last_reference_from_one_of_several_and_goes_stale_with_a_new_holder() {
    let (_dir, vault) = blob_vault();
    let memory = owner_facade(&vault);
    let a = artifact(&memory, &[ONLY_A, SHARED]);
    let b = artifact(&memory, &[SHARED]);
    let preview = memory.preview_entity_delete(&a).expect("preview");
    assert_eq!(preview.held_bytes().len(), 2);
    assert!(held(&preview, ONLY_A).is_last_reference());
    assert_eq!(held(&preview, ONLY_A).holders(), 1);
    assert!(!held(&preview, SHARED).is_last_reference());
    assert_eq!(held(&preview, SHARED).holders(), 2);
    assert_eq!(held(&preview, SHARED).other_holders().to_vec(), vec![b]);
    assert_eq!(preview.same_bytes_matches(), vec![b]);

    // A record taking the shared bytes after the preview makes it stale.
    let e = artifact(&memory, &[SHARED]);
    for options in [EraseOptions::default(), FLAG] {
        let refused = memory
            .confirm_entity_erase(&preview, options)
            .expect_err("stale preview");
        assert_eq!(refused.code, MEMORY_CODE_INVALID_STATE);
    }
    for id in [a, b, e] {
        assert!(live(&vault, &id), "a stale preview erased {id:?}");
    }
}

#[test]
fn an_lfs_preview_tells_shared_chunks_and_the_flag_erases_only_that_object() {
    let (_dir, vault) = blob_vault();
    let memory = owner_facade(&vault);
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let first: Vec<u8> = (0..300 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    // Equal past the first chunk's widest cut, so that chunk is shared; the
    // edit gives each object a chunk of its own.
    let mut second = first.clone();
    second[250 * 1024..254 * 1024].fill(0x42);
    let (first_oid, second_oid) = (LfsOid::digest(&first), LfsOid::digest(&second));
    vault
        .put_lfs_object(first_oid, &first, test_time(20), 20)
        .expect("first object");
    vault
        .put_lfs_object(second_oid, &second, test_time(21), 21)
        .expect("second object");
    let chunks = |oid| -> Vec<[u8; 32]> {
        let mut seen = BTreeSet::new();
        let manifest = vault.lfs_manifest(oid).expect("manifest").expect("live");
        manifest
            .chunks
            .iter()
            .map(|chunk| chunk.hash)
            .filter(|hash| seen.insert(*hash))
            .collect()
    };
    let second_chunks: BTreeSet<_> = chunks(second_oid).into_iter().collect();
    let manifest = vault
        .lfs_object(first_oid)
        .expect("read")
        .expect("live")
        .asset_id;
    let preview = memory.preview_entity_delete(&manifest).expect("preview");

    let rows = preview.lfs_chunks();
    assert_eq!(
        rows.iter()
            .map(LfsChunkImpact::chunk_hash)
            .collect::<Vec<_>>(),
        chunks(first_oid),
        "one row per distinct chunk"
    );
    for row in rows {
        let shared = second_chunks.contains(&row.chunk_hash());
        assert_eq!(row.is_last_reference(), !shared);
        assert_eq!(row.owners(), if shared { 2 } else { 1 });
    }
    assert!(rows.iter().any(|row| !row.is_last_reference()));
    assert!(rows.iter().any(LfsChunkImpact::is_last_reference));
    assert!(preview.held_bytes().is_empty() && preview.same_bytes_matches().is_empty());

    let outcome = memory.confirm_entity_erase(&preview, FLAG).expect("erase");
    assert!(
        outcome.same_bytes.is_empty(),
        "a shared chunk is not the same contents"
    );
    while vault.collect_lfs_garbage(32).expect("collect") != 0 {}

    assert_eq!(vault.lfs_object(first_oid).expect("read"), None);
    assert_eq!(
        vault.get_lfs_object(second_oid).expect("read"),
        Some(second)
    );
    let manifest = vault
        .lfs_object(second_oid)
        .expect("read")
        .expect("live")
        .asset_id;
    let after = memory.preview_entity_delete(&manifest).expect("preview");
    assert!(
        after
            .lfs_chunks()
            .iter()
            .all(LfsChunkImpact::is_last_reference),
        "with the first object collected, every chunk is the second's alone"
    );
}

#[test]
fn after_a_same_bytes_erase_the_same_bytes_can_be_added_again() {
    let (_dir, vault) = blob_vault();
    let memory = owner_facade(&vault);
    let a = artifact(&memory, &[SHARED]);
    artifact(&memory, &[SHARED]);
    let preview = memory.preview_entity_delete(&a).expect("preview");
    memory.confirm_entity_erase(&preview, FLAG).expect("erase");
    assert!(!live(&vault, &asset(SHARED)));

    let again = artifact(&memory, &[SHARED]);

    assert_eq!(version(&vault, &again, 1), Some(SHARED.to_vec()));
    let preview = memory.preview_entity_delete(&again).expect("preview");
    assert!(preview.held_bytes()[0].is_last_reference());
}

#[test]
fn the_erase_door_refuses_the_byte_carrier_and_every_holder_keeps_its_bytes() {
    let (_dir, vault) = blob_vault();
    let memory = owner_facade(&vault);
    let a = artifact(&memory, &[SHARED]);
    let b = artifact(&memory, &[SHARED]);
    let preview = memory
        .preview_entity_delete(&asset(SHARED))
        .expect("carrier preview");
    let mut holders = vec![a, b];
    holders.sort_unstable();
    assert_eq!(held(&preview, SHARED).other_holders().to_vec(), holders);

    for options in [EraseOptions::default(), FLAG] {
        let refused = memory
            .confirm_entity_erase(&preview, options)
            .expect_err("carrier erase");
        assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    }
    assert!(live(&vault, &asset(SHARED)));
    for id in [a, b] {
        assert_eq!(version(&vault, &id, 1), Some(SHARED.to_vec()));
    }
}

#[cfg(feature = "sync")]
#[test]
fn a_match_failing_after_its_tombstone_never_hides_the_erases_around_it() {
    let (_dir, vault) = blob_vault();
    let memory = owner_facade(&vault);
    let a = artifact(&memory, &[SHARED]);
    let b = artifact(&memory, &[SHARED]);
    let c = artifact(&memory, &[SHARED]);
    let (failed, next) = if b < c { (b, c) } else { (c, b) };
    let preview = memory.preview_entity_delete(&a).expect("preview");

    crate::memory::entity_erase::arm_fail_next_match_after_tombstone();
    let outcome = memory.confirm_entity_erase(&preview, FLAG).expect("erase");

    let rows = rows(&outcome);
    assert!(
        matches!(rows.get(&failed), Some(SameBytesOutcome::Failed(_))),
        "{:?}",
        rows.get(&failed)
    );
    assert!(matches!(rows.get(&next), Some(SameBytesOutcome::Erased(_))));
    assert!(outcome.first.receipt_ref.is_some());
    assert!(erased(&vault, &a) && erased(&vault, &next));
}

#[test]
fn a_holder_whose_version_claim_was_deleted_is_held_and_keeps_its_bytes() {
    let (_dir, vault, owner, member) = shared_vault();
    let mine = facade_for(&vault, owner);
    let a = artifact(&mine, &[SHARED]);
    let b = artifact(&facade_for(&vault, member), &[SHARED]);
    let claim = vault.blob_artifact_versions(&b).expect("versions")[0].claim_id;
    vault
        .delete_entity(&claim)
        .expect("soft-delete the version claim");
    let preview = mine.preview_entity_delete(&a).expect("preview");
    assert_eq!(preview.same_bytes_matches(), vec![b]);

    let outcome = mine.confirm_entity_erase(&preview, FLAG).expect("erase");

    assert_eq!(
        rows(&outcome).get(&b),
        Some(&SameBytesOutcome::Held {
            reason: SameBytesHold::AnotherOwnersRecord,
            act_id: None,
        })
    );
    assert!(erased(&vault, &a));
    assert!(live(&vault, &b) && live(&vault, &asset(SHARED)));
}

/// An active brief grant on `brief` that `issuer` creates under the share tests' policy.
fn brief_grant(vault: &crate::Vault, issuer: EntityId, brief: EntityId) -> EntityId {
    let issuer = crate::write_envelope::WriteActor::new(issuer, EdgeActorClass::Human);
    let share = crate::share::Share {
        recipient_ref: put_person(vault, 0xE3),
        brief_ref: brief.to_hex(),
        world_refs: BTreeSet::new(),
        facet_refs: BTreeSet::new(),
        include_unscoped: true,
        status: crate::access_grant::AccessGrantStatus::Active,
        created_at: 42,
        revoked_at: None,
        expires_at: None,
    };
    crate::share::tests::policy(vault, &issuer, &share, true, None).expect("share policy");
    let grant = EntityId::from_bytes([0xC8; 16]).expect("grant id");
    vault.create_share(&grant, &issuer, &share).expect("share");
    grant
}

#[test]
fn a_match_with_its_own_brief_grant_is_erased_and_keeps_no_grant() {
    for reason in [EraseReason::UserHardDelete, EraseReason::GdprDelete] {
        let (_dir, vault) = blob_vault();
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let memory = facade_for(&vault, owner);
        let a = artifact(&memory, &[SHARED]);
        let b = artifact(&memory, &[SHARED]);
        let grant = brief_grant(&vault, owner, b);
        let preview = memory.preview_entity_delete(&a).expect("preview");
        assert!(preview.shared_with().is_empty(), "only the match is shared");

        let outcome = memory
            .confirm_entity_erase(
                &preview,
                EraseOptions {
                    reason,
                    also_same_bytes: true,
                    veto_starter: None,
                },
            )
            .expect("erase");

        let row = rows(&outcome).remove(&b);
        assert!(
            matches!(row, Some(SameBytesOutcome::Erased(_))),
            "{reason:?}: {row:?}"
        );
        assert!(erased(&vault, &a) && erased(&vault, &b), "{reason:?}");
        assert_eq!(
            vault
                .get_share(&grant)
                .expect("read grant")
                .expect("grant")
                .status,
            crate::access_grant::AccessGrantStatus::Revoked,
            "{reason:?}: the erased match's grant outlived it"
        );
    }
}

const WEEK: u64 = 7 * 24 * 60 * 60;

/// A shared vault on a clock the test moves, where the embedded owner wrote `a` and a second
/// owner wrote `b`, both holding the same bytes. The blobs are written without the default
/// manifest (see `blob_vault`); it goes back after them, because a veto window reads its act
/// rows under a manifest.
struct TwoOwners {
    _dir: tempfile::TempDir,
    vault: crate::Vault,
    clock: std::sync::Arc<crate::ports::ManualClock>,
    me: crate::consent::AuthenticatedOwner,
    other: crate::consent::AuthenticatedOwner,
    a: EntityId,
    b: EntityId,
}

fn two_owners() -> TwoOwners {
    let clock = crate::ports::ManualClock::new(100);
    let config = VaultConfig {
        store_clock: clock.bundle(),
        ..VaultConfig::default()
    };
    let (dir, vault, owner, other) = shared_vault_with(config, FederationGrantRole::Owner);
    let me = crate::test_util::embedded_owner_proof(&vault);
    let other_proof = vault
        .authenticate_owner(
            other,
            &other.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("the other owner's proof");
    let a = artifact(&facade_for(&vault, owner), &[SHARED]);
    let b = artifact(&facade_for(&vault, other), &[SHARED]);
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().expect("manifest id"),
        &crate::gate::default_policy_manifest().expect("default manifest"),
    )
    .expect("manifest stores");
    TwoOwners {
        _dir: dir,
        vault,
        clock,
        me,
        other: other_proof,
        a,
        b,
    }
}

/// Erases `a` with the same-bytes flag under the caller's proof; `b`'s row must be held with
/// the `erase` act it started.
fn hold_b(owners: &TwoOwners) -> String {
    let mine = facade_for(&owners.vault, owners.me.actor());
    let preview = mine.preview_entity_delete(&owners.a).expect("preview");
    let outcome = mine
        .confirm_entity_erase(
            &preview,
            EraseOptions {
                veto_starter: Some(&owners.me),
                ..FLAG
            },
        )
        .expect("erase");
    assert!(erased(&owners.vault, &owners.a));
    match rows(&outcome).remove(&owners.b) {
        Some(SameBytesOutcome::Held {
            reason: SameBytesHold::AnotherOwnersRecord,
            act_id: Some(act),
        }) => act,
        row => panic!("the other owner's record was not held with an act: {row:?}"),
    }
}

#[test]
fn a_held_record_is_erased_once_its_owners_veto_window_runs_out() {
    let owners = two_owners();
    let act = hold_b(&owners);
    let mine = facade_for(&owners.vault, owners.me.actor());
    let execute = || mine.execute_completed_entity_erase(&owners.me, &act);

    let early = execute().expect_err("the veto window is open");
    assert_eq!(early.code, MEMORY_CODE_INVALID_STATE, "{early:?}");
    owners
        .vault
        .change_authority_objection(&owners.other, &act, true)
        .expect("the other owner objects");
    owners.clock.set(100 + WEEK + 1);
    let vetoed = execute().expect_err("an objection holds the erase past the deadline");
    assert_eq!(vetoed.code, MEMORY_CODE_INVALID_STATE, "{vetoed:?}");
    assert!(live(&owners.vault, &owners.b));
    owners
        .vault
        .change_authority_objection(&owners.other, &act, false)
        .expect("the other owner withdraws");
    facade_for(&owners.vault, owners.other.actor())
        .execute_completed_entity_erase(&owners.other, &act)
        .expect_err("only the act's starter executes it");
    assert!(live(&owners.vault, &owners.b));

    let receipt = execute().expect("the window ran out unopposed");

    assert!(
        receipt.existed && receipt.receipt_ref.is_some(),
        "{receipt:?}"
    );
    assert!(erased(&owners.vault, &owners.b));
    assert!(
        !live(&owners.vault, &asset(SHARED)),
        "the last holder took the bytes"
    );
    assert_eq!(
        execute().expect("a retry"),
        receipt,
        "a retry returns the first erase's receipt"
    );
}

#[cfg(feature = "sync")]
#[test]
fn a_held_erase_failing_after_its_tombstone_stays_claimed_by_that_request() {
    let owners = two_owners();
    let act = hold_b(&owners);
    let mine = facade_for(&owners.vault, owners.me.actor());
    owners.clock.set(100 + WEEK);
    let learned_at = crate::batch::EntityMetadataHeader::parse(
        &owners
            .vault
            .get_raw(&owners.b)
            .expect("read")
            .expect("live"),
    )
    .expect("header")
    .learned_at;
    let published = || {
        owners
            .vault
            .entity_deletion_metadata(&owners.b, learned_at)
            .expect("deletion metadata")
            .and_then(|deletion| deletion.request_id)
    };

    crate::deletion::arm_fail_after_tombstone_before_purge();
    mine.execute_completed_entity_erase(&owners.me, &act)
        .expect_err("fails after its tombstone");

    let request = published().expect("the tombstone was published");
    let claimed = owners
        .vault
        .pending_authority_act(&act)
        .expect("read act")
        .expect("act")
        .execution
        .expect("the act was claimed with the tombstone");
    assert_eq!(claimed.request, request);
    assert_eq!(claimed.receipt, None);
    let retry = mine
        .execute_completed_entity_erase(&owners.me, &act)
        .expect_err("its deletion recovery finishes the claimed request");
    assert_eq!(retry.code, MEMORY_CODE_INVALID_STATE, "{retry:?}");
    assert_eq!(
        published(),
        Some(request),
        "a retry published no second request"
    );
    assert!(live(&owners.vault, &owners.b), "and purged nothing");
}
