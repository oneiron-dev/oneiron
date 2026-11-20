//! FIX [BATCH-RAW-CLAIM-PUT-SKIPS-ARCHIVED-PERSON-RESTORE] and FIX
//! [COMM-PROJECTED-CLAIM-SKIPS-ARCHIVED-PERSON-RESTORE] (Engine NOTE 21 Nov
//! 02:07, under ARCH-0073 §6: "a re-mention restores the archived record").
//! The vault cleanup archives only a PERSON no live claim is about, so a
//! claim that lands about a PERSON under the cleanup's archive marker
//! restores her in the claim's own write. #9880 wired put_claim and every
//! claim candidate door; these are the two doors it left out:
//!
//! - a raw CLAIM row a batch puts (the owner's `Vault::batch().put`, committed
//!   or applied in the caller's write, and a bound handle's raw put): the
//!   restore's collector read only claim candidates;
//! - a `comm.*` head the comm projector writes about a PERSON party, from
//!   put_claim's projector-only route, a batch's routed put, or a recorded
//!   inbound event projected after the cleanup archived her: the projector
//!   mints the head at its own derived id, past put_claim's restore. The
//!   Engine rules a projector head from an inbound event a re-mention too.
//!
//! Each PERSON is a stored row the fixture archives as the cleanup does
//! (`archive_as_cleanup` writes the cleanup's archive marker), so no test
//! depends on the cleanup's listing rules.
//!
//! Red without the fix (the first seven tests): the claim or head lands and
//! the PERSON keeps her archive marker. Guards that hold with and without it
//! (the last two): a raw batch claim, or a comm head, about a PERSON the
//! owner archived herself lifts nothing.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_batch_put_and_comm_head_restore_archived_person`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::comm::{
    CommClaimValue, PREDICATE_COMM_LAST_TOUCH, count_active_comm_claims, record_comm_inbound_reply,
    resolve_or_create_comm_party, run_comm_projector,
};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::test_doors::derive::row_live;
use oneiron::test_doors::dreamer_promotion_seconds::open_auto_promotion_vault;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, DeleteReason,
    EdgeActorClass, EntityId, RawEntityPut, TimeRange, Vault, VaultConfig,
};

const PARTY: &str = "ann@example.com";
const CHANNEL: &str = "email";

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A stored PERSON named `name`.
fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("name", name)]))
        .expect("a PERSON body");
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(at), at, &body)
        .expect("FIXTURE: a live PERSON");
    id
}

/// `id` archived as the cleanup archives a PERSON no live claim is about:
/// its row and body stay, under the cleanup's archive marker.
fn archive(vault: &Vault, id: EntityId) {
    archive_as_cleanup(vault, &id).expect("FIXTURE: the cleanup's archive marker");
    assert!(
        vault.archived_entity(&id).expect("read").is_some(),
        "FIXTURE: she is archived by the cleanup"
    );
    assert!(
        !row_live(vault, id).expect("read"),
        "FIXTURE: the cleanup's archive hides her row"
    );
}

/// A stored PERSON named `name`, archived by the cleanup.
fn archived_person(vault: &Vault, name: &str) -> EntityId {
    let id = person(vault, name);
    archive(vault, id);
    id
}

/// The comm party for [`PARTY`], archived by the cleanup.
fn archived_party(vault: &Vault) -> EntityId {
    let party = resolve_or_create_comm_party(vault, PARTY).expect("FIXTURE: the comm party");
    archive(vault, party);
    party
}

/// `person` is the owner's to read again: no archive marker, and her row is
/// live.
fn assert_restored(vault: &Vault, person: EntityId, door: &str) {
    assert!(
        vault.archived_entity(&person).expect("read").is_none(),
        "the claim {door} landed restored her: she bears no archive marker"
    );
    assert!(
        row_live(vault, person).expect("read"),
        "her row is live after the claim {door} landed"
    );
}

/// One live last-touch head about [`PARTY`] on [`CHANNEL`] stands.
fn assert_one_touch_head(vault: &Vault, door: &str) {
    assert_eq!(
        count_active_comm_claims(vault, PREDICATE_COMM_LAST_TOUCH, PARTY, CHANNEL)
            .expect("count the comm heads"),
        1,
        "the last-touch head {door} brought stands"
    );
}

/// A raw CLAIM body about `subject`, as a host's raw write carries it: a
/// note at Auto, naming no source (the source belongs to a write envelope).
fn raw_claim_body(vault: &Vault, subject: EntityId) -> Vec<u8> {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("prefers green tea"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: claim body");
    body.source = None;
    body.scope_facet = vault.default_facet().expect("FIXTURE: default facet");
    encode_claim_body(&body).expect("FIXTURE: encode the claim")
}

/// A live last-touch CLAIM body about `party` on [`CHANNEL`] at `at`.
fn touch_body(party: EntityId, at: u64) -> ClaimBody {
    CommClaimValue::LastTouch {
        party_ref: party,
        channel_class: CHANNEL.to_owned(),
        occurred_at: at,
    }
    .claim_body()
    .expect("FIXTURE: the comm claim body")
}

/// A device vault and its embedded owner, for a bound handle's raw put.
fn device_vault(dir: &std::path::Path) -> (Vault, EntityId) {
    let vault = Vault::open(dir, VaultConfig::device()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    (vault, owner)
}

#[test]
fn an_owner_batch_raw_claim_put_about_a_person_the_cleanup_archived_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let ann = archived_person(&vault, "Ann");

    let id = EntityId::now();
    let data = raw_claim_body(&vault, ann);
    let now = vault.now_recorded_at();
    vault
        .batch()
        .put(&id, ENTITY_TYPE_CLAIM, range(now), now, &data)
        .commit()
        .expect("the batch's raw claim about her lands");
    assert!(
        vault.get_claim(&id).expect("read").is_some(),
        "the claim is stored"
    );
    assert_restored(&vault, ann, "a batch's raw put committed");
}

#[test]
fn an_owner_batch_raw_claim_put_applied_in_its_callers_write_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let ann = archived_person(&vault, "Ann");

    let id = EntityId::now();
    let data = raw_claim_body(&vault, ann);
    let now = vault.now_recorded_at();
    vault
        .with_write_txn(|wtxn| {
            vault
                .batch()
                .put(&id, ENTITY_TYPE_CLAIM, range(now), now, &data)
                .apply(wtxn)
        })
        .expect("the batch's raw claim about her lands in the caller's write");
    assert!(
        vault.get_claim(&id).expect("read").is_some(),
        "the claim is stored"
    );
    assert_restored(&vault, ann, "a batch's raw put applied");
}

#[test]
fn a_bound_raw_claim_put_about_a_person_the_cleanup_archived_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = device_vault(dir.path());
    let ann = archived_person(&vault, "Ann");

    let id = EntityId::now();
    let data = raw_claim_body(&vault, ann);
    let now = vault.now_recorded_at();
    vault
        .memory(owner, EdgeActorClass::Human)
        .raw_put_entity(RawEntityPut {
            id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: range(now),
            learned_at: now,
            data: &data,
        })
        .expect("the bound raw claim about her lands");
    assert!(
        vault.get_claim(&id).expect("read").is_some(),
        "the claim is stored"
    );
    assert_restored(&vault, ann, "a bound raw put");
}

#[test]
fn an_owner_put_claim_of_a_comm_touch_about_a_party_the_cleanup_archived_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let ann = archived_party(&vault);

    let now = vault.now_recorded_at();
    vault
        .put_claim(&EntityId::now(), &touch_body(ann, 10), range(now), now)
        .expect("the owner's comm touch about her lands as the projector's head");
    assert_restored(&vault, ann, "put_claim's projector route");
    assert_one_touch_head(&vault, "put_claim");
}

#[test]
fn an_owner_batch_comm_touch_put_about_a_party_the_cleanup_archived_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let ann = archived_party(&vault);

    let mut body = touch_body(ann, 10);
    body.source = None;
    let data = encode_claim_body(&body).expect("FIXTURE: encode the comm claim");
    let now = vault.now_recorded_at();
    vault
        .batch()
        .put(&EntityId::now(), ENTITY_TYPE_CLAIM, range(now), now, &data)
        .commit()
        .expect("the batch's comm touch about her lands as the projector's head");
    assert_restored(&vault, ann, "a batch's routed comm put");
    assert_one_touch_head(&vault, "a batch's routed comm put");
}

#[test]
fn a_bound_comm_touch_put_about_a_party_the_cleanup_archived_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = device_vault(dir.path());
    let ann = archived_party(&vault);

    let mut body = touch_body(ann, 10);
    body.source = None;
    let data = encode_claim_body(&body).expect("FIXTURE: encode the comm claim");
    vault
        .memory(owner, EdgeActorClass::Human)
        .raw_put_entity(RawEntityPut {
            id: EntityId::now(),
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: range(10),
            learned_at: 10,
            data: &data,
        })
        .expect("the bound comm touch about her lands");
    assert_restored(&vault, ann, "a bound raw comm put");
    assert_one_touch_head(&vault, "a bound raw comm put");
}

#[test]
fn an_inbound_reply_projected_after_the_cleanup_archived_its_party_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let ann = resolve_or_create_comm_party(&vault, PARTY).expect("FIXTURE: the comm party");
    // The reply is recorded about her party, then the cleanup archives her
    // before the projector's pass reaches the event.
    record_comm_inbound_reply(&vault, PARTY, CHANNEL, 10).expect("FIXTURE: the inbound reply");
    archive(&vault, ann);

    run_comm_projector(&vault).expect("the projector's pass");
    assert_restored(&vault, ann, "the projector's head for her reply");
    assert_one_touch_head(&vault, "her reply");
}

#[test]
fn a_batch_raw_claim_put_about_a_person_the_owner_archived_lifts_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_auto_promotion_vault(dir.path()).expect("vault");
    let ann = person(&vault, "Ann");
    // The owner's own soft archive: an archive marker with the owner's
    // reason, never the cleanup's.
    vault
        .delete_entity_with_reason(&ann, DeleteReason::UserDelete)
        .expect("the owner archives her");
    assert!(
        !row_live(&vault, ann).expect("read"),
        "FIXTURE: the owner's archive hides her row"
    );

    let data = raw_claim_body(&vault, ann);
    let now = vault.now_recorded_at();
    let put = vault
        .batch()
        .put(&EntityId::now(), ENTITY_TYPE_CLAIM, range(now), now, &data)
        .commit();
    assert!(
        !row_live(&vault, ann).expect("read"),
        "the owner's archive stands: a raw batch claim lifts only the cleanup's marker: {put:?}"
    );
    assert!(
        vault.archived_entity(&ann).expect("read").is_none(),
        "the raw batch claim wrote no cleanup marker: {put:?}"
    );
}

#[test]
fn a_comm_touch_about_a_party_the_owner_archived_lifts_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_auto_promotion_vault(dir.path()).expect("vault");
    let ann = resolve_or_create_comm_party(&vault, PARTY).expect("FIXTURE: the comm party");
    vault
        .delete_entity_with_reason(&ann, DeleteReason::UserDelete)
        .expect("the owner archives her");
    assert!(
        !row_live(&vault, ann).expect("read"),
        "FIXTURE: the owner's archive hides her row"
    );

    let now = vault.now_recorded_at();
    let put = vault.put_claim(&EntityId::now(), &touch_body(ann, 10), range(now), now);
    assert!(
        !row_live(&vault, ann).expect("read"),
        "the owner's archive stands: a comm head lifts only the cleanup's marker: {put:?}"
    );
    assert!(
        vault.archived_entity(&ann).expect("read").is_none(),
        "the comm head wrote no cleanup marker: {put:?}"
    );
}
