//! Replicated CLAIMs citing typed sources (PR2 of [PORT-ONLY-DEPENDENCY-NOT-REPLICATED]):
//! selector unit tests for ANSWER PR2-TYPED-REF-ABSENCE = A (28 Nov 14:48).
//!
//! A typed citation never holds its CLAIM. B registers a resident source at its header and a
//! listed one at its listing; deletion evidence marks the CLAIM stale; any other absent source,
//! on every device, gets a cold-citation row (`ri:k:{claim}:{source}`) and the CLAIM lands
//! readable. A source that lands later is judged at its landing. A self-citation is skipped, and
//! a federated copy keeps today's rule.
//!
//! Fixture: the CLAIM rows are own-vault window rows whose raw evidence carries typed citations
//! (`evidence_refs`, the slot `ClaimBody::evidence_refs` reads); B never verifies a citation, so
//! its frontier is opaque. A cited source is an ASSET row with an inline body: it lands through
//! the window like any row, or is planted resident on B where the test does not exercise its
//! transport. Times sit inside window `2026-03`.

use super::claim_source_registration as shared;
use super::{import_from_peer, insert_blob, rematerialize, synced_device, test_vault_with_grant};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
};
use crate::deletion::TombstoneReason;
use crate::sync::{FederationAdmissionRole, SyncResidenceMode};
use crate::temporal::TimeRange;
use crate::write_envelope::claim_body::{
    EVIDENCE_REFS_KEY, EvidenceKind, EvidenceRef, public_evidence_value,
};
use crate::{EntityId, Vault};
use rmpv::Value;

pub(super) fn window_key() -> crate::sync::WindowKey {
    crate::sync::WindowKey::new("2026-03")
}

pub(super) fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("entity id")
}

/// The `sensitivity: public` scope the selector fixtures stamp on a CLAIM.
pub(super) fn public_scope() -> Value {
    Value::Map(vec![(Value::from("sensitivity"), Value::from("public"))])
}

/// An own-vault CLAIM row with `body`, occurred and learned after `at`.
pub(super) fn claim_raw(body: &ClaimBody, at: u64) -> Vec<u8> {
    crate::test_util::entity_record(
        crate::registry::ENTITY_TYPE_CLAIM,
        TimeRange {
            start: at + 10,
            end: at + 10,
        },
        at + 100,
        0,
        &encode_claim_body(body).expect("encode CLAIM"),
    )
}

/// A cited source row that lands through a window as any row does: an ASSET with an inline body.
pub(super) fn source_raw(at: u64) -> Vec<u8> {
    crate::test_util::entity_record(
        crate::registry::ENTITY_TYPE_ASSET,
        TimeRange { start: at, end: at },
        at + 1,
        0,
        b"cited source",
    )
}

/// A CLAIM body whose raw evidence carries one typed citation of each of `sources`.
fn typed_claim_body(sources: &[EntityId]) -> ClaimBody {
    let refs: Vec<EvidenceRef> = sources
        .iter()
        .map(|source| EvidenceRef {
            kind: EvidenceKind::Note,
            entity: source.to_hex(),
            doc: source.to_hex(),
            at: vec![1],
            span: None,
            quote_sha256: None,
        })
        .collect();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(id(0x91)),
        Value::from("Owen"),
        0.8,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .expect("CLAIM body");
    body.evidence = Some(Value::Map(vec![(
        Value::from(EVIDENCE_REFS_KEY),
        public_evidence_value(&refs).expect("typed citations encode"),
    )]));
    body.scope = Some(public_scope());
    assert_eq!(
        body.evidence_refs().expect("typed citations read").len(),
        sources.len(),
        "the fixture CLAIM carries its typed citations"
    );
    body
}

/// Plants `raw` at `id` on `vault` as a resident row, for tests that do not exercise its transport.
pub(super) fn plant_row(vault: &Vault, id: EntityId, raw: &[u8]) {
    vault
        .with_write_txn_grouped(|txn| {
            crate::ports::EntityStoreStaging::port_stage_entity_row(&vault.store, txn, &id, raw)
        })
        .expect("plant row");
}

/// Delivers `rows` and `tombstones` to `device` in one later window update onto `doc`.
pub(super) fn deliver(
    device: &Vault,
    doc: &loro::LoroDoc,
    rows: &[(EntityId, &[u8])],
    tombstones: &[(EntityId, TombstoneReason, u64)],
) {
    let key = window_key();
    let sender = crate::sync::schema::create_window_doc("a", &key);
    for (row, raw) in rows {
        insert_blob(&sender, *row, raw);
    }
    for (row, reason, at) in tombstones {
        shared::insert_tombstone_v2(&sender, *row, *reason, *at);
    }
    sender.commit();
    let update = sender
        .export(loro::ExportMode::all_updates())
        .expect("export update");
    doc.import(&update).expect("device imports update");
    rematerialize(device, doc, &key);
}

/// The full cold-citation row key of `claim` landed without `source`.
pub(super) fn cold_row(claim: EntityId, source: EntityId) -> String {
    format!("ri:k:{}:{}", claim.to_hex(), source.to_hex())
}

/// The full by-source twin key of `claim`'s cold citation of `source`.
pub(super) fn cold_twin(claim: EntityId, source: EntityId) -> String {
    format!("ri:r:{}:{}", source.to_hex(), claim.to_hex())
}

pub(super) fn has_row(vault: &Vault, key: &str) -> bool {
    vault
        .sync_state_get(key)
        .expect("sync state read")
        .is_some()
}

/// The source-pending hold marker the window ingest writes for `claim`.
pub(super) fn held(vault: &Vault, claim: EntityId) -> bool {
    has_row(
        vault,
        &format!("rm:w:{}:{}", window_key().as_str(), claim.to_hex()),
    )
}

pub(super) fn stale(vault: &Vault, claim: EntityId) -> bool {
    let txn = vault.store.env.read_txn().expect("read txn");
    crate::ports::stale_in_txn(&vault.store, &txn, &claim).expect("stale read")
}

// ---------------------------------------------------------------------------
// TR1: an absent typed citation lands the CLAIM readable with its cold-citation row, on a sync-all
// and on an opened device. Fix undone (typed sources not judged): no cold row (fails).
// ---------------------------------------------------------------------------

#[test]
fn an_absent_typed_citation_lands_the_claim_readable_with_its_cold_row() {
    for mode in [SyncResidenceMode::All, SyncResidenceMode::Opened] {
        let (_dir_b, vault_b, _) = test_vault_with_grant(crate::test_util::entity(0x55));
        shared::set_mode(&vault_b, mode);
        let (claim, source) = (id(0x21), id(0x22));
        let key = window_key();
        let doc_a = crate::sync::schema::create_window_doc("a", &key);
        insert_blob(
            &doc_a,
            claim,
            &claim_raw(&typed_claim_body(&[source]), 1_772_400_000),
        );
        doc_a.commit();
        let _doc_b = synced_device(&doc_a, &key, &vault_b);
        assert!(
            vault_b.get_claim(&claim).expect("read B").is_some(),
            "{mode:?}: the CLAIM lands readable without its typed source"
        );
        assert!(
            has_row(&vault_b, &cold_row(claim, source)),
            "{mode:?}: the CLAIM carries its cold-citation row"
        );
        assert!(
            !held(&vault_b, claim),
            "{mode:?}: a typed citation never holds"
        );
        shared::assert_unregistered(&vault_b, claim);
    }
}

// ---------------------------------------------------------------------------
// TR2: a typed citation with deletion evidence on B marks the CLAIM stale. Fix undone: the CLAIM
// lands readable and unmarked (fails).
// ---------------------------------------------------------------------------

#[test]
fn a_typed_citation_with_deletion_evidence_marks_the_claim_stale() {
    let (_dir_b, vault_b, _) = test_vault_with_grant(crate::test_util::entity(0x55));
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (claim, source) = (id(0x23), id(0x24));
    plant_row(&vault_b, source, &source_raw(1_772_410_000));
    let key = window_key();
    let doc_b = crate::sync::schema::create_window_doc("device", &key);
    deliver(
        &vault_b,
        &doc_b,
        &[],
        &[(source, TombstoneReason::UserDelete, 1_772_411_000)],
    );
    assert!(
        vault_b.get(&source).expect("read source").is_none(),
        "B deleted the source before the CLAIM arrives"
    );
    let raw = claim_raw(&typed_claim_body(&[source]), 1_772_410_000);
    deliver(&vault_b, &doc_b, &[(claim, raw.as_slice())], &[]);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_none(),
        "a CLAIM whose typed source B holds deleted lands withdrawn"
    );
    assert!(
        shared::raw_of(&vault_b, claim).len() > crate::batch::ENTITY_METADATA_HEADER_LEN,
        "the withdrawn CLAIM row still lands"
    );
    assert!(stale(&vault_b, claim), "the CLAIM carries its stale mark");
    assert!(!held(&vault_b, claim), "deletion evidence never holds");
}

// ---------------------------------------------------------------------------
// TR3: a typed source that lands after its CLAIM is judged at its landing: the dependency is
// recorded at its header, and a later erase of it withdraws the CLAIM. Arrival hook undone: no
// registration (fails).
// ---------------------------------------------------------------------------

#[test]
fn a_typed_citation_that_lands_later_is_judged_at_its_landing() {
    let (_dir_b, vault_b, _) = test_vault_with_grant(crate::test_util::entity(0x55));
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (claim, source) = (id(0x25), id(0x26));
    let key = window_key();
    let doc_b = crate::sync::schema::create_window_doc("device", &key);
    let claim_row = claim_raw(&typed_claim_body(&[source]), 1_772_420_000);
    deliver(&vault_b, &doc_b, &[(claim, claim_row.as_slice())], &[]);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "the CLAIM lands readable before its source"
    );
    assert!(has_row(&vault_b, &cold_twin(claim, source)));
    let source_row = source_raw(1_772_420_000);
    deliver(&vault_b, &doc_b, &[(source, source_row.as_slice())], &[]);
    assert!(
        vault_b.get(&source).expect("read source").is_some(),
        "the source lands on B"
    );
    shared::assert_registered(&vault_b, claim, source, shared::learned_of(&source_row));
    assert!(
        !has_row(&vault_b, &cold_twin(claim, source)),
        "the landing judged the CLAIM once and took its by-source row"
    );
    assert!(
        has_row(&vault_b, &cold_row(claim, source)),
        "the cold-citation row stays as the record of the cold landing"
    );
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "a standing source keeps the CLAIM readable"
    );
    deliver(
        &vault_b,
        &doc_b,
        &[],
        &[(source, TombstoneReason::UserDelete, 1_772_421_000)],
    );
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_none(),
        "an erase of the landed source withdraws the CLAIM"
    );
    assert!(
        stale(&vault_b, claim),
        "the registered walk marked the CLAIM stale"
    );
}

// ---------------------------------------------------------------------------
// TR4: a typed self-citation is skipped: no wait, no cold row, no self-edge. Self-skip undone: a
// self cold row or a refused self-edge (fails).
// ---------------------------------------------------------------------------

#[test]
fn a_typed_self_citation_is_skipped() {
    let (_dir_b, vault_b, _) = test_vault_with_grant(crate::test_util::entity(0x55));
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let claim = id(0x27);
    let key = window_key();
    let doc_a = crate::sync::schema::create_window_doc("a", &key);
    insert_blob(
        &doc_a,
        claim,
        &claim_raw(&typed_claim_body(&[claim]), 1_772_430_000),
    );
    doc_a.commit();
    let _doc_b = synced_device(&doc_a, &key, &vault_b);
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "a CLAIM citing itself lands readable"
    );
    assert!(
        !has_row(&vault_b, &cold_row(claim, claim)),
        "no self cold row"
    );
    assert!(!held(&vault_b, claim), "a self-citation never holds");
    shared::assert_unregistered(&vault_b, claim);
}

// ---------------------------------------------------------------------------
// TR5: a federated copy of a typed-citation CLAIM keeps today's rule: it lands readable, with no
// cold row, no hold and no registration. Origin filter widening undone: the own-vault hook runs on
// the peer copy and writes a cold row (fails).
// ---------------------------------------------------------------------------

#[test]
fn a_federated_typed_citation_copy_keeps_todays_rule() {
    let member_ref = crate::test_util::entity(0x55);
    let (_dir_b, vault_b, grant_b) = test_vault_with_grant(member_ref);
    super::put_imported_source_trust(&vault_b);
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (claim, source) = (id(0x28), id(0x29));
    let key = window_key();
    let peer = crate::sync::schema::create_window_doc("federation-peer", &key);
    insert_blob(
        &peer,
        claim,
        &claim_raw(&typed_claim_body(&[source]), 1_772_440_000),
    );
    peer.commit();
    let update = peer
        .export(loro::ExportMode::all_updates())
        .expect("export peer CLAIM");
    let live = crate::sync::schema::create_window_doc("local", &key);
    import_from_peer(
        &vault_b,
        &live,
        &key,
        &update,
        (member_ref, grant_b),
        FederationAdmissionRole::Member,
    );
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "a federated CLAIM lands readable"
    );
    assert!(
        !has_row(&vault_b, &cold_row(claim, source)),
        "the own-vault hook never judges a federated copy"
    );
    assert!(!held(&vault_b, claim), "a federated CLAIM is never held");
    shared::assert_unregistered(&vault_b, claim);
}
