//! Replicated deep-doc CLAIMs (PR2 of [PORT-ONLY-DEPENDENCY-NOT-REPLICATED]): selector unit tests
//! for ANSWER PR2-DEEP-DOC-ROOT-ORDER = A (28 Nov 14:49).
//!
//! A deep-doc CLAIM cites its chunk (`candidate_evidence.derivation.source_ref`) and its root
//! page ASSET (its entity subject), and takes the typed-citation rule for both: never held,
//! registered when B can resolve the source, a cold-citation row otherwise. A window pass visits
//! ASSET rows after every other row (`sync/ingest/entity.rs`, `waits_for_sibling_row`), so a page
//! ASSET carried beside its CLAIM is absent at the CLAIM's put and registers at its own landing,
//! later in that pass.
//!
//! Fixture: the CLAIM body carries the evidence `write_deep_batch` writes (the real writer's body
//! is pinned against `cited_sources` in `ingest/docs_tests.rs`). The chunk is planted resident on
//! B; the CLAIM, the page ASSET (inline body) and the root's tombstone travel the real window
//! path. Times sit inside window `2026-03`.

use super::claim_source_registration as shared;
use super::claim_source_typed_refs::{
    claim_raw, cold_row, cold_twin, deliver, has_row, held, id, plant_row, public_scope,
    source_raw, stale, window_key,
};
use super::test_vault_with_grant;
use crate::EntityId;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::deletion::TombstoneReason;
use crate::sync::SyncResidenceMode;
use crate::temporal::TimeRange;
use rmpv::Value;

/// A deep-doc CLAIM body about `root`, derived from `chunk`, as `write_deep_batch` stamps it.
fn deep_claim_body(chunk: EntityId, root: EntityId) -> ClaimBody {
    let v = Value::from;
    let mut body = ClaimBody::new(
        "docs.topic",
        ClaimSubject::Entity(root),
        v("gravity"),
        0.8,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .expect("CLAIM body");
    let candidate = Value::Map(vec![
        (v("kind"), v("imported_evidence")),
        (v("source_id"), v(crate::ingest::DOCS_EXPORT_SOURCE_ID)),
        (v("source_record_id"), v("chunk:hash:fixture.ner.v1:quote")),
        (
            v("derivation"),
            Value::Map(vec![
                (v("source_ref"), v(chunk.to_hex().as_str())),
                (v("source_hash"), v("segment-hash")),
                (v("producer"), v("fixture.ner.v1")),
                (v("source"), v("imported")),
                (v("derived_kind"), v("ner_claim")),
                (v("approval_digest"), v("approval-digest")),
            ]),
        ),
    ]);
    body.evidence = Some(Value::Map(vec![(v("candidate_evidence"), candidate)]));
    body.scope = Some(public_scope());
    body
}

/// A docs chunk row (ASSET_TEXT) planted resident on B.
fn chunk_raw(at: u64) -> Vec<u8> {
    crate::test_util::entity_record(
        crate::registry::ENTITY_TYPE_ASSET_TEXT,
        TimeRange { start: at, end: at },
        at + 2,
        0,
        b"Gravity describes attraction",
    )
}

// ---------------------------------------------------------------------------
// DD1: on a sync-all device the CLAIM and its page ASSET arrive in one window. The CLAIM lands
// readable at once with its cold-citation row, and the page ASSET registers when it lands later
// in that pass. PR1's hold rule here: the CLAIM stays out (fails); arrival hook undone: the root
// never registers (fails).
// ---------------------------------------------------------------------------

#[test]
fn a_deep_doc_claim_lands_readable_before_its_page_asset_in_one_pass() {
    let (_dir_b, vault_b, _) = test_vault_with_grant(crate::test_util::entity(0x55));
    shared::set_mode(&vault_b, SyncResidenceMode::All);
    let (claim, chunk, root) = (id(0x31), id(0x32), id(0x33));
    let at = 1_772_450_000;
    let chunk_row = chunk_raw(at);
    plant_row(&vault_b, chunk, &chunk_row);
    let claim_row = claim_raw(&deep_claim_body(chunk, root), at);
    let root_row = source_raw(at);
    let doc_b = crate::sync::schema::create_window_doc("device", &window_key());
    deliver(
        &vault_b,
        &doc_b,
        &[(claim, claim_row.as_slice()), (root, root_row.as_slice())],
        &[],
    );
    assert!(
        vault_b.get_claim(&claim).expect("read B").is_some(),
        "the deep-doc CLAIM lands readable in the pass that carries its page ASSET"
    );
    assert!(!held(&vault_b, claim), "a deep-doc CLAIM is never held");
    assert!(
        has_row(&vault_b, &cold_row(claim, root)),
        "the CLAIM landed before its page ASSET, with its cold-citation row"
    );
    assert!(
        !has_row(&vault_b, &cold_row(claim, chunk)),
        "the resident chunk registered at its header, with no cold row"
    );
    assert!(
        vault_b.get(&root).expect("read root").is_some(),
        "the page ASSET lands later in the same pass"
    );
    shared::assert_registered(&vault_b, claim, chunk, shared::learned_of(&chunk_row));
    shared::assert_registered(&vault_b, claim, root, shared::learned_of(&root_row));
    assert!(
        !has_row(&vault_b, &cold_twin(claim, root)),
        "the page ASSET's landing judged the CLAIM and took its by-source row"
    );
}

// ---------------------------------------------------------------------------
// DD2: a root erase that reaches B as a row tombstone hides the deep-doc CLAIM: a registered root
// (it landed beside the CLAIM), and a root that never landed (its hard tombstone leaves B's `dt:`
// mark, which the gate reads by the cold-citation row). Fix undone: the CLAIM stays readable
// (fails).
// ---------------------------------------------------------------------------

#[test]
fn a_root_erase_reaching_b_as_a_row_tombstone_hides_the_deep_doc_claim() {
    for (case, root_lands) in [("registered root", true), ("cold root", false)] {
        let (_dir_b, vault_b, _) = test_vault_with_grant(crate::test_util::entity(0x55));
        shared::set_mode(&vault_b, SyncResidenceMode::All);
        let (claim, chunk, root) = (id(0x34), id(0x35), id(0x36));
        let at = 1_772_460_000;
        plant_row(&vault_b, chunk, &chunk_raw(at));
        let claim_row = claim_raw(&deep_claim_body(chunk, root), at);
        let root_row = source_raw(at);
        let doc_b = crate::sync::schema::create_window_doc("device", &window_key());
        let mut rows: Vec<(EntityId, &[u8])> = vec![(claim, claim_row.as_slice())];
        if root_lands {
            rows.push((root, root_row.as_slice()));
        }
        deliver(&vault_b, &doc_b, &rows, &[]);
        assert!(
            vault_b.get_claim(&claim).expect("read B").is_some(),
            "{case}: B serves the deep-doc CLAIM before the erase"
        );
        deliver(
            &vault_b,
            &doc_b,
            &[],
            &[(root, TombstoneReason::UserHardDelete, at + 1_000)],
        );
        assert!(
            vault_b.get(&root).expect("read root").is_none(),
            "{case}: B holds no root after its erase"
        );
        assert!(
            vault_b.get_claim(&claim).expect("read B").is_none(),
            "{case}: the root erase hides the deep-doc CLAIM"
        );
        if root_lands {
            assert!(
                stale(&vault_b, claim),
                "{case}: the registered walk marked the CLAIM stale"
            );
        }
    }
}
