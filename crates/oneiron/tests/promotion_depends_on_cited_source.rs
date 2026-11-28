//! PROMOTED-CLAIM-SOURCE-DEPENDENCY-GAPS paths 2 and 3: a CLAIM written from
//! an inline-text TURN or from a cited CLAIM is withdrawn when that source is
//! erased. The settlement Keep lands through `record_message_dependencies_in_txn`
//! (a native Keep through settlement.rs, an imported Keep staged through
//! imported_keep.rs), the same function the promotion writer's verified arm and
//! the other callers share, so one edge withdraws every row written from the
//! erased source.
//!
//! No entry point reaches the writer's verified arm without the sealed
//! executor, and the conflict marker doors record no dependency at all, so
//! these tests settle: the staged and kept CLAIMs are the rows under test.
//! The marker withdrawal case has no test: see the leg report.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test promotion_depends_on_cited_source`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteReason;
use oneiron::dreamer_consolidation::{ConflictSettleOutcome, ConflictSettlement};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::derive::{
    open_conflict_with_alternative, open_conflict_with_imported_alternative, settlement_kept_claim,
};
use oneiron::test_doors::nightly_arc_summary::cited_refs;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    subject: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open the vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("install signing keys");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner");
        let issuer = HostSlipIssuer::from_secret(b"promotion-depends-on-cited-source")
            .expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("bind the owner to the host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine signers");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");

        // One known subject the fixture's claims are about.
        let mut named = Vec::new();
        rmpv::encode::write_value(
            &mut named,
            &rmpv::Value::Map(vec![("name".into(), "Mira Vale".into())]),
        )
        .expect("encode the named PERSON");
        let subject = EntityId::now();
        let at = vault.now_recorded_at();
        vault
            .put_entity(
                &subject,
                ENTITY_TYPE_PERSON,
                TimeRange { start: at, end: at },
                at,
                &named,
            )
            .expect("write the named PERSON");
        Self {
            vault,
            owner,
            proof,
            subject,
            _dir: dir,
        }
    }

    /// The owner's Keep of the retained `alternative` of `marker`.
    fn keep(&self, marker: EntityId, alternative: EntityId) -> ConflictSettleOutcome {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .settle_conflict(
                Some(&self.proof),
                marker,
                ConflictSettlement::Keep(alternative),
                self.vault.now_recorded_ms(),
            )
            .expect("the owner's Keep is accepted")
    }
}

/// The owner's own claim about the fixture's subject; its id. Observed, Auto
/// and active in the default facet, as the member a retained alternative may
/// cite (a generated claim never corroborates).
fn owner_claim(fixture: &Fixture, value: &str) -> EntityId {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(fixture.subject),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(ClaimSource::Observed);
    body.scope = None;
    body.scope_facet = fixture.vault.default_facet().expect("the default facet");
    let id = EntityId::now();
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_claim(&id, &body, TimeRange { start: at, end: at }, at)
        .expect("the owner's own claim");
    id
}

/// The owner's Keep of an imported alternative, staged in its import's review:
/// the staged CLAIM and the inline TURN the door cited for it.
fn staged_imported_keep(fixture: &Fixture) -> (EntityId, EntityId) {
    let member = owner_claim(fixture, "the kept note");
    let (marker, alternative) =
        open_conflict_with_imported_alternative(&fixture.vault, member, "the imported words")
            .expect("an open conflict with an imported alternative");
    let outcome = fixture.keep(marker, alternative);
    let ConflictSettleOutcome::ImportReviewPending { staged, .. } = &outcome else {
        panic!("the owner's Keep of an imported alternative stages: {outcome:?}");
    };
    assert_eq!(staged.marker, marker, "the staged Keep names the marker");
    assert_eq!(
        staged.alternative, alternative,
        "the staged Keep names the alternative"
    );
    let kept = staged.staged;
    assert!(
        fixture
            .vault
            .get_claim(&kept)
            .expect("read the staged CLAIM")
            .is_some(),
        "the CLAIM staged from the imported TURN does not read"
    );
    let refs = cited_refs(&fixture.vault, &marker).expect("read the marker's cited refs");
    assert_eq!(
        refs.len(),
        1,
        "the marker cites exactly its inline TURN: {refs:?}"
    );
    (kept, refs[0])
}

#[test]
fn a_claim_from_an_inline_turn_is_withdrawn_with_the_turn() {
    let f = Fixture::new();
    let (kept, turn) = staged_imported_keep(&f);
    assert!(
        f.vault.delete_entity(&turn).expect("soft delete the TURN"),
        "the TURN existed"
    );
    assert!(
        f.vault
            .get_claim(&kept)
            .expect("read the staged CLAIM")
            .is_none(),
        "the CLAIM written from an erased inline TURN still reads"
    );
}

#[test]
fn a_claim_from_an_inline_turn_is_withdrawn_with_the_hard_deleted_turn() {
    let f = Fixture::new();
    let (kept, turn) = staged_imported_keep(&f);
    let deleted = f
        .vault
        .delete_entity_with_reason_as_owner(&f.proof, &turn, DeleteReason::UserHardDelete)
        .expect("the owner hard deletes the TURN");
    assert!(deleted.existed, "the TURN existed");
    assert!(
        f.vault
            .get_claim(&kept)
            .expect("read the staged CLAIM")
            .is_none(),
        "the CLAIM written from a hard-deleted inline TURN still reads"
    );
}

#[test]
fn a_claim_from_a_cited_claim_is_withdrawn_with_that_claim() {
    let f = Fixture::new();
    let a = owner_claim(&f, "the cited note");
    let (marker, alternative) = open_conflict_with_alternative(&f.vault, a, "the rival note")
        .expect("an open conflict with a retained alternative");
    let outcome = f.keep(marker, alternative);
    let ConflictSettleOutcome::Settled(receipt) = &outcome else {
        panic!("the owner's Keep of a native alternative settles: {outcome:?}");
    };
    let kept = settlement_kept_claim(&f.vault, f.subject, receipt.resolved)
        .expect("read the settlement's kept claim")
        .expect("the settlement kept a claim");
    assert!(
        f.vault
            .get_claim(&kept)
            .expect("read the kept CLAIM")
            .is_some(),
        "the CLAIM kept from the cited CLAIM does not read"
    );
    assert!(
        f.vault
            .delete_entity(&a)
            .expect("soft delete the cited CLAIM"),
        "the cited CLAIM existed"
    );
    assert!(
        f.vault
            .get_claim(&kept)
            .expect("read the kept CLAIM")
            .is_none(),
        "the CLAIM written from an erased CLAIM still reads"
    );
}

#[test]
fn a_claim_from_a_witnessed_turn_still_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("vault");
    let reply = json!({
        "persons": [{"id": "new:P1", "name": "owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [
            {
                "subject": "new:P1", "predicate": "profile.name", "value": "owen",
                "confidence": 0.8, "evidence_refs": [{"source": "T1", "quote": "owen"}],
            },
            {
                "subject": "new:P1", "predicate": "profile.nickname", "value": "o",
                "confidence": 0.8, "evidence_refs": [{"source": "T1", "quote": "call me o"}],
            },
        ],
    })
    .to_string();
    let pass = consolidate_unbound_turn(&vault, "my name is owen, call me o", None, None, &reply)
        .expect("one consolidation pass");
    assert_eq!(pass.landed.len(), 2, "both claims land: {:?}", pass.landed);
    for claim in &pass.landed {
        assert!(
            vault
                .get_claim(claim)
                .expect("read the landed CLAIM")
                .is_some(),
            "a CLAIM from a witnessed TURN does not read"
        );
    }
}
