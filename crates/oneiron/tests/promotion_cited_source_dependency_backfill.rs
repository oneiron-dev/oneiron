//! S1-OLD-ROWS: a row written before S1 from an inline TURN or a cited CLAIM gets its
//! dependency, or is withdrawn, by a one-time pass at open.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test promotion_cited_source_dependency_backfill`.
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
use oneiron::test_doors::cited_source_dependency_backfill::{
    cited_source_dependency_backfill_counts, cited_source_dependency_sources,
    forget_cited_source_dependencies, reset_cited_source_dependency_backfill,
    write_claim_citing_missing_source, write_claim_citing_source_at,
    write_claim_citing_source_with_current_binding, write_claim_with_undecodable_locators,
};
use oneiron::test_doors::claim_value_redaction::redact_claim_value_fields;
use oneiron::test_doors::derive::{
    open_conflict_with_alternative, open_conflict_with_imported_alternative, settlement_kept_claim,
};
use oneiron::test_doors::nightly_arc_summary::cited_refs;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    subject: EntityId,
    dir: tempfile::TempDir,
    keystore: Arc<MemoryKeystore>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let keystore = Arc::new(MemoryKeystore::new());
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open the vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault
            .prepare_install_signing()
            .expect("install signing keys");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner");
        let issuer = HostSlipIssuer::from_secret(b"promotion-cited-source-dependency-backfill")
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
            dir,
            keystore,
        }
    }

    /// Drops the vault and opens the same directory again with the same
    /// keystore, reinstalling the signing, host-root, machine and owner-proof
    /// state the next step needs.
    fn reopen(self) -> Self {
        let Fixture {
            vault,
            owner: _,
            proof: _,
            subject,
            dir,
            keystore,
        } = self;
        drop(vault);
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopen the vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault
            .prepare_install_signing()
            .expect("install signing keys");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner");
        let issuer = HostSlipIssuer::from_secret(b"promotion-cited-source-dependency-backfill")
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
        Self {
            vault,
            owner,
            proof,
            subject,
            dir,
            keystore,
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

/// A CLAIM through the public `put_claim` door whose `body.evidence` carries
/// a claim-shaped locator to `source` that no Dreamer run verified: unstamped
/// top-level evidence with a 32-zero-byte hash; its id.
fn caller_claim_citing_source(fixture: &Fixture, source: EntityId) -> EntityId {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(fixture.subject),
        rmpv::Value::from("the caller's note"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(ClaimSource::Observed);
    body.scope = None;
    body.scope_facet = fixture.vault.default_facet().expect("the default facet");
    body.evidence = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("locators"),
        rmpv::Value::Array(vec![rmpv::Value::Map(vec![
            (
                rmpv::Value::from("source_id"),
                rmpv::Value::Binary(source.as_bytes().to_vec()),
            ),
            (
                rmpv::Value::from("claim_id"),
                rmpv::Value::Binary(source.as_bytes().to_vec()),
            ),
            (
                rmpv::Value::from("content_hash"),
                rmpv::Value::Binary(vec![0; 32]),
            ),
        ])]),
    )]));
    let id = EntityId::now();
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_claim(&id, &body, TimeRange { start: at, end: at }, at)
        .expect("the caller's claim");
    id
}

/// The owner's own claim about the fixture's subject with a map value holding
/// `secret_note` (for redaction) beside a public field; its id.
fn owner_map_claim(fixture: &Fixture) -> EntityId {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(fixture.subject),
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("secret_note"),
                rmpv::Value::from("the door code"),
            ),
            (
                rmpv::Value::from("public_note"),
                rmpv::Value::from("likes tea"),
            ),
        ]),
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
        .expect("the owner's map claim");
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
fn an_old_row_gets_its_inline_turn_dependency() {
    let f = Fixture::new();
    let (kept, turn) = staged_imported_keep(&f);
    let sources =
        cited_source_dependency_sources(&f.vault, kept).expect("read the staged CLAIM's sources");
    assert!(
        sources.contains(&turn),
        "S1 did not record the staged CLAIM's inline TURN dependency"
    );
    forget_cited_source_dependencies(&f.vault, kept).expect("strip the CLAIM's dependency");
    let sources =
        cited_source_dependency_sources(&f.vault, kept).expect("read the staged CLAIM's sources");
    assert!(
        sources.is_empty(),
        "the staged CLAIM keeps a dependency after the strip"
    );
    reset_cited_source_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&kept).expect("read the CLAIM").is_some(),
        "the old row does not read after the backfill"
    );
    let sources =
        cited_source_dependency_sources(&f.vault, kept).expect("read the staged CLAIM's sources");
    assert!(
        sources.contains(&turn),
        "the backfill did not restore the old row's inline TURN dependency"
    );
    assert!(
        f.vault.delete_entity(&turn).expect("soft delete the TURN"),
        "the TURN existed"
    );
    assert!(
        f.vault
            .get_claim(&kept)
            .expect("read the staged CLAIM")
            .is_none(),
        "the old row written from a deleted inline TURN still reads after the backfill"
    );
}

#[test]
fn an_old_row_whose_inline_turn_was_deleted_is_withdrawn() {
    let f = Fixture::new();
    let (kept, turn) = staged_imported_keep(&f);
    forget_cited_source_dependencies(&f.vault, kept).expect("strip the CLAIM's dependency");
    assert!(
        f.vault.delete_entity(&turn).expect("soft delete the TURN"),
        "the TURN existed"
    );
    assert!(
        f.vault.get_claim(&kept).expect("read the CLAIM").is_some(),
        "the CLAIM does not read before the backfill"
    );
    reset_cited_source_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&kept).expect("read the CLAIM").is_none(),
        "the backfill left an old row whose inline TURN was deleted"
    );
}

#[test]
fn an_old_row_whose_cited_claim_was_deleted_is_withdrawn() {
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
    forget_cited_source_dependencies(&f.vault, kept).expect("strip the CLAIM's dependency");
    let deleted = f
        .vault
        .delete_entity_with_reason_as_owner(&f.proof, &a, DeleteReason::UserHardDelete)
        .expect("the owner hard deletes the cited CLAIM");
    assert!(deleted.existed, "the cited CLAIM existed");
    assert!(
        f.vault.get_claim(&kept).expect("read the CLAIM").is_some(),
        "the CLAIM does not read before the backfill"
    );
    reset_cited_source_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&kept).expect("read the CLAIM").is_none(),
        "the backfill left an old row whose cited CLAIM was deleted"
    );
}

#[test]
fn a_row_whose_source_is_absent_without_a_marker_stays() {
    let f = Fixture::new();
    let (claim, missing) = write_claim_citing_missing_source(&f.vault, f.subject)
        .expect("write the CLAIM citing an absent id");
    assert!(
        f.vault
            .get(&missing)
            .expect("read the missing id")
            .is_none(),
        "the cited id is stored"
    );
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "the CLAIM does not read before the backfill"
    );
    reset_cited_source_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "a row whose source is absent without a marker was withdrawn"
    );
    let counts = cited_source_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is complete");
    assert_eq!(
        counts[4], 1,
        "missing_without_marker counts the absent source"
    );
    let sources =
        cited_source_dependency_sources(&f.vault, claim).expect("read the CLAIM's sources");
    assert!(
        sources.is_empty(),
        "a row whose source is absent without a marker gained a dependency"
    );
}

#[test]
fn a_row_whose_locators_do_not_decode_stays() {
    let f = Fixture::new();
    let claim = write_claim_with_undecodable_locators(&f.vault, f.subject)
        .expect("write the CLAIM with undecodable locators");
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "the CLAIM does not read before the backfill"
    );
    reset_cited_source_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "a row whose locators do not decode was withdrawn"
    );
    let counts = cited_source_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is complete");
    assert_eq!(
        counts[3], 1,
        "undecodable counts the CLAIM whose locators do not decode"
    );
}

/// Two old CLAIMs in a chain over a CLAIM the owner then hard deletes: A at
/// `a` cites the deleted CLAIM, B at `b` cites A, neither with a dependency
/// row. The backfill visits the lower id first.
fn old_chain_over_a_deleted_claim(f: &Fixture, a: EntityId, b: EntityId) {
    let cited = owner_claim(f, "the deleted note");
    write_claim_citing_source_at(&f.vault, f.subject, a, cited).expect("write A citing the CLAIM");
    write_claim_citing_source_at(&f.vault, f.subject, b, a).expect("write B citing A");
    forget_cited_source_dependencies(&f.vault, a).expect("strip A's dependency");
    forget_cited_source_dependencies(&f.vault, b).expect("strip B's dependency");
    let deleted = f
        .vault
        .delete_entity_with_reason_as_owner(&f.proof, &cited, DeleteReason::UserHardDelete)
        .expect("the owner hard deletes the cited CLAIM");
    assert!(deleted.existed, "the cited CLAIM existed");
    assert!(
        f.vault.get_claim(&a).expect("read A").is_some(),
        "A does not read before the backfill"
    );
    assert!(
        f.vault.get_claim(&b).expect("read B").is_some(),
        "B does not read before the backfill"
    );
}

/// Two fresh ids, lower first.
fn two_ids() -> (EntityId, EntityId) {
    let (one, two) = (EntityId::now(), EntityId::now());
    (one.min(two), one.max(two))
}

#[test]
fn a_row_cited_before_its_withdrawn_source_follows_it() {
    let f = Fixture::new();
    let (b, a) = two_ids();
    old_chain_over_a_deleted_claim(&f, a, b);
    reset_cited_source_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    let counts = cited_source_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is complete");
    assert_eq!(
        counts[6], 0,
        "the pass met B after A was withdrawn: the B-first order did not happen"
    );
    assert!(
        counts[1] >= 1,
        "the pass did not link B to A while A was live"
    );
    assert!(
        f.vault.get_claim(&a).expect("read A").is_none(),
        "the backfill left A, whose cited CLAIM was deleted"
    );
    assert!(
        f.vault.get_claim(&b).expect("read B").is_none(),
        "B, linked to A earlier in the pass, still reads after the pass withdrew A"
    );
}

#[test]
fn a_row_citing_a_stale_source_is_withdrawn() {
    let f = Fixture::new();
    let (a, b) = two_ids();
    old_chain_over_a_deleted_claim(&f, a, b);
    reset_cited_source_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&a).expect("read A").is_none(),
        "the backfill left A, whose cited CLAIM was deleted"
    );
    assert!(
        f.vault.get_claim(&b).expect("read B").is_none(),
        "B still reads after the pass withdrew A, the source it cites"
    );
    let counts = cited_source_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is complete");
    assert_eq!(counts[6], 1, "stale_source counts B's withdrawn source");
}

#[test]
fn the_backfill_runs_once() {
    let f = Fixture::new();
    let (kept, _turn) = staged_imported_keep(&f);
    forget_cited_source_dependencies(&f.vault, kept).expect("strip the CLAIM's dependency");
    reset_cited_source_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    let first = cited_source_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is complete");
    // A rerun would count this new CLAIM and its missing source.
    write_claim_citing_missing_source(&f.vault, f.subject)
        .expect("write another citing CLAIM after completion");
    let f = f.reopen();
    let second = cited_source_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is still complete");
    assert_eq!(
        first, second,
        "a second open leaves the backfill counts unchanged"
    );
}

#[test]
fn a_row_with_caller_supplied_evidence_stays() {
    let f = Fixture::new();
    let a = owner_claim(&f, "the cited note");
    let b = caller_claim_citing_source(&f, a);
    assert!(
        f.vault.get_claim(&b).expect("read B").is_some(),
        "B does not read before the backfill"
    );
    let deleted = f
        .vault
        .delete_entity_with_reason_as_owner(&f.proof, &a, DeleteReason::UserHardDelete)
        .expect("the owner hard deletes the cited CLAIM");
    assert!(deleted.existed, "the cited CLAIM existed");
    reset_cited_source_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&b).expect("read B").is_some(),
        "a row with caller-supplied evidence was withdrawn"
    );
    let counts = cited_source_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is complete");
    assert_eq!(counts[7], 1, "untrusted_writer counts B");
    assert_eq!(counts[2], 0, "nothing was withdrawn");
    let sources = cited_source_dependency_sources(&f.vault, b).expect("read B's sources");
    assert!(
        sources.is_empty(),
        "a row with caller-supplied evidence gained a dependency"
    );
}

#[test]
fn a_row_citing_a_redacted_claim_value_is_withdrawn() {
    let f = Fixture::new();
    let a = owner_map_claim(&f);
    let b = EntityId::now();
    write_claim_citing_source_with_current_binding(&f.vault, f.subject, b, a)
        .expect("write B citing A's value");
    assert!(
        f.vault.get_claim(&b).expect("read B").is_some(),
        "B does not read before the backfill"
    );
    redact_claim_value_fields(&f.vault, a, &["secret_note".to_owned()], f.owner)
        .expect("redact A's value field");
    let redacted = f
        .vault
        .get_claim(&a)
        .expect("read A")
        .expect("the redacted CLAIM no longer reads");
    assert!(
        matches!(&redacted.value, rmpv::Value::Map(entries)
            if !entries.iter().any(|(key, _)| key.as_str() == Some("secret_note"))),
        "the redacted CLAIM kept the field"
    );
    reset_cited_source_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&b).expect("read B").is_none(),
        "B still reads after citing a redacted CLAIM value"
    );
    let counts = cited_source_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is complete");
    assert_eq!(counts[8], 1, "rewritten_source counts B");
    assert_eq!(counts[2], 1, "the backfill withdrew B");
    let sources = cited_source_dependency_sources(&f.vault, b).expect("read B's sources");
    assert!(
        sources.is_empty(),
        "B gained a dependency to the redacted A"
    );
}
