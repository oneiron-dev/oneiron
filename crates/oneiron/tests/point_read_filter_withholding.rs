//! L23005 (POINT-READ-FILTER-WITHHOLDING-GAP): a row the base key reads
//! but the request filter excludes is absence, COUNTED.
//!
//! `vault_read_parity.rs` pins the baseline half: a row the key itself can
//! never read counts nothing and names no row authority. This file pins the
//! narrowing half at the point-read doors: a CLAIM the base read key admits,
//! asked through a PERSON-only request filter, answers as absence with
//! `suppressed_count == 1` and the `row_authority` axis, on the by-ID point
//! path, on single hydrate (both the `ref` and the `short_id`/`content_hash`
//! forms), and on batch hydrate. A ref that never resolves stays uncounted
//! under the same filter, so the count proves the row existed for this key.
//!
//! The only pre-existing assertion of the by-ID shape is the lib-unit case at
//! `memory/tests/takes_notes.rs` in
//! `cross_resident_diary_coreference_requires_both_exact_grants_on_every_read`
//! (kept: privacy), whose target does not compile on main; this file keeps
//! the same assertion alive in a target that does.

use std::collections::BTreeSet;

use oneiron::authority::{HostSlipIssuer, SlipCaveat};
use oneiron::claim::{ScopedReadActorKey, base_world_id};
use oneiron::code_run::vault_read::{
    CoreBatchShortIdHydrateRequest, CoreHydrateRequest, CoreHydrateStatus,
    CoreShortIdHydrateOutcome, InProcessVaultReadAdapter, VaultReadClient, VaultReadError,
    VaultReadMethod, View,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use oneiron::memory::ReadFilterInput;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    RetrievalFilter, TimeRange, Vault, VaultConfig,
};

const MISSING_REF: &str = "cl4096:ff";

// ─── Fixture (the vault_read_parity shape, trimmed) ──────────────────────────

/// Explicit base-world read proof: the host root slip attenuated to base
/// `read` only. The Auto-approved claim below is surfaceable through it.
fn base_read_scope() -> Scope {
    Scope {
        worlds: ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())])),
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
        audience: ScopeAxis::All,
        verbs: ScopeAxis::Some(BTreeSet::from(["read".to_owned()])),
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Restricted),
    }
}

fn base_read_key(vault: &Vault) -> ScopedReadActorKey {
    let issuer =
        HostSlipIssuer::from_secret(b"vault-read-parity-test-host-secret").expect("host issuer");
    let mut slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    issuer
        .attenuate(
            &mut slip,
            SlipCaveat {
                scope: Some(base_read_scope()),
                ..Default::default()
            },
        )
        .expect("narrow root to base read");
    let challenge = b"vault-read-parity";
    let proof_bytes = issuer
        .binding_proof(&slip, challenge)
        .expect("binding proof");
    let verified = vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof_bytes)
        .expect("verified base-read slip");
    ScopedReadActorKey::from_verified_slip(&verified).expect("read key")
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    actor: ScopedReadActorKey,
    admitted_id: EntityId,
    admitted_ref: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault");
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = Some("test/model@v1".to_owned());
        config.map_size = 16 * 1024 * 1024;
        let vault = Vault::open(dir.path(), config).expect("open vault");

        let subject = seed_id(0x21);
        let admitted_id = seed_id(0x22);
        let occurred = TimeRange {
            start: 1_780_000_000,
            end: 1_780_000_000,
        };
        vault
            .put_entity(
                &subject,
                ENTITY_TYPE_PERSON,
                occurred,
                occurred.start,
                b"subject",
            )
            .expect("subject entity");
        vault
            .put_claim(
                &admitted_id,
                &claim(subject, "alpha hallway note", ClaimApprovalStatus::Auto),
                occurred,
                occurred.start,
            )
            .expect("admitted claim");

        let actor = base_read_key(&vault);
        let admitted_ref = probe_short_ref(&vault, &admitted_id);

        Self {
            _dir: dir,
            vault,
            actor,
            admitted_id,
            admitted_ref,
        }
    }

    fn adapter(&self) -> InProcessVaultReadAdapter<'_> {
        InProcessVaultReadAdapter::new(&self.vault, self.actor.clone())
    }
}

fn seed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn claim(subject: EntityId, text: &str, approval: ClaimApprovalStatus) -> ClaimBody {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    )
    .expect("fixture");
    body.source = Some(ClaimSource::UserStated);
    body
}

/// Test-oracle only: resolves an entity's canonical short ref through the naked
/// vault, which is exactly what the adapters may never do.
fn probe_short_ref(vault: &Vault, id: &EntityId) -> String {
    let prefix = oneiron::registry::short_id_prefix(ENTITY_TYPE_CLAIM).expect("claim prefix");
    // Fresh production open seeds claims before this append-only fixture runs.
    // With no claim deletions here, the live count bounds the per-type counter;
    // a fixed cl1..cl8 probe would only search the bootstrap population.
    let claim_count = vault
        .count_entities_by_type(ENTITY_TYPE_CLAIM)
        .expect("fixture claim count");
    for counter in 1..=claim_count {
        let short_id = format!("{prefix}{counter}");
        for content_hash in 0..=u8::MAX {
            let hydrated = vault
                .hydrate_short_id(&short_id, content_hash)
                .expect("short id probe");
            if hydrated.is_some_and(|hydrated| hydrated.id == *id) {
                return format!("{short_id}:{content_hash:02x}");
            }
        }
    }
    panic!("fixture entity {} has no short id row", id.to_hex());
}

// ─── Requests ────────────────────────────────────────────────────────────────

/// A PERSON-only request filter: it excludes the fixture's CLAIM row while
/// the base key still reads it.
fn person_only_input() -> ReadFilterInput {
    ReadFilterInput {
        entity_types: Some(BTreeSet::from([ENTITY_TYPE_PERSON])),
        ..Default::default()
    }
}

/// The same narrowing as the point-read door takes it.
fn person_only_filter() -> RetrievalFilter {
    RetrievalFilter {
        entity_types: Some(BTreeSet::from([ENTITY_TYPE_PERSON])),
        ..Default::default()
    }
}

fn hydrate_request(reference: &str, filter: Option<ReadFilterInput>) -> CoreHydrateRequest {
    CoreHydrateRequest {
        reference: Some(reference.to_owned()),
        short_id: None,
        content_hash: None,
        view: Some(View::Full),
        image_input: false,
        task: None,
        filter,
    }
}

fn hydrate_parts_request(
    short_id: &str,
    content_hash: &str,
    filter: Option<ReadFilterInput>,
) -> CoreHydrateRequest {
    CoreHydrateRequest {
        reference: None,
        short_id: Some(short_id.to_owned()),
        content_hash: Some(content_hash.to_owned()),
        view: Some(View::Full),
        image_input: false,
        task: None,
        filter,
    }
}

fn batch_request(
    reference: &str,
    filter: Option<ReadFilterInput>,
) -> CoreBatchShortIdHydrateRequest {
    CoreBatchShortIdHydrateRequest {
        refs: vec![reference.to_owned()],
        view: Some(View::Full),
        image_input: false,
        task: None,
        filter,
    }
}

// ─── Receipt assertions ──────────────────────────────────────────────────────

/// A filter-narrowed row answers NOT_FOUND, and its receipt counts the one
/// withheld row and names the row-authority axis.
fn assert_counted_absence(error: &VaultReadError, method: VaultReadMethod) {
    let VaultReadError::Engine {
        method: actual,
        engine_code,
        narrowing: Some(receipt),
        ..
    } = error
    else {
        panic!("a filtered point read answers NOT_FOUND with a narrowing receipt: {error:?}");
    };
    assert_eq!(*actual, method);
    assert_eq!(engine_code.as_str(), "NOT_FOUND");
    assert_eq!(
        receipt.suppressed_count, 1,
        "the one filter-excluded row is withheld, not missing: {error:?}"
    );
    assert!(
        receipt.narrowed_axes.contains(&"row_authority".to_owned()),
        "a counted withholding names its axis: {error:?}"
    );
    assert!(
        receipt.replan_hint.contains(&"row_authority".to_owned()),
        "a counted withholding names its re-plan hint: {error:?}"
    );
}

/// A ref that never resolves answers NOT_FOUND with no count and no row
/// authority, even under the same excluding filter.
fn assert_uncounted_absence(error: &VaultReadError, method: VaultReadMethod) {
    let VaultReadError::Engine {
        method: actual,
        engine_code,
        narrowing: Some(receipt),
        ..
    } = error
    else {
        panic!("a missing ref answers NOT_FOUND with a narrowing receipt: {error:?}");
    };
    assert_eq!(*actual, method);
    assert_eq!(engine_code.as_str(), "NOT_FOUND");
    assert_eq!(
        receipt.suppressed_count, 0,
        "a missing ref withholds nothing: {error:?}"
    );
    assert!(
        !receipt
            .narrowed_axes
            .iter()
            .any(|axis| axis == "row_authority"),
        "a missing ref names no row authority: {error:?}"
    );
    assert!(
        !receipt
            .replan_hint
            .iter()
            .any(|axis| axis == "row_authority"),
        "a missing ref hints no row authority: {error:?}"
    );
}

// ─── The narrowing half ──────────────────────────────────────────────────────

#[test]
fn point_read_filter_withholding_is_counted() {
    let fixture = Fixture::new();
    let read = fixture.vault.scoped_read(fixture.actor.clone());

    // The base key reads the claim: the unfiltered point read serves it and
    // counts nothing, so the narrowing below is not vacuous.
    let open = read
        .get_entity_parts_with_receipt(&fixture.admitted_id, None)
        .expect("open point read");
    assert!(open.value.is_some(), "the base key reads the claim");
    assert_eq!(open.receipt.suppressed_count, 0);

    // The PERSON-only request filter excludes the CLAIM row: absence, counted.
    let filter = person_only_filter();
    let narrowed = read
        .get_entity_parts_with_receipt(&fixture.admitted_id, Some(&filter))
        .expect("filtered point read");
    assert!(narrowed.value.is_none(), "the filter excludes the claim");
    assert_eq!(
        narrowed.receipt.suppressed_count, 1,
        "the one filter-excluded row is withheld, not missing"
    );
    assert!(
        narrowed
            .receipt
            .narrowed_axes
            .contains(&"row_authority".to_owned()),
        "a counted withholding names its axis"
    );
    assert!(
        narrowed
            .receipt
            .replan_hint
            .contains(&"row_authority".to_owned()),
        "a counted withholding names its re-plan hint"
    );

    // A missing id under the same filter stays uncounted: the count above
    // proves the row existed for this key.
    let missing = read
        .get_entity_parts_with_receipt(&seed_id(0x99), Some(&filter))
        .expect("missing point read");
    assert!(missing.value.is_none());
    assert_eq!(missing.receipt.suppressed_count, 0);
    assert!(
        !missing
            .receipt
            .narrowed_axes
            .iter()
            .any(|axis| axis == "row_authority"),
        "a missing id names no row authority"
    );
    assert!(
        !missing
            .receipt
            .replan_hint
            .iter()
            .any(|axis| axis == "row_authority"),
        "a missing id hints no row authority"
    );
}

#[test]
fn hydrate_filter_withholding_is_counted() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();

    // Unfiltered, the admitted short ref hydrates live with its item.
    let open = adapter
        .hydrate(hydrate_request(&fixture.admitted_ref, None))
        .expect("open hydrate");
    assert_eq!(open.status, CoreHydrateStatus::Live);
    assert!(open.item.is_some(), "the base key reads the claim");
    assert_eq!(open.narrowing.suppressed_count, 0);

    // The `ref` form under the excluding filter: counted absence.
    let denied = adapter
        .hydrate(hydrate_request(
            &fixture.admitted_ref,
            Some(person_only_input()),
        ))
        .expect_err("a filtered hydrate reads as absence");
    assert_counted_absence(&denied, VaultReadMethod::Hydrate);

    // The `short_id`/`content_hash` parts form narrows identically.
    let (short_id, content_hash) = fixture
        .admitted_ref
        .split_once(':')
        .expect("the probe ref carries its hash");
    let denied = adapter
        .hydrate(hydrate_parts_request(
            short_id,
            content_hash,
            Some(person_only_input()),
        ))
        .expect_err("a filtered parts hydrate reads as absence");
    assert_counted_absence(&denied, VaultReadMethod::Hydrate);

    // A missing ref under the same filter stays uncounted.
    let missing = adapter
        .hydrate(hydrate_request(MISSING_REF, Some(person_only_input())))
        .expect_err("a missing ref reads as absence");
    assert_uncounted_absence(&missing, VaultReadMethod::Hydrate);
}

#[test]
fn batch_hydrate_filter_withholding_is_counted() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();

    // Unfiltered, the admitted ref hydrates live in its slot.
    let open = adapter
        .hydrate_many(batch_request(&fixture.admitted_ref, None))
        .expect("open batch hydrate");
    assert_eq!(open.results.len(), 1);
    assert_eq!(open.results[0].outcome, CoreShortIdHydrateOutcome::Live);
    assert!(open.results[0].result.is_some());
    assert_eq!(open.narrowing.suppressed_count, 0);

    // Under the excluding filter the slot answers NotFound with no result,
    // echoing only the caller's own ref, while the batch receipt counts it.
    let narrowed = adapter
        .hydrate_many(batch_request(
            &fixture.admitted_ref,
            Some(person_only_input()),
        ))
        .expect("filtered batch hydrate");
    assert_eq!(narrowed.results.len(), 1);
    assert_eq!(
        narrowed.results[0].outcome,
        CoreShortIdHydrateOutcome::NotFound
    );
    assert_eq!(narrowed.results[0].result, None);
    assert_eq!(narrowed.results[0].reference, fixture.admitted_ref);
    assert_eq!(
        narrowed.narrowing.suppressed_count, 1,
        "the one filter-excluded row is withheld, not missing"
    );
    assert!(
        narrowed
            .narrowing
            .narrowed_axes
            .contains(&"row_authority".to_owned()),
        "a counted withholding names its axis"
    );
    assert!(
        narrowed
            .narrowing
            .replan_hint
            .contains(&"row_authority".to_owned()),
        "a counted withholding names its re-plan hint"
    );

    // A missing ref under the same filter stays uncounted.
    let missing = adapter
        .hydrate_many(batch_request(MISSING_REF, Some(person_only_input())))
        .expect("missing batch hydrate");
    assert_eq!(missing.results.len(), 1);
    assert_eq!(
        missing.results[0].outcome,
        CoreShortIdHydrateOutcome::NotFound
    );
    assert_eq!(missing.results[0].result, None);
    assert_eq!(missing.narrowing.suppressed_count, 0);
    assert!(
        !missing
            .narrowing
            .narrowed_axes
            .iter()
            .any(|axis| axis == "row_authority"),
        "a missing ref names no row authority"
    );
    assert!(
        !missing
            .narrowing
            .replan_hint
            .iter()
            .any(|axis| axis == "row_authority"),
        "a missing ref hints no row authority"
    );
}
