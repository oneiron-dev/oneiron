#![cfg(oneiron_test_support)]

//! Regression for a facade claim's facet on the consolidation root-pin path.

use oneiron::claim::{ClaimBody, ClaimSource, ClaimSubject, base_world_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::consolidation_frontier::{
    ConsolidationAccountingRequest, ConsolidationPinRequest, ConsolidationReference,
    ConsolidationRootAccounting, ConsolidationRootBucket, ConsolidationRootInput,
};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use rmpv::Value;
use serde_json::json;

struct Fixture {
    vault: Vault,
    actor: EntityId,
    owner: AuthenticatedOwner,
    facet: EntityId,
    project: EntityId,
    claim: EntityId,
    body: ClaimBody,
    _dir: tempfile::TempDir,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("create facet regression directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open fixture vault");
    let actor = vault.ensure_embedded_owner_actor().expect("ensure owner");
    assert_eq!(
        vault.get_entity_type(&actor).expect("read owner back"),
        Some(ENTITY_TYPE_PERSON),
    );
    let owner = vault
        .authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate owner");
    let facet = EntityId::now();
    let project = EntityId::now();
    for (id, kind, name) in [
        (facet, ENTITY_TYPE_FACET, "consolidation facet"),
        (project, ENTITY_TYPE_EVENT, "consolidation project"),
    ] {
        // Projects are audience ids, not a distinct engine entity kind.
        let bytes = rmp_serde::to_vec_named(&json!({"name": name})).expect("encode fixture row");
        vault
            .put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, &bytes)
            .expect("write fixture row");
        assert_eq!(vault.get(&id).expect("read fixture row back"), Some(bytes));
        assert_eq!(
            vault.get_entity_type(&id).expect("read row kind"),
            Some(kind)
        );
    }
    let claim = EntityId::now();
    let receipt = vault
        .memory(actor, EdgeActorClass::Human)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(claim.to_hex()),
            predicate: "facet_regression.value".to_owned(),
            subject_ref: actor.to_hex(),
            value: json!("a facet-scoped fact"),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: facet.to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: project.to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(1),
            learned_at: Some(1),
            salience: None,
        })
        .expect("admit claim through vault.claims.upsert's scoped writer");
    let body = vault
        .get_claim(&claim)
        .expect("read admitted claim")
        .expect("claim exists");
    assert_eq!(body.predicate, "facet_regression.value");
    assert_eq!(body.subject, ClaimSubject::Entity(actor));
    assert_eq!(body.value, Value::from("a facet-scoped fact"));
    assert_eq!(body.confidence, 1.0);
    assert_eq!(body.source, Some(ClaimSource::UserStated));
    assert_eq!(body.approval.as_str(), receipt.approval);
    assert_eq!(body.world, None, "base reality decodes as None");
    assert_eq!(body.rel, None, "the claim covers all relationships");
    assert_eq!(body.scope_facet, facet);
    assert_eq!(body.scope_project, project);
    let scope = body
        .scope
        .as_ref()
        .expect("admission writes a scope")
        .as_map()
        .expect("scope map");
    let facets: Vec<_> = scope
        .iter()
        .filter(|(key, _)| matches!(key.as_str(), Some("facet" | "facet_ref" | "facetRef")))
        .cloned()
        .collect();
    assert_eq!(
        facets,
        vec![(Value::from("facet"), Value::from(facet.to_hex()))],
    );
    Fixture {
        vault,
        actor,
        owner,
        facet,
        project,
        claim,
        body,
        _dir: dir,
    }
}

fn pin_request(fixture: &Fixture, claim: EntityId) -> ConsolidationPinRequest {
    ConsolidationPinRequest {
        buckets: vec![ConsolidationRootInput {
            bucket: ConsolidationRootBucket {
                subject: fixture.actor.to_hex(),
                predicate_root: "facet_regression".to_owned(),
                world: None,
                facet: Some(fixture.facet.to_hex()),
                relationship: None,
                project: fixture.project.to_hex(),
            },
            evidence: vec![ConsolidationReference {
                source_id: claim.to_hex(),
                claim_id: Some(claim.to_hex()),
                byte_range: None,
            }],
        }],
    }
}

fn pin_and_read_back(fixture: &Fixture, claim: EntityId) {
    let memory = fixture.vault.memory(fixture.actor, EdgeActorClass::Human);
    let request = pin_request(fixture, claim);
    let pinned = memory
        .consolidation_pin_as_owner(&fixture.owner, &request)
        .unwrap_or_else(|error| {
            panic!(
                "claim's own facet bucket must pin, got {}: {}",
                error.code, error.message,
            )
        });
    let read: ConsolidationRootAccounting = memory
        .consolidation_accounting_as_owner(
            &fixture.owner,
            &ConsolidationAccountingRequest {
                root_ref: pinned.root_ref.clone(),
            },
        )
        .expect("read pinned root through vault.consolidation.accounting's path");
    assert_eq!(
        serde_json::to_value(&read).expect("serialize read accounting"),
        serde_json::to_value(&pinned).expect("serialize pin receipt"),
        "the read path returns the entire persisted pin",
    );
    assert_eq!(read.buckets.len(), 1);
    let bucket = &read.buckets[0];
    assert_eq!(bucket.bucket, request.buckets[0].bucket);
    assert_eq!(bucket.pinned.len(), 1);
    assert_eq!(bucket.pinned[0].reference, request.buckets[0].evidence[0]);
    assert_eq!(bucket.pinned[0].trust_class, ClaimSource::UserStated);
}

/// The control uses the public typed writer because JSON admission cannot
/// express MessagePack binary. All other admitted fields are unchanged.
fn write_dreamer_scope_control(fixture: &Fixture) -> EntityId {
    let mut body = fixture.body.clone();
    let Some(Value::Map(scope)) = &mut body.scope else {
        panic!("admitted claim must have a scope map");
    };
    scope.retain(|(key, _)| key.as_str() != Some("facet"));
    scope.push((
        Value::from("facet_ref"),
        Value::Binary(fixture.facet.as_bytes().to_vec()),
    ));
    let claim = EntityId::now();
    fixture
        .vault
        .put_claim(&claim, &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("write raw facet scope through the public typed claim writer");
    assert_eq!(
        fixture
            .vault
            .get_claim(&claim)
            .expect("read control claim back"),
        Some(body),
        "the typed writer preserves the requested scope spelling and bytes",
    );
    claim
}

#[test]
fn a_facade_claims_own_facet_bucket_pins() {
    let fixture = setup();
    pin_and_read_back(&fixture, fixture.claim);
}

#[test]
fn a_dreamer_spelled_facet_still_pins() {
    let fixture = setup();
    let claim = write_dreamer_scope_control(&fixture);
    pin_and_read_back(&fixture, claim);
}
