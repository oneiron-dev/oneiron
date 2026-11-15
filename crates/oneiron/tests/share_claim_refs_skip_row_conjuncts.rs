//! [SHARE-CLAIM-REFS-SKIP-ROW-CONJUNCTS] The visible claim refs of a
//! resolved share meet the scoped read lane's row admission, not only the
//! share's own maximum and the policy-only claim check: a claim whose
//! principal audience is someone other than the viewer, and a
//! `core.coreference.status` claim one of whose ends the viewer cannot
//! read (here, an end no row stores), stay out of the brief, while an
//! ordinary claim the viewer reads stays in.
//!
//! On main `resolve_share_for_view` read each brief claim raw, checked it
//! surfaceable, met the share's facets and called
//! `scoped_read_claim_allowed` alone, so both withheld claims below were
//! named visible. The coreference claim is stored past the claim write
//! doors (`oneiron::test_doors::share_claim_refs`), as a row whose end was
//! deleted after it landed stands; the write doors refuse such a claim
//! today, and a stored row must still not surface through a share.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test share_claim_refs_skip_row_conjuncts`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::access_grant::AccessGrantStatus;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::share::Share;
use oneiron::test_doors::share_claim_refs::put_stored_claim;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EdgeKind,
    EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_authority::federation::scope_codec::{effect_preset, encode_scope_value, read_preset};
use rmpv::Value;

fn entity(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("a fixture id")
}

fn at(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

fn put_person(vault: &Vault, id: EntityId, body: &[u8]) {
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, at(1), 1, body)
        .expect("a PERSON row");
}

/// The share tests' policy (`share/tests.rs::policy` with creation allowed
/// and no read selectors): the issuer may create a shared brief, and the
/// recipient holds an unrestricted `core:read` grant.
fn policy(vault: &Vault, issuer: &WriteActor, recipient: EntityId) {
    let grants = vec![
        Value::Map(vec![
            (
                Value::from("actor_ref"),
                Value::from(issuer.entity_ref().to_hex()),
            ),
            (Value::from("effector"), Value::from("external:share_brief")),
            (
                Value::from("scope"),
                encode_scope_value(&effect_preset()).expect("effect preset encodes"),
            ),
            (
                Value::from("selectors"),
                Value::Map(vec![(Value::from("channel"), Value::from("shared_brief"))]),
            ),
        ]),
        Value::Map(vec![
            (Value::from("actor_ref"), Value::from(recipient.to_hex())),
            (Value::from("effector"), Value::from("core:read")),
            (
                Value::from("scope"),
                encode_scope_value(&read_preset()).expect("read preset encodes"),
            ),
            (Value::from("selectors"), Value::Nil),
            (Value::from("receipt_required"), Value::Boolean(false)),
        ]),
    ];
    let value = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.2")),
        (Value::from("pack_id"), Value::from("brief-share-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(vec![])),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("human")),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
        (Value::from("scoped_grants"), Value::Array(grants)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).expect("policy encoding");
    let manifest_id = oneiron_store::policy_record::default_policy_manifest_id()
        .expect("the default manifest id");
    oneiron::test_support::put_policy_manifest_bytes(vault, manifest_id, &bytes)
        .expect("store the share policy");
}

fn profile_body(predicate: &str, subject: EntityId, value: &str) -> ClaimBody {
    ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body")
}

#[test]
fn share_visible_claim_refs_meet_scoped_read_row_admission() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), test_config()).expect("open vault");
    let issuer = WriteActor::new(entity(0x51), EdgeActorClass::Human);
    let recipient = entity(0x52);
    let subject = entity(0x53);
    let other_principal = entity(0x54);
    put_person(&vault, issuer.entity_ref(), b"issuer");
    put_person(&vault, recipient, b"recipient");
    put_person(&vault, subject, b"subject");
    put_person(&vault, other_principal, b"other principal");

    // Every claim below is born under the subject's substrate facet
    // (`ClaimBody::new` stamps it, and the PERSON put mints that FACET row),
    // so the share's facet maximum names that one facet.
    let facet = oneiron::claim::substrate_facet_id(subject).expect("the subject's facet id");
    let share = Share {
        recipient_ref: recipient,
        brief_ref: "brief:opaque-report".to_owned(),
        world_refs: BTreeSet::new(),
        facet_refs: BTreeSet::from([facet]),
        include_unscoped: true,
        status: AccessGrantStatus::Active,
        created_at: 42,
        revoked_at: None,
        expires_at: None,
        mention: None,
    };
    let share_id = entity(0x81);

    // The claims land under the shipped policy, as the graph-fs and
    // derive-links fixtures land theirs; the share policy is installed
    // after them, before the share it alone admits is created.
    let ordinary = entity(0x91);
    vault
        .put_claim(
            &ordinary,
            &profile_body("profile.name", subject, "visible value"),
            at(1),
            1,
        )
        .expect("the ordinary claim");

    // The same shape of claim, but its principal audience is the other
    // principal alone (`derive_links.rs` stamps a principal this way): the
    // share's policy-only check read no principal, so main named it visible.
    let principal_other = entity(0x92);
    let mut principal_body = profile_body("profile.city", subject, "the other principal's value");
    principal_body.scope = Some(Value::Map(vec![(
        Value::from("principal"),
        Value::Binary(other_principal.as_bytes().to_vec()),
    )]));
    vault
        .put_claim(&principal_other, &principal_body, at(1), 1)
        .expect("the principal claim");

    // A confirmed coreference between the subject and an end no row stores.
    // Its FacetOf stamp is the one stamp its body was born with, the
    // subject's substrate facet, so the share maximum alone admits it.
    let coreference = entity(0x93);
    let coreference_body = ClaimBody::new(
        "core.coreference.status",
        ClaimSubject::Edge {
            source: subject,
            kind: EdgeKind::SameAs,
            target: entity(0x55),
        },
        Value::from("confirmed"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("a coreference claim body");
    put_stored_claim(&vault, &coreference, &coreference_body).expect("the stored claim");
    vault
        .put_edge(&coreference, EdgeKind::FacetOf, &facet, 1.0)
        .expect("the coreference claim's facet stamp");

    policy(&vault, &issuer, recipient);
    vault
        .create_share(&share_id, &issuer, &share)
        .expect("an admitted share");

    let resolved = vault
        .resolve_share_for_view(
            &share_id,
            &recipient,
            None,
            &[ordinary, principal_other, coreference],
        )
        .expect("resolve the share")
        .expect("an active share");
    assert_eq!(
        resolved.visible_claim_refs,
        vec![ordinary],
        "only the ordinary claim meets the viewer's row admission: the \
         principal claim is another principal's alone, and the coreference \
         claim names an end the viewer cannot read"
    );
}
