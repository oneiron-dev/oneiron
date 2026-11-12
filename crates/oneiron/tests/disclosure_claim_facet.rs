//! The owner's disclosure doors store their claim heads
//! ([DISCLOSURE-SCOPE-CLAIM-FACET], [DISCLOSURE-TIER-CLAIM-FACET]).
//!
//! Each door mirrors its row into a `disclosure.*` CLAIM about the row's
//! subject. A CLAIM built with `ClaimBody::new(.., ClaimSubject::Entity(id), ..)`
//! is stamped with `id`'s derived substrate facet, and only a PERSON has a
//! FACET there: the CLAIM birth gate refused the first clearance of every
//! contact and the first Tier-A mark of every row that is not a PERSON with
//! `Registry(InvalidFacet { found: None, .. })`, and the door's transaction
//! rolled back. Both heads are now born in the vault default facet.
//!
//! The confirm door's standing answer, its narrow and its revoke write the
//! clearance through the same writer as the trusted-set pre-clearance below.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test disclosure_claim_facet`.

use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::disclosure::{
    DisclosureScopeStatus, PREDICATE_DISCLOSURE_SCOPE, PREDICATE_DISCLOSURE_TIER,
};
use oneiron::federation::Scope;
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{ClaimBody, ClaimSubject, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn put_row(vault: &Vault, entity_type: u8) -> TestResult<EntityId> {
    let row = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &row,
        entity_type,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        b"owen",
    )?;
    Ok(row)
}

/// The one `predicate` CLAIM attached to `subject`.
fn disclosure_head(vault: &Vault, subject: EntityId, predicate: &str) -> TestResult<ClaimBody> {
    let mut heads = Vec::new();
    for claim in vault.claims_for_subject(&subject)? {
        heads.extend(
            vault
                .get_claim(&claim)?
                .filter(|body| body.predicate == predicate),
        );
    }
    assert_eq!(heads.len(), 1, "one {predicate} head about the subject");
    Ok(heads.pop().ok_or("no head")?)
}

#[test]
fn owner_preclear_clears_a_contact() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("preclear_contact_disclosure")?;
    let person = put_row(&vault, ENTITY_TYPE_PERSON)?;
    let contact = EntityId::now();
    vault.create_counterparty_contact(
        &contact,
        &CounterpartyContactRecord::public(person, "owen@example.com", vault.now_recorded_at())?,
    )?;

    let receipts = vault.preclear_contact_disclosure(&proof, "owen", &[contact], Scope::top())?;

    assert_eq!(receipts.len(), 1, "one receipt per contact");
    assert_eq!(receipts[0].contact_ref, contact);
    let clearance = vault
        .counterparty_disclosure_scope(&contact)?
        .ok_or("the contact keeps no clearance row")?;
    assert_eq!(clearance.status, DisclosureScopeStatus::Active);
    assert_eq!(clearance.scope, Scope::top());
    let head = disclosure_head(&vault, contact, PREDICATE_DISCLOSURE_SCOPE)?;
    assert_eq!(head.subject, ClaimSubject::Entity(contact));
    assert_eq!(head.scope_facet, vault.default_facet()?);
    Ok(())
}

#[test]
fn owner_tier_a_mark_stores_its_claim() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    vault.ensure_embedded_owner_actor()?;
    let row = put_row(&vault, ENTITY_TYPE_EVENT)?;

    vault.set_disclosure_tier_a(&row, vault.now_recorded_at())?;

    assert!(
        vault.disclosure_tier_a_marked(&row)?,
        "the mark row is stored"
    );
    let head = disclosure_head(&vault, row, PREDICATE_DISCLOSURE_TIER)?;
    assert_eq!(head.subject, ClaimSubject::Entity(row));
    assert_eq!(head.scope_facet, vault.default_facet()?);
    Ok(())
}
