//! FIX RECEIPTS-CREDENTIAL-PIN-TEST (slice 6.4c): `vault.receipts` is
//! screened by the caller's read credential. A handle bound to a verified
//! read credential (`Memory::with_read_proof`, as oneiron-server's
//! `credential_memory` binds a transport caller) sees only the receipts whose
//! claim its own read lane reads (OF-172 D2): on the gate ledger
//! (`gate_records_before`) and on the receipt family's kinds
//! (`credential_kept_receipts`). The pin: no `claim_ref` on such a page is
//! one the same handle's `vault.policy.preflight` (act `read`) answers
//! withheld.
//!
//! Public paths only. A device vault with its host root and embedded owner;
//! each credential is minted from the host root's claims and verified with
//! the host's binding proof, as a transport verifies the slip a request
//! presents.
//!
//! `cargo test --locked -p oneiron --all-features --test receipts_credential_pin`

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::memory::{ClaimInput, Memory, MemoryReceipt};
use oneiron::snapshot_read::{PolicyPreflightAct, PolicyPreflightRef, PolicyPreflightRequest};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CHALLENGE: &[u8] = b"oneiron-request:receipts-credential-pin";
/// A page large enough to hold every receipt the fixture writes.
const PAGE_LIMIT: usize = 1000;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-receipts-credential-pin")?;
    vault.ensure_host_root_slip(&issuer)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(Fixture {
        _dir: dir,
        vault,
        issuer,
        owner,
    })
}

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The live `human` credential this host mints `holder`, held to `records`
/// (empty: no records caveat), verified as a transport verifies it.
fn credential(
    fixture: &Fixture,
    holder: EntityId,
    records: BTreeSet<String>,
) -> Result<VerifiedSlip, Box<dyn std::error::Error>> {
    let root = fixture.vault.ensure_host_root_slip(&fixture.issuer)?;
    let mut claims = root.claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.records = records;
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)?;
    let binding = fixture.issuer.binding_proof(&slip, CHALLENGE)?;
    Ok(fixture.vault.verify_capability_slip(
        &fixture.issuer.public_key(),
        &slip,
        CHALLENGE,
        &binding,
    )?)
}

/// The owner writes one claim, which lands and appends its gate decision;
/// answers the claim's id as the owner's own ledger names it on that
/// decision's receipt.
fn owner_claim(fixture: &Fixture, value: &str) -> Result<EntityId, Box<dyn std::error::Error>> {
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let commit = owner.claim_upsert(&ClaimInput {
        id: Some(EntityId::now().to_hex()),
        predicate: "decision.practical".to_owned(),
        subject_ref: fixture.owner.to_hex(),
        value: serde_json::json!(value),
        confidence: 0.9,
        source: "user_stated".to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
        confidence_details: None,
    })?;
    assert_eq!(
        commit.approval, "auto",
        "the owner's claim lands: {commit:?}"
    );
    let ledger = owner.receipts(PAGE_LIMIT)?;
    let claim_ref = ledger
        .iter()
        .find(|receipt| receipt.receipt_ref == commit.receipt_ref)
        .and_then(|receipt| receipt.claim_ref.clone())
        .ok_or_else(|| {
            format!(
                "the owner's ledger names the claim's decision {}: {ledger:?}",
                commit.receipt_ref
            )
        })?;
    Ok(EntityId::from_hex(&claim_ref)?)
}

/// The claims `receipts` name, by their `claim_ref`.
fn claim_refs(receipts: &[MemoryReceipt]) -> Result<Vec<EntityId>, Box<dyn std::error::Error>> {
    receipts
        .iter()
        .filter_map(|receipt| receipt.claim_ref.as_deref())
        .map(|hex| Ok(EntityId::from_hex(hex)?))
        .collect()
}

/// `reader`'s two `vault.receipts` pages: the gate ledger (no kinds) and the
/// receipt family's `gate` kind, each as the verb calls it.
fn receipt_pages(
    reader: &Memory<'_>,
) -> Result<[Vec<MemoryReceipt>; 2], Box<dyn std::error::Error>> {
    let ledger = reader.receipts_page(PAGE_LIMIT, &[], None)?;
    let family = reader.receipts_page(PAGE_LIMIT, &["gate".to_owned()], None)?;
    Ok([ledger.receipts, family.receipts])
}

/// `reader`'s `vault.policy.preflight` with the act `read` on `refs`: the ids
/// it answers withheld.
fn withheld_by_preflight(
    reader: &Memory<'_>,
    refs: Vec<EntityId>,
) -> Result<BTreeSet<EntityId>, Box<dyn std::error::Error>> {
    let answer = oneiron::verbs::vault_policy_preflight(
        reader,
        PolicyPreflightRequest {
            refs,
            act: PolicyPreflightAct::Read,
        },
    )?
    .value;
    Ok(answer
        .refs
        .into_iter()
        .filter_map(|answer| match answer {
            PolicyPreflightRef::Withheld { entity } => Some(entity),
            PolicyPreflightRef::Readable { .. } => None,
        })
        .collect())
}

/// The pin: every claim `reader`'s pages name is one its own preflight
/// reads, judged in one preflight with `also` beside them.
fn assert_pages_name_only_readable_claims(
    reader: &Memory<'_>,
    pages: &[Vec<MemoryReceipt>; 2],
    also: &[EntityId],
    who: &str,
) -> Result<BTreeSet<EntityId>, Box<dyn std::error::Error>> {
    let mut named = BTreeSet::new();
    for page in pages {
        named.extend(claim_refs(page)?);
    }
    let mut refs: Vec<EntityId> = named.iter().copied().collect();
    refs.extend(also.iter().copied().filter(|id| !named.contains(id)));
    let withheld = withheld_by_preflight(reader, refs)?;
    let leaked: Vec<&EntityId> = named.intersection(&withheld).collect();
    assert!(
        leaked.is_empty(),
        "{who}'s receipt pages name claims its own preflight withholds: {leaked:?}"
    );
    Ok(withheld)
}

#[test]
fn a_strangers_receipt_page_names_no_claim_its_preflight_withholds() -> TestResult {
    let fixture = fixture()?;
    let first = owner_claim(&fixture, "keep the spare key in the blue box")?;
    let second = owner_claim(&fixture, "renew the lease in March")?;

    // The ledger holds both decisions: the owner's own pages name both claims.
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    for (page, name) in receipt_pages(&owner)?.iter().zip(["ledger", "gate kind"]) {
        let named = claim_refs(page)?;
        assert!(
            named.contains(&first) && named.contains(&second),
            "the owner's {name} page names both claims: {named:?}"
        );
    }

    // A person with no grant, bound to its own live credential.
    let stranger = EntityId::now();
    fixture.vault.put_entity(
        &stranger,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a person with no grant",
    )?;
    let proof = credential(&fixture, stranger, BTreeSet::new())?;
    let reader = fixture
        .vault
        .memory(stranger, EdgeActorClass::Human)
        .with_read_proof(&proof);
    let pages = receipt_pages(&reader)?;
    let withheld =
        assert_pages_name_only_readable_claims(&reader, &pages, &[first, second], "the stranger")?;
    assert!(
        withheld.contains(&first) && withheld.contains(&second),
        "the stranger's preflight withholds the owner's claims: {withheld:?}"
    );
    for (page, name) in pages.iter().zip(["ledger", "gate kind"]) {
        let named = claim_refs(page)?;
        assert!(
            !named.contains(&first) && !named.contains(&second),
            "the stranger's {name} page names an owner claim: {named:?}"
        );
    }
    Ok(())
}

#[test]
fn a_credential_held_to_one_claim_pages_that_claim_and_no_other() -> TestResult {
    let fixture = fixture()?;
    let first = owner_claim(&fixture, "keep the spare key in the blue box")?;
    let second = owner_claim(&fixture, "renew the lease in March")?;

    // The owner's credential, held by a records caveat to the first claim
    // (and the owner's own row, the claim's subject).
    let proof = credential(
        &fixture,
        fixture.owner,
        BTreeSet::from([first.to_hex(), fixture.owner.to_hex()]),
    )?;
    let reader = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&proof);
    let pages = receipt_pages(&reader)?;
    let withheld = assert_pages_name_only_readable_claims(
        &reader,
        &pages,
        &[first, second],
        "the held owner",
    )?;
    assert!(
        !withheld.contains(&first) && withheld.contains(&second),
        "the held credential's preflight reads the first claim and withholds the second: \
         {withheld:?}"
    );
    for (page, name) in pages.iter().zip(["ledger", "gate kind"]) {
        let named = claim_refs(page)?;
        assert!(
            named.contains(&first) && !named.contains(&second),
            "the held credential's {name} page names the first claim and not the second: \
             {named:?}"
        );
    }
    Ok(())
}
