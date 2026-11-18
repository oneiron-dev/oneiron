//! FIX RECEIPTS-PAGE-READ-COST-GROWS: one `vault.receipts` page of the gate
//! ledger costs a bounded amount per receipt. Every ledger row about a claim
//! is sealed (a zstd frame under AES-256-GCM) and opened into a buffer that is
//! wiped on drop. On main that buffer was sized to the 16 MiB plaintext cap,
//! not to the row, so each row read wiped 16 MiB, and the owner's page grew by
//! tens of milliseconds per receipt (E2E RETRIEVAL-09: 5.1 s for one page
//! after about 75 writes).
//!
//! The owner writes 500 claims. After 25, 75 and 500 writes the test reads one
//! page as the HTTP facade does (`receipts_page(1000, [], None)` on an owner
//! handle bound to its read credential), timed, and beside it the unbound
//! handle's `receipts(1000)`, which decodes the ledger with no lane read. Each
//! bound page must finish within `PAGE_FIXED` plus `PAGE_PER_RECEIPT` for each
//! receipt it holds: a bound linear in the page. The figures are for the test
//! profile, whose workspace crates build at opt-level 0, as the E2E server's
//! do. One `PAGE-COST` line per checkpoint is printed:
//!
//! `cargo test --locked -p oneiron --all-features --test gate_ledger_page_read_cost -- --nocapture`

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::memory::ClaimInput;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const CHALLENGE: &[u8] = b"oneiron-request:gate-ledger-page-read-cost";
/// The owner's claim writes after which one page is read and timed.
const CHECKPOINTS: [usize; 3] = [25, 75, 500];
/// The page size the E2E receipt wait asks for.
const PAGE_LIMIT: usize = 1000;
/// One page's allowance for the call itself.
const PAGE_FIXED: Duration = Duration::from_secs(1);
/// One page's allowance for each receipt it holds. On main one receipt cost
/// tens of milliseconds in this profile; on the head about one.
const PAGE_PER_RECEIPT: Duration = Duration::from_millis(10);

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    proof: VerifiedSlip,
}

/// A device vault with its host root and embedded owner, and the owner's read
/// credential minted from the host root's claims as oneiron-server's
/// credentials are, verified with its holder's signature.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    let issuer =
        HostSlipIssuer::from_secret(b"oneiron-test-gate-ledger-page-read-cost").expect("issuer");
    let root = vault.ensure_host_root_slip(&issuer).expect("host root");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let key = SigningKey::from_bytes(&[0x37; 32]);
    let mut claims = root.claims;
    claims.slip_id = [0x37; 32];
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.records = BTreeSet::new();
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("mint the owner credential");
    let signature = key
        .sign(&slip.binding_transcript(CHALLENGE).expect("transcript"))
        .to_bytes();
    let proof = vault
        .verify_capability_slip(&issuer.public_key(), &slip, CHALLENGE, &signature)
        .expect("verify the owner credential");
    Fixture {
        _dir: dir,
        vault,
        owner,
        proof,
    }
}

/// The owner's `index`th claim: a distinct value of a set-cardinality
/// predicate, so every write stands and appends its own gate decision.
fn write_claim(fixture: &Fixture, index: usize) {
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(EntityId::now().to_hex()),
            predicate: "decision.practical".to_owned(),
            subject_ref: fixture.owner.to_hex(),
            value: serde_json::json!(format!("keep ledger entry {index}")),
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
        })
        .unwrap_or_else(|error| panic!("the owner's claim write {index}: {error:?}"));
    assert_eq!(
        receipt.approval, "auto",
        "the owner's claim write {index} lands"
    );
}

/// One checkpoint's timed reads.
struct PageCost {
    writes: usize,
    receipts: usize,
    unbound_receipts: usize,
    bound: Duration,
    unbound: Duration,
}

impl PageCost {
    fn limit(&self) -> Duration {
        PAGE_FIXED
            + PAGE_PER_RECEIPT * u32::try_from(self.receipts).expect("a page holds under 2^32 rows")
    }
}

/// The owner's page read as the facade reads it, and the unbound ledger read,
/// each timed, after `writes` claim writes.
fn time_pages(fixture: &Fixture, writes: usize) -> PageCost {
    let bound_handle = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&fixture.proof);
    let started = Instant::now();
    let page = bound_handle
        .receipts_page(PAGE_LIMIT, &[], None)
        .expect("the owner's credential-bound page read");
    let bound = started.elapsed();
    let unbound_handle = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let started = Instant::now();
    let ledger = unbound_handle
        .receipts(PAGE_LIMIT)
        .expect("the unbound ledger read");
    let unbound = started.elapsed();
    let cost = PageCost {
        writes,
        receipts: page.receipts.len(),
        unbound_receipts: ledger.len(),
        bound,
        unbound,
    };
    let per_receipt_us = cost.bound.as_micros() / cost.receipts.max(1) as u128;
    let (receipts, unbound_receipts) = (cost.receipts, cost.unbound_receipts);
    let (bound_ms, unbound_ms, limit_ms) = (
        cost.bound.as_millis(),
        cost.unbound.as_millis(),
        cost.limit().as_millis(),
    );
    println!(
        "PAGE-COST writes={writes} receipts={receipts} unbound_receipts={unbound_receipts} \
         bound_ms={bound_ms} unbound_ms={unbound_ms} bound_us_per_receipt={per_receipt_us} \
         limit_ms={limit_ms}"
    );
    cost
}

#[test]
fn a_gate_ledger_page_costs_at_most_linear_time_in_its_receipts() {
    let fixture = fixture();
    let mut costs = Vec::with_capacity(CHECKPOINTS.len());
    let mut written = 0;
    for checkpoint in CHECKPOINTS {
        while written < checkpoint {
            write_claim(&fixture, written);
            written += 1;
        }
        costs.push(time_pages(&fixture, written));
    }
    for cost in &costs {
        let (writes, receipts) = (cost.writes, cost.receipts);
        assert!(
            receipts >= writes,
            "the owner's page after {writes} claim writes holds each write's gate decision, \
             found {receipts}"
        );
    }
    for cost in &costs {
        let (writes, receipts, bound, limit) =
            (cost.writes, cost.receipts, cost.bound, cost.limit());
        assert!(
            bound <= limit,
            "the owner's page of {receipts} receipts after {writes} claim writes took {bound:?}, \
             over its linear bound {limit:?} ({PAGE_FIXED:?} + {PAGE_PER_RECEIPT:?} per receipt)"
        );
    }
}
