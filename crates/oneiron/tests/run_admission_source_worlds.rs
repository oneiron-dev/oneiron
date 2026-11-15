//! Census row L5-25 (DEC-0005 world privacy, fix 12; true world provenance,
//! :457): a provider call that names no world still says which worlds it
//! read. Its provenance is the rows the host code assembled its input from
//! (`RunAdmission::sourced`, FIX 5760), never the caller's claim (Astra R4).
//! The host's receipt sink resolves those rows to their live worlds when the
//! call is admitted (`RunReceiptSink::source_worlds`, through
//! `Vault::source_row_worlds`), and every receipt of the call names them as
//! `source_worlds`: `Admitted`, `Dispatched`, `Settled` and a refusal's
//! `Denied`. A row whose worlds no read proves leaves them unknown: no
//! `source_worlds` at all, never an empty or partial set.
//!
//! Each call goes through the public `RunAdmission::call` over a gated fake
//! provider. The vault fixture uses `oneiron::test_doors`, built only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test run_admission_source_worlds`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oneiron::authority::MachineRole;
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferBinding, OfferRoute, Payer,
    RunAdmission, RunCall, RunDeclaration, RunDenied, RunEvent, RunReceipt, RunReceiptSink,
};
use oneiron::llm::{self, ReplyAssertions, SingleRouteBackend};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmResult,
    LlmStreamResult, LlmUsage, Vault, VaultConfig,
};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The model every request and offer here names.
const MODEL: &str = "test/model@r1";
/// What each call reserves, in tokens.
const CALL_RESERVE: u64 = 500;
const OCCURRED_AT: u64 = 1_700_000_000;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("a gated call pending on something other than its provider's answer");
}

/// A provider that answers every call at once with one short text.
struct AnsweringProvider;

impl LlmBackend for AnsweringProvider {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let mut usage = LlmUsage::zero();
        usage.raw_provider = json!({});
        Box::pin(std::future::ready(Ok(LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: "reranked".to_owned(),
                    signature: None,
                }],
            },
            usage,
            finish_reason: FinishReason::Stop,
            reply_assertions: ReplyAssertions::default(),
            token_scores: None,
        })))
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

impl SingleRouteBackend for AnsweringProvider {
    fn preflight(&self, _request: &LlmRequest, _stream: bool) -> LlmResult<()> {
        Ok(())
    }
}

/// The host's receipt sink as a server builds it: rows kept in order, and
/// the source rows' worlds read from its vault.
struct VaultReceipts {
    vault: Arc<Vault>,
    rows: MemoryReceipts,
}

impl RunReceiptSink for VaultReceipts {
    fn record(&self, receipt: RunReceipt) {
        self.rows.record(receipt);
    }

    fn source_worlds(&self, rows: &[EntityId]) -> Option<Vec<EntityId>> {
        self.vault.source_row_worlds(rows).ok().flatten()
    }
}

/// A vault with one world beside base reality, an owner claim in each, and
/// the receipt sink over it.
struct Fixture {
    _dir: tempfile::TempDir,
    harbor: EntityId,
    harbor_claim: EntityId,
    base_claim: EntityId,
    receipts: Arc<VaultReceipts>,
}

fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    world: EntityId,
    value: &str,
) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: world.to_hex(),
                scope_facet_id: vault.default_facet().expect("owner default facet").to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        })
        .expect("owner writes a claim in the requested world");
    id
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let harbor = vault
        .create_world(&owner_proof, "Harbor", OCCURRED_AT)
        .expect("owner creates a world");
    let harbor_claim = write_owner_claim(&vault, owner, &owner_proof, harbor, "harbor claim");
    let base_claim = write_owner_claim(&vault, owner, &owner_proof, base_world_id(), "base claim");
    Fixture {
        _dir: dir,
        harbor,
        harbor_claim,
        base_claim,
        receipts: Arc::new(VaultReceipts {
            vault: Arc::new(vault),
            rows: MemoryReceipts::default(),
        }),
    }
}

/// One model request that names no world, as every host door's call does.
fn unscoped_request() -> TestResult<LlmRequest> {
    Ok(LlmRequest {
        model: llm::ModelId::new(MODEL)?,
        envelope: llm::CallEnvelope {
            scope: llm::Scope::default(),
            purpose: llm::CallPurpose::Consolidation,
            class: llm::CallClass::BestEffort,
            tier: llm::TierPrecedence::for_purpose(
                &llm::CallPurpose::Consolidation,
                llm::ModelTierRef("default".into()),
            ),
            response_format: llm::ResponseFormat::Text,
            locality: llm::ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "rank these rows".to_owned(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    })
}

fn customer_offer() -> TestResult<OfferBinding> {
    Ok(OfferBinding {
        offer: format!("{MODEL}@model.test"),
        model: llm::ModelId::new(MODEL)?,
        route: OfferRoute::new("fake", "https://model.test:443")?,
        locality: llm::ModelLocality::OwnServer,
        payer: Payer::CustomerKey,
        credential_binding: Some("customer-key-1".to_owned()),
        catalog_revision: Some("catalog-7".to_owned()),
        custody: KeyCustody::T0,
        rates: Vec::new(),
        payer_person: None,
    })
}

fn declared_run(receipts: &Arc<VaultReceipts>) -> RunAdmission {
    RunAdmission::new(
        format!("source-worlds:{}", EntityId::now().to_hex()),
        RunDeclaration::declared(BudgetLine {
            limit_units: 10_000,
            reserve_units: CALL_RESERVE,
            unit: LeaseUnit::tokens(),
        }),
        None,
        receipts.clone(),
    )
}

/// Sends one call through the handle's gate.
fn call_once(run: &RunAdmission) -> TestResult {
    let offer = customer_offer()?;
    let gated = run.gate(Arc::new(AnsweringProvider), &offer);
    let request = unscoped_request()?;
    block_on_ready(run.call(
        &gated,
        RunCall {
            selector: None,
            request: &request,
            offer: &offer,
        },
    ))
    .map_err(|error| format!("call failed: {error:?}"))?;
    Ok(())
}

/// Each receipt's kind and JSON, in order.
fn receipt_rows(receipts: &VaultReceipts) -> TestResult<Vec<(&'static str, Value)>> {
    let mut rows = Vec::new();
    for row in receipts.rows.rows() {
        let kind = match &row.event {
            RunEvent::Admitted(_) => "admitted",
            RunEvent::Dispatched { .. } => "dispatched",
            RunEvent::Settled { .. } => "settled",
            RunEvent::Denied { .. } => "denied",
            _ => "other",
        };
        rows.push((kind, serde_json::to_value(&row)?));
    }
    Ok(rows)
}

fn worlds_json(worlds: &[EntityId]) -> TestResult<Value> {
    let sorted: Vec<EntityId> = worlds
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(serde_json::to_value(sorted)?)
}

#[test]
fn a_sourced_call_names_its_rows_worlds_on_every_receipt() -> TestResult {
    let fixture = fixture();
    let run = declared_run(&fixture.receipts)
        .sourced(Some(vec![fixture.harbor_claim, fixture.base_claim]));
    call_once(&run)?;

    let rows = receipt_rows(&fixture.receipts)?;
    let kinds: Vec<&str> = rows.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, ["admitted", "dispatched", "settled"], "{rows:?}");
    let expected = worlds_json(&[fixture.harbor, base_world_id()])?;
    for (kind, row) in &rows {
        assert_eq!(
            row.get("source_worlds"),
            Some(&expected),
            "the {kind} receipt names the worlds of the rows the call's input came from: {row}",
        );
        assert_eq!(
            row.get("world"),
            None,
            "a call that named no world claims none in its scope: {row}",
        );
    }
    Ok(())
}

#[test]
fn a_call_whose_rows_prove_no_world_names_none() -> TestResult {
    let fixture = fixture();
    // A row this vault does not hold proves no world, so the call's worlds
    // stay unknown, even beside a row that proves one.
    let unheld =
        declared_run(&fixture.receipts).sourced(Some(vec![fixture.harbor_claim, EntityId::now()]));
    call_once(&unheld)?;
    // A call whose host named no rows has no provenance at all.
    call_once(&declared_run(&fixture.receipts))?;

    let rows = receipt_rows(&fixture.receipts)?;
    assert_eq!(rows.len(), 6, "{rows:?}");
    for (kind, row) in &rows {
        assert_eq!(
            row.get("source_worlds"),
            None,
            "the {kind} receipt of a call with unknown provenance names no worlds: {row}",
        );
    }
    Ok(())
}

#[test]
fn a_held_call_names_its_rows_worlds() -> TestResult {
    let fixture = fixture();
    let run = declared_run(&fixture.receipts).sourced(Some(vec![fixture.harbor_claim]));
    run.refuse_in_world(
        Some("rerank"),
        MODEL,
        RunDenied::KeptOnDevice {
            reason: "world_stays_on_device",
        },
        None,
    );

    let rows = receipt_rows(&fixture.receipts)?;
    let [(kind, row)] = rows.as_slice() else {
        return Err(format!("one Denied receipt for the held rung, got {rows:?}").into());
    };
    assert_eq!(*kind, "denied");
    assert_eq!(
        row.get("source_worlds"),
        Some(&worlds_json(&[fixture.harbor])?),
        "the held call's Denied receipt names the worlds of the rows it would have sent: {row}",
    );
    Ok(())
}
