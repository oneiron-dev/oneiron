//! DESIGN 15-setting-primitive, stage 4 mixed (SETTING-KEYED-B, KB3): two rows leave their tables.
//! - This machine's residence choice is the install key `sync.residence.mode`: no row reads as no
//!   choice (the host's configured mode), the engine's switch records the choice the residence
//!   readers return, and `vault.settings.set` refuses a change past the switch.
//! - `BUDGET_RESIDENT_SHARE` splits: the owner's share for each resident is the key
//!   `budget.resident_share` (agent scope, the vault's row for every resident with none), and what
//!   the resident's calls were charged stays the ledger's. The run admission reads the share in
//!   force; the default split counts every resident on record; a change of the share leaves the
//!   depletion as it stands.
//! - Row B4 of BUDGET-TRAP-UNTYPED-NO-SENDER (D3), ported from `run_admission_step_budget.rs` with
//!   the share written through the key: a resident's step under its pinned share parks, and the
//!   owner's share write that fits the call wakes it in that write; a share still short, or
//!   another resident's share, does not.
//!
//! Trap states and the owner's release go through `oneiron::test_doors`, built only under
//! `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test setting_keyed_b_3`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::dreamer_runner::{
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DREAMER_SERVER_PARK_OWNER, DreamerConsolidationScope,
    DreamerParkWait, DreamerParkedWait, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt, ParkResumer,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm;
use oneiron::llm::run_admission::{
    Allocation, AllocationRef, BudgetLine, HostAccount, KeyCustody, LeaseUnit, MemoryReceipts,
    OfferBinding, OfferRoute, Payer, ResidentLedger, RunAdmission, RunCall, RunDeclaration,
};
use oneiron::memory::DreamerParkCauseView;
use oneiron::setting::{
    Restore, ScopeKind, SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope,
    SettingSync,
};
use oneiron::sync::SyncResidenceMode;
use oneiron::sync::residence::{
    load_device_sync_preference, resolve_residence_mode, set_device_sync_preference,
};
use oneiron::test_doors::park_typed_wait as doors;
use oneiron::test_doors::wake_d1_park_release as release_doors;
use oneiron::{EntityId, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The owner's share of the host-paid allocation for each resident.
const SHARE: &str = "budget.resident_share";
/// This machine's residence choice.
const RESIDENCE: &str = "sync.residence.mode";

/// The model every request and offer here names.
const MODEL: &str = "test/model@r1";
/// What each call reserves, in tokens: on the step's guard, the run's line and the allocation.
const STEP_RESERVE: u64 = 500;
/// Room enough for every call here on the step's guard and the run's line.
const ROOM_UNITS: u64 = 10_000;
/// The host's allocation, in tokens: far more than any call here asks.
const ALLOCATION_UNITS: u64 = 100_000;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    // The backend answers at once and a refused or parked step never awaits anything else, so
    // polling again immediately is correct; the bound catches a future pending on anything else.
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("a host-paid step pending on something other than its backend's answer");
}

/// A temporary vault with a process-memory device keystore, as the crate's test opener opens one.
fn open_vault() -> oneiron::Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    Ok((dir, vault))
}

/// The vault's embedded owner, authenticated: what an owner door takes.
fn embedded_owner_proof(vault: &Vault) -> oneiron::consent::AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// One paid model request on the owner's own server.
fn paid_step_request(text: &str) -> llm::LlmRequest {
    llm::LlmRequest {
        model: llm::ModelId::new(MODEL).expect("model id"),
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
        messages: vec![llm::LlmMessage {
            role: llm::LlmMessageRole::User,
            content: vec![llm::ContentPart::Text {
                text: text.to_owned(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    }
}

/// The host's paid offer of the model on the owner's own server, under a T0 key, priced in tokens.
fn host_offer() -> OfferBinding {
    OfferBinding {
        offer: format!("{MODEL}@model.test"),
        model: llm::ModelId::new(MODEL).expect("model id"),
        route: OfferRoute::new("fake", "https://model.test:443").expect("route"),
        locality: llm::ModelLocality::OwnServer,
        payer: Payer::Host,
        credential_binding: Some("host-key-1".to_owned()),
        catalog_revision: Some("catalog-7".to_owned()),
        custody: KeyCustody::T0,
        rates: Vec::new(),
        payer_person: None,
    }
}

/// A declared run on a token line with room for every call here; `host` pays its host-paid calls.
fn host_paid_run(name: &str, host: Option<Arc<HostAccount>>) -> RunAdmission {
    RunAdmission::new(
        name,
        RunDeclaration::declared(BudgetLine {
            limit_units: ROOM_UNITS,
            reserve_units: STEP_RESERVE,
            unit: LeaseUnit::tokens(),
        }),
        host,
        Arc::new(MemoryReceipts::default()),
    )
}

/// A host-paid model backend: it runs the host's run admission for each call, as a gated backend
/// does before it sends, and answers a refusal as the model error the refusal reads as. It sends
/// nothing: an admitted call answers a fatal error, which no step here reaches.
struct AdmittingBackend {
    run: RunAdmission,
    offer: OfferBinding,
    calls: AtomicUsize,
}

impl AdmittingBackend {
    fn new(run: RunAdmission) -> Self {
        Self {
            run,
            offer: host_offer(),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Whether the run admission admits one more call of the step's request now.
    fn admits(&self) -> bool {
        let request = paid_step_request("host-paid step");
        self.run
            .admit(RunCall {
                selector: None,
                request: &request,
                offer: &self.offer,
            })
            .is_ok()
    }
}

impl llm::LlmBackend for AdmittingBackend {
    fn generate<'a>(
        &'a self,
        request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = match self.run.admit(RunCall {
            selector: None,
            request: &request,
            offer: &self.offer,
        }) {
            Ok(_permit) => Err(llm::LlmError::Fatal(llm::FatalLlmError::EmptyResponse)),
            Err(denied) => Err(llm::LlmError::from(denied)),
        };
        Box::pin(std::future::ready(answer))
    }

    fn stream<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmStreamResult<'a> {
        panic!("a durable step's paid call here generates; it never streams");
    }
}

/// One micro consolidation try enqueued under `tag` and claimed under the Dreamer server's lease
/// owner, as a running server's pass holds it, so its step parks under a live lease.
fn leased_try(vault: &Vault, tag: &str, now: u64) -> oneiron::Result<AttemptRecord> {
    let store = DreamerRunnerStore::new(vault);
    let status = match store.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        input: rmpv::Value::from(format!("input:{tag}")),
        parent_attempt: None,
        dedupe_key: Some(tag.to_owned()),
        run_id: None,
        now,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
        // The outcome enum is `#[non_exhaustive]` outside the crate.
        other => panic!("unexpected enqueue outcome {other:?}"),
    };
    let ClaimOutcome::Claimed(row) = AttemptQueue::new(vault).claim_kind(
        DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
            now: u64::MAX,
        },
    )?
    else {
        panic!("the enqueued try is ready to claim");
    };
    assert_eq!(
        row.id, status.attempt.id,
        "the claim takes the try just enqueued"
    );
    Ok(row)
}

/// Runs one host-paid step of `row`'s try, bound to its wake pass as every Dreamer host's step is,
/// under a step guard with room, so only the run admission below the backend can refuse it.
fn host_paid_step(
    vault: &Vault,
    row: &AttemptRecord,
    now_ms: u64,
    backend: &AdmittingBackend,
) -> llm::DurableStepResult<llm::StepOutcome> {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let ctx = llm::DurableStepContext {
        vault,
        attempt_id: row.id,
        run_id: None,
        envelope_actor: WriteActor::new(owner, EdgeActorClass::Human),
        subject: owner,
        deadline: None,
        now_ms,
        spend_scope: None,
        wake_pass_bound: true,
    };
    let guard = llm::BudgetGuard::with_reserve_units(
        "run-admission-step",
        ROOM_UNITS,
        STEP_RESERVE,
        llm::BudgetExhaustionPolicy::Suspend,
    );
    block_on_ready(llm::call_as_step(
        &ctx,
        backend,
        &guard,
        paid_step_request("host-paid step"),
    ))
}

/// Parks `row`'s try on its resident's spent share: the run admission refuses its host-paid step.
/// Asserts the park's wait and its resumers, and returns its trap.
fn park_on_share(
    vault: &Vault,
    row: &AttemptRecord,
    resident: EntityId,
    backend: &AdmittingBackend,
) -> Result<llm::TrapRef, Box<dyn std::error::Error>> {
    let outcome = host_paid_step(vault, row, 1_000, backend);
    let trap = match outcome {
        Ok(llm::StepOutcome::Trapped { trap, .. }) => trap,
        other => panic!("a resident's spent pinned share traps the step: got {other:?}"),
    };
    assert_eq!(
        trap.kind,
        llm::DreamerTrapKind::Budget,
        "the resident's step parks at a budget trap"
    );
    let park = DreamerRunnerStore::new(vault)
        .parked_attempt(row.id)?
        .expect("the resident's step park");
    assert_eq!(
        park.park_owner,
        llm::trap_park_owner(&trap.trap_claim_id),
        "the resident's step park sits under its trap's owner"
    );
    assert_eq!(
        park.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::ResidentShare {
                resident,
                needed_units: STEP_RESERVE,
            },
            lease_generation: row.attempt_count,
        }),
        "a resident's spent pinned share parks a resident share wait naming the share the call needed"
    );
    for resumer in ParkResumer::ALL {
        assert_eq!(
            park.resumable_by(resumer),
            matches!(
                resumer,
                ParkResumer::ResidentShareRaise
                    | ParkResumer::TrapConsume
                    | ParkResumer::OwnerRelease
            ),
            "only the owner's share write, its trap consume or the owner's release resumes a resident share park ({resumer:?})"
        );
    }
    Ok(trap)
}

/// Asserts `row`'s try was woken as the same try: its park gone, its trap consumed, queued again
/// under the same lease generation.
fn assert_woken(vault: &Vault, row: &AttemptRecord, trap: &llm::TrapRef, what: &str) -> TestResult {
    let store = DreamerRunnerStore::new(vault);
    assert!(
        store.parked_attempt(row.id)?.is_none(),
        "{what} clears the park"
    );
    assert_eq!(
        doors::trap_state(vault, trap)?,
        llm::DreamerTrapState::Consumed,
        "{what} consumes the park's trap"
    );
    let status = store.status(row.id)?.expect("the woken try's row");
    assert_eq!(
        status.attempt.state.as_str(),
        "queued",
        "{what} queues the same try again"
    );
    assert_eq!(
        status.attempt.attempt_count, row.attempt_count,
        "{what} keeps the try's lease generation"
    );
    Ok(())
}

/// Asserts `row`'s try still waits at its trap, leased as its host holds it.
fn assert_still_parked(vault: &Vault, row: &AttemptRecord, what: &str) -> TestResult {
    assert!(
        DreamerRunnerStore::new(vault)
            .parked_attempt(row.id)?
            .is_some(),
        "{what} leaves the resident's park"
    );
    let after = AttemptQueue::new(vault)
        .get(row.id)?
        .expect("the parked try");
    assert_eq!(
        after.state.as_str(),
        "leased",
        "{what} leaves the parked try leased"
    );
    Ok(())
}

/// The owner pins `resident`'s share at `units`: a value row of `budget.resident_share` at the
/// resident's agent scope, through `vault.settings.set`'s door.
fn pin_share(
    vault: &Vault,
    owner: &oneiron::consent::AuthenticatedOwner,
    resident: EntityId,
    units: u64,
) -> TestResult {
    set_share(
        vault,
        owner,
        SettingScope::Agent(resident),
        Some(json!({ "units": units, "pinned": true })),
    )
}

/// The owner sets (or, with `None`, clears) the share row at `scope`.
fn set_share(
    vault: &Vault,
    owner: &oneiron::consent::AuthenticatedOwner,
    scope: SettingScope,
    value: Option<serde_json::Value>,
) -> TestResult {
    let outcome = vault.set_setting(
        SettingCaller::Owner(owner),
        SetSetting {
            key: SHARE.to_owned(),
            item: None,
            scope,
            mode: SettingMode::Value,
            value,
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    )?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's share write applies: {outcome:?}"
    );
    Ok(())
}

fn attempt_hex(row: &AttemptRecord) -> String {
    row.id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn a_resident_step_under_its_pinned_share_parks_until_the_owners_share_write_fits_it() -> TestResult
{
    let (_dir, vault) = open_vault()?;
    let vault = Arc::new(vault);
    let owner = embedded_owner_proof(&vault);
    let resident = EntityId::now();
    let account = HostAccount::with_residents(llm::VaultResidentLedger::new(Arc::clone(&vault)));
    account.grant(Allocation {
        reference: AllocationRef {
            id: "allocation-1".to_owned(),
            generation: 1,
        },
        units: ALLOCATION_UNITS,
        unit: LeaseUnit::tokens(),
        wallet: None,
    })?;
    pin_share(&vault, &owner, resident, 0)?;
    let backend = AdmittingBackend::new(
        host_paid_run("resident-share", Some(account)).initiated_by(Some(resident)),
    );

    // 1. The pinned share refuses both tries' host-paid steps: each parks a resident share wait.
    let row_a = leased_try(&vault, "resident-share-a", 1)?;
    let trap_a = park_on_share(&vault, &row_a, resident, &backend)?;
    let row_b = leased_try(&vault, "resident-share-b", 2)?;
    let trap_b = park_on_share(&vault, &row_b, resident, &backend)?;
    assert!(
        !backend.admits(),
        "the run admission still refuses the resident's call"
    );

    // 2. A share write still short of the call, and another resident's share write, wake nothing.
    pin_share(&vault, &owner, resident, STEP_RESERVE - 1)?;
    assert_still_parked(&vault, &row_a, "a share write still short of the call")?;
    assert_still_parked(&vault, &row_b, "a share write still short of the call")?;
    pin_share(&vault, &owner, EntityId::now(), ALLOCATION_UNITS)?;
    assert_still_parked(&vault, &row_a, "another resident's share write")?;
    assert_still_parked(&vault, &row_b, "another resident's share write")?;

    // 3. The owner's release frees a resident share park too: Resume wakes its trap.
    let store = DreamerRunnerStore::new(&vault);
    let park_b = store
        .parked_attempt(row_b.id)?
        .expect("try B's resident share park");
    let released = release_doors::release_as_owner(
        &vault,
        &owner,
        &attempt_hex(&row_b),
        DreamerParkCauseView::from(park_b.cause),
        park_b.parked_at,
        row_b.attempt_count,
    );
    let released = match released {
        Ok(released) => released,
        Err(error) => panic!("the owner's Resume serves a resident share park: got {error:?}"),
    };
    assert!(
        released.effected,
        "the owner's Resume of a resident share park queues it"
    );
    assert_woken(
        &vault,
        &row_b,
        &trap_b,
        "the owner's Resume of a resident share park",
    )?;

    // 4. The owner's share write that fits the call wakes the park in that write, and the run
    // admission now admits the resident's call.
    pin_share(&vault, &owner, resident, STEP_RESERVE)?;
    assert_woken(
        &vault,
        &row_a,
        &trap_a,
        "the owner's share write that fits the call",
    )?;
    assert!(backend.admits(), "the share that fits the call admits it");
    Ok(())
}

fn allocation(generation: u64) -> AllocationRef {
    AllocationRef {
        id: "allocation-1".to_owned(),
        generation,
    }
}

#[test]
fn the_residence_mode_reads_no_choice_until_the_engine_switch_records_one() -> TestResult {
    let (_dir, vault) = open_vault()?;
    assert_eq!(
        load_device_sync_preference(&vault)?,
        None,
        "no row reads as no choice"
    );
    assert_eq!(
        resolve_residence_mode(&vault, SyncResidenceMode::Opened)?,
        SyncResidenceMode::Opened,
        "with no choice the host's configured mode holds"
    );
    let spec = oneiron::setting::spec_named(RESIDENCE)?;
    assert_eq!(
        spec.sync,
        SettingSync::Install,
        "the residence choice is this machine's"
    );
    assert!(
        spec.on_change.is_some(),
        "the key refuses a change past its switch"
    );

    set_device_sync_preference(&vault, SyncResidenceMode::All)?;
    assert_eq!(
        load_device_sync_preference(&vault)?.map(|preference| preference.mode),
        Some(SyncResidenceMode::All),
        "the switch's choice is what the reader returns"
    );
    assert_eq!(
        resolve_residence_mode(&vault, SyncResidenceMode::Opened)?,
        SyncResidenceMode::All,
        "the choice outranks the host's configured mode"
    );
    Ok(())
}

#[test]
fn the_owners_settings_door_refuses_the_residence_mode_past_its_switch() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = embedded_owner_proof(&vault);
    let refused = vault
        .set_setting(
            SettingCaller::Owner(&owner),
            SetSetting::vault_value(RESIDENCE, json!("all")),
        )
        .expect_err("vault.settings.set refuses the residence mode");
    assert!(
        format!("{refused:?}").contains("vault.residence.mode"),
        "the refusal names the residence door: {refused:?}"
    );
    assert_eq!(
        load_device_sync_preference(&vault)?,
        None,
        "the refused change writes nothing"
    );
    Ok(())
}

#[test]
fn the_owners_share_row_is_what_the_run_admission_reads() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let vault = Arc::new(vault);
    let owner = embedded_owner_proof(&vault);
    let ledger = llm::VaultResidentLedger::new(Arc::clone(&vault));
    let resident = EntityId::now();
    let other = EntityId::now();

    let spec = oneiron::setting::spec_named(SHARE)?;
    assert!(
        spec.admits_scope(ScopeKind::Agent),
        "a resident's share sits at its agent scope"
    );
    assert_eq!(
        spec.restore,
        Restore::Live,
        "the share stays live through a restore"
    );

    let before = ledger.standing(resident, &allocation(1), 100);
    assert_eq!(
        (before.share_units, before.pinned, before.used_units),
        (100, false, 0),
        "with no row a lone resident's default split is the whole allocation"
    );
    assert!(vault.resident_shares()?.is_empty(), "no resident on record");

    set_share(
        &vault,
        &owner,
        SettingScope::Agent(resident),
        Some(json!({ "units": 30, "pinned": true })),
    )?;
    let own = ledger.standing(resident, &allocation(1), 100);
    assert_eq!(
        (own.share_units, own.pinned),
        (30, true),
        "the resident's own row is its share"
    );
    let shares = vault.resident_shares()?;
    assert_eq!(
        shares.len(),
        1,
        "the share write puts its resident on record"
    );
    assert_eq!(shares[0].resident, resident);
    assert_eq!(shares[0].share.units, Some(30));
    assert!(shares[0].share.pinned);
    let split = ledger.standing(other, &allocation(1), 100);
    assert_eq!(
        (split.share_units, split.pinned),
        (70, false),
        "a resident with no row splits what the shares in units leave"
    );

    set_share(
        &vault,
        &owner,
        SettingScope::Vault,
        Some(json!({ "units": 10, "pinned": false })),
    )?;
    assert_eq!(
        ledger.standing(other, &allocation(1), 100).share_units,
        10,
        "the vault's row is the share of every resident with none of its own"
    );
    assert_eq!(
        ledger.standing(resident, &allocation(1), 100).share_units,
        30,
        "the resident's own row still decides for it"
    );
    Ok(())
}

#[test]
fn a_share_change_leaves_the_charges_in_the_ledger() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let vault = Arc::new(vault);
    let owner = embedded_owner_proof(&vault);
    let ledger = llm::VaultResidentLedger::new(Arc::clone(&vault));
    let resident = EntityId::now();

    set_share(
        &vault,
        &owner,
        SettingScope::Agent(resident),
        Some(json!({ "units": 50, "pinned": false })),
    )?;
    ledger.charge(resident, &allocation(1), 20, 0);
    ledger.charge(resident, &allocation(1), 40, 10);
    let read = ledger.standing(resident, &allocation(1), 100);
    assert_eq!((read.share_units, read.used_units), (50, 60));

    set_share(&vault, &owner, SettingScope::Agent(resident), None)?;
    let cleared = ledger.standing(resident, &allocation(1), 100);
    assert_eq!(
        (cleared.share_units, cleared.pinned, cleared.used_units),
        (100, false, 60),
        "a cleared share is the default split again, and the depletion stays as it stands"
    );
    let shares = vault.resident_shares()?;
    assert_eq!(shares.len(), 1, "the resident stays on record");
    assert_eq!(
        (
            shares[0].share.units,
            shares[0].used_units,
            shares[0].overdraft_units,
            shares[0].overdrafts
        ),
        (None, 60, 10, 1),
        "the owner's read shows the share in force beside the ledger's counts"
    );
    assert_eq!(
        ledger.standing(resident, &allocation(2), 100).used_units,
        0,
        "a new allocation generation starts the depletion again"
    );
    Ok(())
}
