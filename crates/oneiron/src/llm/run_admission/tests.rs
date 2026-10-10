//! The research-connector fixture (ARCH-0053 `#training-fixture-cases`) on
//! local fakes. The admission, alias resolution, reservation, dispatch and
//! settlement are production code; only the upstreams are fakes.
//!
//! The `ai.*` leg runs here in full. The paid leg runs against the admission
//! contract a leased paid adapter calls; RSG-006 stays open until the broker's
//! first real leased adapter passes N4a and P2, and N4b, N5's wire forms and
//! N11 (key reflection) need that adapter too.
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Barrier};
use std::task::{Context, Waker};

use super::*;
use crate::llm::{
    BudgetDenied, CallClass, CallEnvelope, CallPurpose, ContentPart, DispatchRefused,
    FAILED_RUNGS_KEY, FatalLlmError, LlmBackend, LlmCapability, LlmError, LlmMessage,
    LlmMessageRole, LlmRequest, LlmStreamEvent, ModelId, ModelLocality, ModelTierRef,
    ResponseFormat, TierPrecedence,
};

mod support;
use support::{
    FakePaidEndpoint, FakeProvider, FakeResolver, Reply, SENTINEL_KEY, block_on, paid_call,
};

const RUN: &str = "run-1";
const SMALL: &str = "fake/teacher-small@v1";
const LARGE: &str = "fake/teacher-large@v1";
const MODEL_ORIGIN: &str = "https://model.test:443";
const PAID_ORIGIN: &str = "https://paid.test:443";

fn id(model: &str) -> ModelId {
    ModelId::new(model).expect("model id")
}

fn units() -> LeaseUnit {
    LeaseUnit::new("units").expect("unit")
}

/// Run A's line: 20 units; a model call reserves 6.
fn line() -> BudgetLine {
    BudgetLine {
        limit_units: 20,
        reserve_units: 6,
        unit: units(),
    }
}

fn one_to_one() -> Vec<UnitRate> {
    vec![UnitRate {
        unit: units(),
        per: 1,
        cost: 1,
    }]
}

fn model_route() -> OfferRoute {
    OfferRoute::new("fake", MODEL_ORIGIN).expect("route")
}

fn offer(model: &str) -> OfferBinding {
    OfferBinding {
        offer: format!("{model}@model.test"),
        model: id(model),
        route: model_route(),
        locality: ModelLocality::ThirdParty,
        payer: Payer::CustomerKey,
        catalog_revision: Some("catalog-7".to_owned()),
        custody: KeyCustody::T0,
        rates: one_to_one(),
    }
}

fn local_offer() -> OfferBinding {
    OfferBinding {
        offer: "local/small@v1@device".to_owned(),
        model: id("local/small@v1"),
        route: OfferRoute::new("local", "device").expect("route"),
        locality: ModelLocality::OnDevice,
        payer: Payer::Local,
        catalog_revision: None,
        custody: KeyCustody::Keyless,
        rates: one_to_one(),
    }
}

fn search() -> PaidConnector {
    PaidConnector {
        connector: "search".to_owned(),
        route: OfferRoute::new("paid", PAID_ORIGIN).expect("route"),
        locality: ModelLocality::ThirdParty,
        payer: Payer::CustomerKey,
        catalog_revision: Some("catalog-7".to_owned()),
        custody: KeyCustody::T0,
        unit_cost: 3,
        cost_unit: units(),
        rates: Vec::new(),
    }
}

fn request(model: &str) -> LlmRequest {
    let purpose = CallPurpose::Other {
        name: "teacher".to_owned(),
    };
    LlmRequest {
        model: id(model),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("teacher".to_owned())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "label this pair".to_owned(),
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}

fn host_aliases() -> BTreeMap<String, ModelId> {
    BTreeMap::from([
        ("teacher-small".to_owned(), id(SMALL)),
        ("teacher-other".to_owned(), id(LARGE)),
    ])
}

fn teachers(models: &[&str], aliases: &BTreeMap<String, ModelId>) -> DeclaredTeachers {
    DeclaredTeachers::new(
        models.iter().map(|model| id(model)),
        aliases.clone(),
        "seat/decision@local",
        "fine-tune the vault's decision seat",
    )
    .expect("teachers")
}

/// Run A declares the small teacher and the search connector.
fn declaration() -> RunDeclaration {
    RunDeclaration::declared(line())
        .with_teachers(teachers(&[SMALL], &host_aliases()))
        .with_connector("search")
}

struct Run {
    admission: RunAdmission,
    receipts: Arc<MemoryReceipts>,
}

impl Run {
    fn start(declaration: RunDeclaration, host: Option<Arc<HostAccount>>) -> Self {
        let receipts = Arc::new(MemoryReceipts::default());
        Self {
            admission: RunAdmission::new(RUN, declaration, host, receipts.clone()),
            receipts,
        }
    }

    fn denials(&self) -> usize {
        self.receipts
            .rows()
            .iter()
            .filter(|row| matches!(row.event, RunEvent::Denied { .. }))
            .count()
    }

    fn used(&self) -> u64 {
        self.admission.read().used_units
    }

    fn reserved(&self) -> u64 {
        self.admission.read().reserved_units
    }
}

/// What every refusal must leave behind: nothing sent, nothing resolved,
/// nothing spent or reserved, one denial row, and no key in any row.
struct Before {
    sends: usize,
    paid_sends: usize,
    resolved: u32,
    used: u64,
    reserved: u64,
    denials: usize,
}

struct World {
    a: Run,
    b: Run,
    provider: Arc<FakeProvider>,
    gated_a: GatedBackend,
    gated_b: GatedBackend,
    resolver: FakeResolver,
    endpoint: FakePaidEndpoint,
}

impl World {
    fn new() -> Self {
        Self::with(declaration())
    }

    fn with(declaration_a: RunDeclaration) -> Self {
        let provider = FakeProvider::new();
        let a = Run::start(declaration_a, None);
        // Run B has its own line and the same textual run id.
        let b = Run::start(declaration(), None);
        let gated_a = a.admission.gate(provider.clone(), &model_route());
        let gated_b = b.admission.gate(provider.clone(), &model_route());
        Self {
            a,
            b,
            provider,
            gated_a,
            gated_b,
            resolver: FakeResolver::default(),
            endpoint: FakePaidEndpoint::default(),
        }
    }

    fn before(&self) -> Before {
        Before {
            sends: self.provider.sent().len(),
            paid_sends: self.endpoint.sends(),
            resolved: self.resolver.resolved(),
            used: self.a.used(),
            reserved: self.a.reserved(),
            denials: self.a.denials(),
        }
    }

    fn assert_refused_cleanly(&self, before: &Before) {
        assert_eq!(
            self.provider.sent().len(),
            before.sends,
            "a send reached the fake"
        );
        assert_eq!(
            self.endpoint.sends(),
            before.paid_sends,
            "a paid send happened"
        );
        assert_eq!(
            self.resolver.resolved(),
            before.resolved,
            "a key was resolved"
        );
        assert_eq!(self.a.used(), before.used, "units were spent");
        assert_eq!(self.a.reserved(), before.reserved, "a reservation leaked");
        assert_eq!(self.a.denials(), before.denials + 1, "one denial row");
        assert_no_key(&self.a.receipts);
    }

    fn generate(
        &self,
        gated: &GatedBackend,
        request: LlmRequest,
        permit: &RunPermit,
    ) -> Result<(), LlmError> {
        block_on(gated.generate(request, permit.lease())).map(|_| ())
    }
}

fn assert_no_key(receipts: &MemoryReceipts) {
    let rows = serde_json::to_string(&receipts.rows()).expect("receipts serialize");
    assert!(!rows.contains(SENTINEL_KEY), "a receipt holds the key");
}

fn admit(
    run: &Run,
    selector: Option<&str>,
    request: &LlmRequest,
    offer: &OfferBinding,
) -> Result<RunPermit, RunDenied> {
    run.admission.admit(RunCall {
        selector,
        request,
        offer,
    })
}

// ---------------------------------------------------------------------------
// Negative cases
// ---------------------------------------------------------------------------

#[test]
fn n1_a_teacher_the_run_did_not_declare_is_refused_by_id_and_by_alias() {
    let world = World::new();
    let before = world.before();
    let named = request("fake/teacher-b@v1");
    assert_eq!(
        admit(&world.a, None, &named, &offer("fake/teacher-b@v1")).expect_err("undeclared"),
        RunDenied::UndeclaredTeacher {
            model: id("fake/teacher-b@v1")
        }
    );
    world.assert_refused_cleanly(&before);

    let before = world.before();
    let resolved = world
        .a
        .admission
        .resolve("teacher-other")
        .expect("frozen alias");
    assert_eq!(resolved, id(LARGE));
    let aliased = request(resolved.as_str());
    assert_eq!(
        admit(&world.a, Some("teacher-other"), &aliased, &offer(LARGE))
            .expect_err("alias to undeclared"),
        RunDenied::UndeclaredTeacher { model: id(LARGE) }
    );
    world.assert_refused_cleanly(&before);
}

#[test]
fn n2_alias_drift_is_refused_and_the_run_keeps_its_frozen_aliases() {
    let mut aliases = host_aliases();
    let world = World::with(
        RunDeclaration::declared(line())
            .with_teachers(teachers(&[SMALL], &aliases))
            .with_connector("search"),
    );
    // No revision: not a model id and not a frozen alias.
    assert_eq!(
        world.a.admission.resolve("fake/teacher-small"),
        Err(RunDenied::UnknownSelector {
            selector: "fake/teacher-small".to_owned()
        })
    );
    for drifted in ["fake/teacher-small@v2", "Fake/Teacher-Small@v1"] {
        let before = world.before();
        let model = world.a.admission.resolve(drifted).expect("an id");
        assert_eq!(
            admit(
                &world.a,
                Some(drifted),
                &request(model.as_str()),
                &offer(model.as_str())
            )
            .expect_err("drifted id"),
            RunDenied::UndeclaredTeacher { model }
        );
        world.assert_refused_cleanly(&before);
    }
    // The host remaps the alias after the run started; the run does not follow.
    aliases.insert("teacher-small".to_owned(), id("fake/teacher-small@v2"));
    assert_eq!(world.a.admission.resolve("teacher-small"), Ok(id(SMALL)));
    let before = world.before();
    let remapped = aliases["teacher-small"].clone();
    assert!(matches!(
        admit(
            &world.a,
            Some("teacher-small"),
            &request(remapped.as_str()),
            &offer(remapped.as_str())
        ),
        Err(RunDenied::UndeclaredTeacher { .. })
    ));
    world.assert_refused_cleanly(&before);
}

/// One way a request names another model or route than its permit.
type Swap = fn(&mut LlmRequest);

#[test]
fn n3_a_model_swap_after_admission_is_refused_before_send() {
    let world = World::new();
    let permit = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("declared teacher");
    let reserved = world.a.reserved();

    // The body names the large model under the small model's permit.
    let before = world.before();
    assert_eq!(
        world.generate(&world.gated_a, request(LARGE), &permit),
        Err(LlmError::BudgetDenied(BudgetDenied::LeaseInvalid))
    );
    world.assert_refused_cleanly(&before);

    // A param or provider option picks another model or route.
    let swaps: [(&str, Swap); 5] = [
        ("model", |r| {
            r.params.insert("model".into(), LARGE.into());
        }),
        ("openai.model", |r| {
            r.provider_options
                .insert("openai".into(), serde_json::json!({ "model": LARGE }));
        }),
        ("openai.models", |r| {
            r.provider_options.insert(
                "openai".into(),
                serde_json::json!({ "models": [SMALL, LARGE] }),
            );
        }),
        ("route", |r| {
            r.params.insert("route".into(), "fallback".into());
        }),
        ("anthropic.provider", |r| {
            r.provider_options.insert(
                "anthropic".into(),
                serde_json::json!({ "provider": { "order": ["other"] } }),
            );
        }),
    ];
    for (key, swap) in swaps {
        let mut swapped = request(SMALL);
        swap(&mut swapped);
        let before = world.before();
        assert_eq!(
            world.generate(&world.gated_a, swapped.clone(), &permit),
            Err(crate::llm::FatalLlmError::InvalidRequest.into()),
            "{key}"
        );
        world.assert_refused_cleanly(&before);
        // Refused at admission too, before any reservation.
        let before = world.before();
        assert_eq!(
            admit(&world.a, None, &swapped, &offer(SMALL)).expect_err("override"),
            RunDenied::RouteOverride {
                key: key.to_owned()
            }
        );
        world.assert_refused_cleanly(&before);
    }
    // None of the refusals spent the permit; it still serves its own call.
    assert_eq!(world.a.reserved(), reserved);
    world
        .generate(&world.gated_a, request(SMALL), &permit)
        .expect("the permit's own call");
    assert_eq!(world.provider.sent().len(), 1);
}

#[test]
fn n4a_a_paid_call_without_this_runs_admission_sends_nothing() {
    let world = World::new();
    let other_run = admit(&world.b, None, &request(SMALL), &offer(SMALL)).expect("run B permit");
    for lease in [
        crate::llm::BudgetLease::for_test("run-1:metered:1"),
        other_run.lease().clone(),
    ] {
        let before = world.before();
        assert_eq!(
            paid_call(
                &world.a.admission,
                &lease,
                &search(),
                &world.resolver,
                &world.endpoint,
                1
            ),
            Err(RunDenied::Dispatch {
                refused: DispatchRefused::ForeignLease
            })
        );
        world.assert_refused_cleanly(&before);
    }
}

#[test]
fn n5_a_permit_does_not_carry_onto_a_lookalike_or_other_route() {
    let world = World::new();
    let permit = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("permit");
    for origin in [
        "https://model.test.evil.test:443",
        "https://notmodel.test:443",
        "http://model.test:443",
        "https://model.test:8443",
        "https://child.model.test:443",
    ] {
        let lookalike = world.a.admission.gate(
            world.provider.clone(),
            &OfferRoute::new("fake", origin).expect("route"),
        );
        let before = world.before();
        assert_eq!(
            world.generate(&lookalike, request(SMALL), &permit),
            Err(LlmError::BudgetDenied(BudgetDenied::LeaseInvalid)),
            "{origin}"
        );
        world.assert_refused_cleanly(&before);
    }
    // A userinfo lookalike never becomes a route at all.
    assert_eq!(
        OfferRoute::new("fake", "https://user@model.test:443"),
        Err(OfferRouteError::Origin)
    );
}

#[test]
fn n6_a_lease_from_another_run_is_refused_before_the_provider() {
    let world = World::new();
    let theirs = admit(&world.b, None, &request(SMALL), &offer(SMALL)).expect("run B permit");
    let ours = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("run A permit");
    // Equal textual ids: the same run id, the same sequence.
    assert_eq!(theirs.lease().id(), ours.lease().id());
    let b_before = (world.b.used(), world.b.reserved());
    let before = world.before();
    assert_eq!(
        world.generate(&world.gated_a, request(SMALL), &theirs),
        Err(LlmError::BudgetDenied(BudgetDenied::LeaseInvalid))
    );
    world.assert_refused_cleanly(&before);
    assert_eq!((world.b.used(), world.b.reserved()), b_before);
    // And run A's permit does not open run B's backend.
    assert!(
        world
            .generate(&world.gated_b, request(SMALL), &ours)
            .is_err()
    );
    assert_eq!(world.provider.sent().len(), 0);
}

#[test]
fn n7_a_settled_aborted_or_cloned_permit_dispatches_at_most_once() {
    let world = World::new();
    let settled = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("permit");
    world
        .generate(&world.gated_a, request(SMALL), &settled)
        .expect("first call");
    let usage = world.provider.sent().len();
    let settled_lease = settled.lease().clone();
    settled
        .settle(CallOutcome::Answered(&crate::llm::LlmUsage::zero()))
        .expect("settle");
    let aborted = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("permit");
    let aborted_lease = aborted.lease().clone();
    aborted
        .settle(CallOutcome::Failed)
        .expect("abort before dispatch");
    for lease in [&settled_lease, &aborted_lease] {
        let before = world.before();
        assert_eq!(
            block_on(world.gated_a.generate(request(SMALL), lease)).map(|_| ()),
            Err(LlmError::BudgetDenied(BudgetDenied::LeaseInvalid))
        );
        world.assert_refused_cleanly(&before);
    }
    assert_eq!(world.provider.sent().len(), usage);

    // Two clones of one permit, sent at once.
    let raced = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("permit");
    let start = Barrier::new(2);
    let results: Vec<_> = std::thread::scope(|scope| {
        let racers: Vec<_> = (0..2)
            .map(|_| {
                let lease = raced.lease().clone();
                let gated = &world.gated_a;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    block_on(gated.generate(request(SMALL), &lease)).is_ok()
                })
            })
            .collect();
        racers
            .into_iter()
            .map(|racer| racer.join().expect("racer"))
            .collect()
    });
    assert_eq!(results.iter().filter(|ok| **ok).count(), 1);
    assert_eq!(world.provider.sent().len(), usage + 1);
}

#[test]
fn n8_a_remote_call_labelled_on_device_gets_no_unmetered_lease() {
    let world = World::new();
    let mut labelled = request(SMALL);
    labelled.envelope.locality = ModelLocality::OnDevice;
    let before = world.before();
    assert_eq!(
        admit(&world.a, None, &labelled, &offer(SMALL)).expect_err("locality lie"),
        RunDenied::LocalityMismatch
    );
    world.assert_refused_cleanly(&before);
    // A host-local payer on a remote route is still metered.
    let mut remote_local = offer(SMALL);
    remote_local.payer = Payer::Local;
    let permit = admit(&world.a, None, &request(SMALL), &remote_local).expect("metered");
    assert_eq!(permit.facts().reserved_units, 6);
}

#[test]
fn n9_an_exhausted_line_refuses_new_calls_while_an_admitted_call_settles_in_full() {
    let world = World::new();
    let first = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("6 of 20");
    let second = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("12 of 20");
    let third = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("18 of 20");
    let before = world.before();
    assert_eq!(
        admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect_err("24 > 20"),
        RunDenied::Budget {
            denied: BudgetDenied::Exhausted
        }
    );
    world.assert_refused_cleanly(&before);
    let before = world.before();
    assert_eq!(
        world
            .a
            .admission
            .admit_paid(&search(), 1)
            .expect_err("21 > 20"),
        RunDenied::Budget {
            denied: BudgetDenied::Exhausted
        }
    );
    world.assert_refused_cleanly(&before);

    // The first call runs long: 9 units against its 6-unit estimate.
    world.provider.reply_with(Reply::Usage {
        input: 7,
        output: 2,
    });
    let response = block_on(world.gated_a.generate(request(SMALL), first.lease()))
        .expect("admitted call finishes");
    first
        .settle(CallOutcome::Answered(&response.usage))
        .expect("settle above estimate");
    assert_eq!(world.a.used(), 9);
    for permit in [second, third] {
        permit.settle(CallOutcome::Failed).expect("release unsent");
    }
    assert_eq!((world.a.used(), world.a.reserved()), (9, 0));
}

#[test]
fn n10_a_response_lost_after_work_is_charged_its_reservation_once() {
    let world = World::new();
    world.provider.reply_with(Reply::LostAfterWork);
    let lost = block_on(world.a.admission.call(
        &world.gated_a,
        RunCall {
            selector: None,
            request: &request(SMALL),
            offer: &offer(SMALL),
        },
    ));
    assert!(matches!(
        lost,
        Err(RunCallError::Failed {
            settlement: None,
            ..
        })
    ));
    assert_eq!(world.provider.sent().len(), 1, "the fake recorded the work");
    assert_eq!((world.a.used(), world.a.reserved()), (6, 0));

    // A completion settles once: settling takes the permit, and the lease
    // left behind cannot start another call.
    world.provider.reply_with(Reply::Usage {
        input: 3,
        output: 1,
    });
    let permit = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("permit");
    let lease = permit.lease().clone();
    let response = block_on(world.gated_a.generate(request(SMALL), &lease)).expect("answer");
    permit
        .settle(CallOutcome::Answered(&response.usage))
        .expect("settle");
    assert!(block_on(world.gated_a.generate(request(SMALL), &lease)).is_err());
    assert_eq!((world.a.used(), world.a.reserved()), (10, 0));
}

#[test]
fn n12_the_run_cannot_edit_its_own_declaration() {
    let world = World::new();
    let widened = RunDeclaration::declared(BudgetLine {
        limit_units: 1_000,
        ..line()
    })
    .with_teachers(teachers(&[SMALL, LARGE], &host_aliases()));
    let before = world.before();
    assert_eq!(
        world.a.admission.revise(DeclarationEditor::Run, widened),
        Err(RunDenied::DeclarationEditRefused)
    );
    world.assert_refused_cleanly(&before);
    assert_eq!(world.a.admission.revision(), 1);
    assert_eq!(world.a.admission.read().limit_units, 20);
    assert!(admit(&world.a, None, &request(LARGE), &offer(LARGE)).is_err());
}

// ---------------------------------------------------------------------------
// Positive controls
// ---------------------------------------------------------------------------

#[test]
fn p1_the_declared_teacher_answers_and_settles_its_usage_once() {
    let world = World::new();
    let call = request(SMALL);
    let response = block_on(world.a.admission.call(
        &world.gated_a,
        RunCall {
            selector: Some("teacher-small"),
            request: &call,
            offer: &offer(SMALL),
        },
    ))
    .expect("declared teacher");
    assert_eq!(response.usage.input.total + response.usage.output.total, 4);
    assert_eq!((world.a.used(), world.a.reserved()), (4, 0));

    let sent = world.provider.sent();
    assert_eq!(sent.len(), 1);
    let digest = call.canonical_hash_hex().expect("digest");
    assert_eq!(sent[0].request_digest, digest);

    let report = world.a.admission.teacher_report();
    assert_eq!(report.declared, vec![id(SMALL)]);
    assert_eq!(
        report.called,
        vec![CalledTeacher {
            model: id(SMALL),
            served_model: Some(SMALL.to_owned()),
            request_digest: digest,
            lease: sent[0].lease.clone(),
            settled_units: Some(4),
        }]
    );
    let rows = world.a.receipts.rows();
    let RunEvent::Admitted(facts) = &rows[0].event else {
        panic!("first row is the admission: {rows:?}");
    };
    assert_eq!(facts.teacher_target.as_deref(), Some("seat/decision@local"));
    assert_eq!(
        facts.purpose.as_deref(),
        Some("fine-tune the vault's decision seat")
    );
    assert_eq!(facts.catalog_revision.as_deref(), Some("catalog-7"));
    assert!(facts.rules_enforced);
    assert!(matches!(
        rows[2].event,
        RunEvent::Settled {
            units: 4,
            error: None,
            ..
        }
    ));
    assert_no_key(&world.a.receipts);
}

#[test]
fn p2_a_paid_search_with_the_runs_permit_settles_its_cost() {
    let world = World::new();
    let permit = world.a.admission.admit_paid(&search(), 1).expect("search");
    assert_eq!(permit.facts().reserved_units, 3);
    let lease = permit.lease().clone();
    let used = paid_call(
        &world.a.admission,
        &lease,
        &search(),
        &world.resolver,
        &world.endpoint,
        1,
    )
    .expect("admitted search");
    permit.settle(CallOutcome::Used(used)).expect("settle");
    assert_eq!(
        (world.endpoint.sends(), world.endpoint.billable_units()),
        (1, 1)
    );
    assert_eq!(world.resolver.resolved(), 1);
    assert_eq!((world.a.used(), world.a.reserved()), (3, 0));
    // The same permit does not buy a second search.
    assert_eq!(
        paid_call(
            &world.a.admission,
            &lease,
            &search(),
            &world.resolver,
            &world.endpoint,
            1
        ),
        Err(RunDenied::Dispatch {
            refused: DispatchRefused::Closed
        })
    );
    assert_no_key(&world.a.receipts);
}

#[test]
fn p3_the_owner_widens_the_declaration_and_the_run_calls_the_new_teacher() {
    let world = World::new();
    let widened = RunDeclaration::declared(line())
        .with_teachers(teachers(&[SMALL, LARGE], &host_aliases()))
        .with_connector("search");
    assert_eq!(
        world.a.admission.revise(DeclarationEditor::Owner, widened),
        Ok(2)
    );
    let response = block_on(world.a.admission.call(
        &world.gated_a,
        RunCall {
            selector: Some("teacher-other"),
            request: &request(LARGE),
            offer: &offer(LARGE),
        },
    ));
    assert!(response.is_ok());
    assert!(world.a.receipts.rows().iter().any(|row| row.revision == 2
        && row.event
            == RunEvent::Revised {
                editor: DeclarationEditor::Owner,
                from: 1
            }));
}

#[test]
fn p4_a_real_local_call_stays_unmetered() {
    let world = World::with(RunDeclaration::declared(line()));
    let local = local_offer();
    let gated = world.a.admission.gate(world.provider.clone(), &local.route);
    let mut call = request("local/small@v1");
    call.envelope.locality = ModelLocality::OnDevice;
    block_on(world.a.admission.call(
        &gated,
        RunCall {
            selector: None,
            request: &call,
            offer: &local,
        },
    ))
    .expect("local call");
    assert_eq!(world.provider.sent().len(), 1);
    assert_eq!((world.a.used(), world.a.reserved()), (0, 0));
}

// ---------------------------------------------------------------------------
// The host's inputs, key rungs and units (CROSS-ARCH-0023 C1, C5; ARCH-0069)
// ---------------------------------------------------------------------------

fn micro_usd() -> LeaseUnit {
    LeaseUnit::new("provider_cost_micro_usd").expect("unit")
}

fn host_offer(model: &str) -> OfferBinding {
    OfferBinding {
        payer: Payer::Host,
        rates: vec![
            UnitRate {
                unit: units(),
                per: 1,
                cost: 1,
            },
            UnitRate {
                unit: micro_usd(),
                per: 1,
                cost: 2,
            },
        ],
        ..offer(model)
    }
}

fn granted(units: u64, generation: u64) -> Arc<HostAccount> {
    let account = HostAccount::new();
    account
        .grant(Allocation {
            reference: AllocationRef {
                id: "alloc-1".to_owned(),
                generation,
            },
            units,
            unit: micro_usd(),
        })
        .expect("grant");
    account
}

#[test]
fn a_host_paid_permit_binds_the_payer_catalog_and_allocation_and_settles_both_lines() {
    let account = granted(100, 1);
    let provider = FakeProvider::new();
    let run = Run::start(declaration(), Some(account.clone()));
    let gated = run.admission.gate(provider, &model_route());
    let permit = admit(&run, None, &request(SMALL), &host_offer(SMALL)).expect("host-paid");
    let facts = permit.facts().clone();
    assert_eq!(facts.payer, Payer::Host);
    assert_eq!(facts.catalog_revision.as_deref(), Some("catalog-7"));
    assert_eq!(
        facts.allocation,
        Some(AllocationRef {
            id: "alloc-1".to_owned(),
            generation: 1
        })
    );
    assert_eq!(facts.unit, units());
    assert_eq!(facts.allocation_reserved_units, Some(12));
    let response = block_on(gated.generate(request(SMALL), permit.lease())).expect("answer");
    permit
        .settle(CallOutcome::Answered(&response.usage))
        .expect("settle");
    assert!(run.receipts.rows().iter().any(|row| matches!(
        row.event,
        RunEvent::Settled {
            units: 4,
            allocation_units: Some(8),
            ..
        }
    )));
    // A consumed generation cannot come back.
    assert_eq!(
        account.grant(Allocation {
            reference: AllocationRef {
                id: "alloc-1".to_owned(),
                generation: 1
            },
            units: 100,
            unit: micro_usd(),
        }),
        Err(AllocationGrantError::StaleGeneration)
    );
}

#[test]
fn a_host_check_holds_new_host_paid_spend_and_nothing_else() {
    // Room for one host-paid call (12 of 20), not two.
    let account = granted(20, 1);
    let with_local = RunDeclaration::declared(line())
        .with_teachers(teachers(&[SMALL, "local/small@v1"], &host_aliases()));
    let run = Run::start(with_local, Some(account.clone()));
    let admitted = admit(&run, None, &request(SMALL), &host_offer(SMALL)).expect("first fits");
    assert_eq!(
        admit(&run, None, &request(SMALL), &host_offer(SMALL)).expect_err("spent"),
        RunDenied::AllocationExhausted
    );
    account.refuse_fresh(AllocationRefusal::HostCheck);
    assert_eq!(
        account.status().fresh_allocation_refused,
        Some(AllocationRefusal::HostCheck)
    );
    let before = (run.used(), run.reserved());
    assert_eq!(
        admit(&run, None, &request(SMALL), &host_offer(SMALL)).expect_err("held"),
        RunDenied::AllocationRefused {
            reason: AllocationRefusal::HostCheck
        }
    );
    assert_eq!((run.used(), run.reserved()), before);
    // The customer's own key and the local model go on.
    admit(&run, None, &request(SMALL), &offer(SMALL)).expect("BYOK continues");
    let mut local = request("local/small@v1");
    local.envelope.locality = ModelLocality::OnDevice;
    admit(&run, None, &local, &local_offer()).expect("local continues");
    // The admitted host-paid call still settles.
    admitted
        .settle(CallOutcome::Failed)
        .expect("admitted work settles");
    // A vault with no allocation delivered and a hold reads as the hold.
    let empty = HostAccount::new();
    let held = Run::start(declaration(), Some(empty.clone()));
    assert_eq!(
        admit(&held, None, &request(SMALL), &host_offer(SMALL)).expect_err("none delivered"),
        RunDenied::NoAllocation
    );
    empty.refuse_fresh(AllocationRefusal::HostCheck);
    assert_eq!(
        admit(&held, None, &request(SMALL), &host_offer(SMALL)).expect_err("held"),
        RunDenied::AllocationRefused {
            reason: AllocationRefusal::HostCheck
        }
    );
}

#[test]
fn a_declared_run_keeps_paid_keys_at_t0_unless_the_owner_says_otherwise() {
    let mut t1 = offer(SMALL);
    t1.custody = KeyCustody::T1;
    let world = World::new();
    let before = world.before();
    assert_eq!(
        admit(&world.a, None, &request(SMALL), &t1).expect_err("T1 key"),
        RunDenied::KeyAtT1
    );
    world.assert_refused_cleanly(&before);

    let overridden = Run::start(declaration().with_custody_override(t1.offer.clone()), None);
    let permit = admit(&overridden, None, &request(SMALL), &t1).expect("owner override");
    assert!(!permit.facts().rules_enforced);

    let mut seat = t1.clone();
    seat.payer = Payer::CustomerSeat;
    let permit = admit(&world.a, None, &request(SMALL), &seat).expect("BYO seat stays T1");
    assert!(!permit.facts().rules_enforced);

    let undeclared = Run::start(RunDeclaration::undeclared(line()), None);
    let permit = admit(&undeclared, None, &request(SMALL), &t1).expect("undeclared run");
    assert!(permit.facts().rules_enforced);
}

#[test]
fn a_run_that_declares_no_teachers_may_use_any_bound_offer() {
    let world = World::with(RunDeclaration::declared(line()));
    for model in [SMALL, LARGE, "fake/teacher-b@v1"] {
        let permit =
            admit(&world.a, None, &request(model), &offer(model)).expect("any bound offer");
        assert_eq!(permit.facts().teacher_target, None);
    }
}

#[test]
fn units_never_mix_without_a_rate_and_undeclared_connectors_are_refused() {
    let world = World::new();
    let mut no_rate = offer(SMALL);
    no_rate.rates.clear();
    let before = world.before();
    assert_eq!(
        admit(&world.a, None, &request(SMALL), &no_rate).expect_err("tokens into units"),
        RunDenied::UnitMismatch {
            from: LeaseUnit::tokens(),
            to: units()
        }
    );
    world.assert_refused_cleanly(&before);
    let before = world.before();
    let gpu = PaidConnector {
        connector: "gpu".to_owned(),
        ..search()
    };
    assert_eq!(
        world
            .a
            .admission
            .admit_paid(&gpu, 1)
            .expect_err("undeclared"),
        RunDenied::UndeclaredConnector {
            connector: "gpu".to_owned()
        }
    );
    world.assert_refused_cleanly(&before);
}

#[test]
fn a_teacher_declaration_needs_its_target_and_purpose() {
    let models = [id(SMALL)];
    assert_eq!(
        DeclaredTeachers::new(models.clone(), host_aliases(), " ", "fine-tune"),
        Err(DeclarationError::MissingTarget)
    );
    assert_eq!(
        DeclaredTeachers::new(models, host_aliases(), "seat/decision@local", ""),
        Err(DeclarationError::MissingPurpose)
    );
}

#[test]
fn a_streamed_call_starts_its_permit_once_and_receipts_its_digest() {
    use futures_core::Stream;
    let world = World::new();
    let permit = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("permit");
    let call = request(SMALL);
    let mut stream = world
        .gated_a
        .stream(call.clone(), permit.lease())
        .expect("stream starts");
    let mut usage = None;
    loop {
        let next = block_on(std::future::poll_fn(|cx| {
            std::pin::Pin::new(&mut stream).poll_next(cx)
        }));
        match next {
            Some(Ok(LlmStreamEvent::Done { usage: done, .. })) => usage = Some(done),
            Some(Ok(_)) => {}
            Some(Err(error)) => panic!("stream failed: {error:?}"),
            None => break,
        }
    }
    drop(stream);
    assert!(
        world
            .gated_a
            .stream(request(SMALL), permit.lease())
            .is_err()
    );
    permit
        .settle(CallOutcome::Answered(&usage.expect("terminal")))
        .expect("settle");
    let report = world.a.admission.teacher_report();
    assert_eq!(report.called.len(), 1);
    assert_eq!(
        report.called[0].request_digest,
        call.canonical_hash_hex().expect("digest")
    );
    assert_eq!(world.provider.sent().len(), 1);
}

#[test]
fn an_answer_pays_a_reservation_for_each_failed_rung_and_never_zero() {
    let world = World::new();
    let permit = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("permit");
    world
        .generate(&world.gated_a, request(SMALL), &permit)
        .expect("answer");
    let mut usage = crate::llm::LlmUsage::zero();
    usage.raw_provider = serde_json::json!({ FAILED_RUNGS_KEY: 1 });
    permit
        .settle(CallOutcome::Answered(&usage))
        .expect("settle");
    // No usage reported: the 6-unit reservation, plus 6 for the failed rung.
    assert_eq!(world.a.used(), 12);
}

// ---------------------------------------------------------------------------
// A permit's lifetime, the gate's edge and the receipts' facts
// ---------------------------------------------------------------------------

#[test]
fn an_unsettled_permit_settles_when_dropped() {
    let account = granted(100, 1);
    let provider = FakeProvider::new();
    let run = Run::start(declaration(), Some(account.clone()));
    let gated = run.admission.gate(provider.clone(), &model_route());
    let allocation = || {
        let read = account.live().0.expect("live allocation").meter.read();
        (read.used_units, read.reserved_units)
    };
    // Dropped before it starts: both reservations come back.
    let unsent = admit(&run, None, &request(SMALL), &host_offer(SMALL)).expect("permit");
    assert_eq!((run.reserved(), allocation()), (6, (0, 12)));
    drop(unsent);
    assert_eq!((run.used(), run.reserved(), allocation()), (0, 0, (0, 0)));
    // Dropped after it went out: both lines keep their reservations as spend.
    let sent = admit(&run, None, &request(SMALL), &host_offer(SMALL)).expect("permit");
    block_on(gated.generate(request(SMALL), sent.lease())).expect("answer");
    drop(sent);
    assert_eq!((run.used(), run.reserved(), allocation()), (6, 0, (12, 0)));
    assert_eq!(provider.sent().len(), 1);
    let settled = run
        .receipts
        .rows()
        .into_iter()
        .filter(|row| matches!(row.event, RunEvent::Settled { .. }))
        .count();
    assert_eq!(settled, 2);
}

#[test]
fn a_cancelled_call_settles_its_permit_and_writes_its_dispatch_receipt() {
    let world = World::new();
    world.provider.reply_with(Reply::Hang);
    let (small, small_offer) = (request(SMALL), offer(SMALL));
    let mut call = Box::pin(world.a.admission.call(
        &world.gated_a,
        RunCall {
            selector: None,
            request: &small,
            offer: &small_offer,
        },
    ));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(call.as_mut().poll(&mut cx).is_pending());
    assert_eq!((world.a.used(), world.a.reserved()), (0, 6));
    drop(call);
    assert_eq!(world.provider.sent().len(), 1);
    assert_eq!((world.a.used(), world.a.reserved()), (6, 0));
    let rows = world.a.receipts.rows();
    assert!(rows.iter().any(|row| matches!(
        row.event,
        RunEvent::Dispatched {
            answered: false,
            ..
        }
    )));
    assert!(
        rows.iter()
            .any(|row| matches!(row.event, RunEvent::Settled { units: 6, .. }))
    );
}

#[test]
fn a_call_its_route_cannot_serve_is_refused_before_its_permit_starts() {
    let world = World::new();
    world.provider.refuse(LlmCapability::Streaming);
    let permit = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("permit");
    let before = world.before();
    let refused = world
        .gated_a
        .stream(request(SMALL), permit.lease())
        .err()
        .expect("refused");
    assert!(matches!(
        refused,
        LlmError::Fatal(FatalLlmError::Unsupported(_))
    ));
    assert_eq!(world.provider.sent().len(), before.sends);
    assert_eq!(world.a.used(), before.used);
    assert!(world.a.receipts.rows().iter().any(|row| matches!(
        &row.event,
        RunEvent::Denied {
            reason: RunDenied::Unsupported {
                capability: LlmCapability::Streaming
            },
            ..
        }
    )));
    // The permit is unused: the call goes out once it fits the route.
    let response =
        block_on(world.gated_a.generate(request(SMALL), permit.lease())).expect("answer");
    permit
        .settle(CallOutcome::Answered(&response.usage))
        .expect("settle");
    assert_eq!((world.a.used(), world.a.reserved()), (4, 0));
}

#[test]
fn a_route_that_could_carry_a_credential_into_a_receipt_is_refused() {
    for origin in [
        "https://user:sk-secret@model.test",
        "https://model.test/v1?key=sk-secret",
        "https://model.test/#sk-secret",
        "https://model.test/ v1",
        "",
    ] {
        assert_eq!(
            OfferRoute::new("fake", origin),
            Err(OfferRouteError::Origin),
            "{origin}"
        );
    }
    for adapter in ["", "fake@other", "fake\n"] {
        assert_eq!(
            OfferRoute::new(adapter, MODEL_ORIGIN),
            Err(OfferRouteError::Adapter),
            "{adapter:?}"
        );
    }
    let route = OfferRoute::new("fake", "https://model.test:443/v1").expect("a path is fine");
    assert_eq!(
        (route.adapter(), route.origin()),
        ("fake", "https://model.test:443/v1")
    );
}

#[test]
fn a_large_native_amount_converts_whole_and_is_never_priced_low() {
    let half = vec![UnitRate {
        unit: units(),
        per: 2,
        cost: 1,
    }];
    let convert = super::host::convert;
    assert_eq!(
        convert(u128::from(u64::MAX) * 2, &gpu_seconds(), &units(), &half),
        Some(u64::MAX)
    );
    assert_eq!(convert(u128::MAX, &units(), &units(), &[]), Some(u64::MAX));
    let zero_per = UnitRate {
        per: 0,
        ..half[0].clone()
    };
    assert_eq!(convert(7, &gpu_seconds(), &units(), &[zero_per]), None);
    // A connector call that big is refused, never admitted at half its price.
    let gpu = PaidConnector {
        connector: "gpu".to_owned(),
        unit_cost: 2,
        cost_unit: gpu_seconds(),
        rates: half,
        ..search()
    };
    let run = Run::start(RunDeclaration::declared(line()).with_connector("gpu"), None);
    assert_eq!(
        run.admission
            .admit_paid(&gpu, u64::MAX)
            .expect_err("too big"),
        RunDenied::Budget {
            denied: BudgetDenied::Exhausted
        }
    );
    assert_eq!((run.used(), run.reserved()), (0, 0));
}

#[test]
fn a_calls_receipts_carry_the_revision_it_was_admitted_under() {
    let world = World::new();
    let permit = admit(&world.a, None, &request(SMALL), &offer(SMALL)).expect("permit");
    let widened = RunDeclaration::declared(line())
        .with_teachers(teachers(&[SMALL, LARGE], &host_aliases()))
        .with_connector("search");
    assert_eq!(
        world.a.admission.revise(DeclarationEditor::Owner, widened),
        Ok(2)
    );
    world
        .generate(&world.gated_a, request(SMALL), &permit)
        .expect("answer");
    permit
        .settle(CallOutcome::Answered(&crate::llm::LlmUsage::zero()))
        .expect("settle");
    let revisions: Vec<u32> = world
        .a
        .receipts
        .rows()
        .into_iter()
        .filter(|row| {
            matches!(
                row.event,
                RunEvent::Admitted(_) | RunEvent::Dispatched { .. } | RunEvent::Settled { .. }
            )
        })
        .map(|row| row.revision)
        .collect();
    assert_eq!(revisions, vec![1, 1, 1]);
}

// ---------------------------------------------------------------------------
// C2: the stop at a paid job's declared maximum
// ---------------------------------------------------------------------------

fn gpu_seconds() -> LeaseUnit {
    LeaseUnit::new("gpu_seconds").expect("unit")
}

fn maximum(units: u64) -> DeclaredMaximum {
    DeclaredMaximum {
        units,
        unit: gpu_seconds(),
    }
}

const SHOWN: Option<MaximumShown> = Some(MaximumShown { at_ms: 1 });

#[test]
fn a_job_starts_only_under_a_maximum_the_customer_saw() {
    assert_eq!(
        JobMaximum::start("job", maximum(100), None),
        Err(JobStartRefused::MaximumNotShown)
    );
    assert_eq!(
        JobMaximum::start("job", maximum(0), SHOWN),
        Err(JobStartRefused::ZeroMaximum)
    );
}

#[test]
fn a_job_stops_at_its_maximum_only_after_the_warning_reached_the_customer_and_a_checkpoint() {
    let mut job = JobMaximum::start("job", maximum(100), SHOWN).expect("start");
    assert_eq!(job.record_usage(50), vec![]);
    assert!(!job.confirm_warning(), "no warning is due at 50");
    job.checkpoint(CheckpointRef("too-early".to_owned()));
    assert_eq!(
        job.record_usage(95),
        vec![JobSignal::Warning95 {
            used_units: 95,
            maximum_units: 100
        }]
    );
    assert_eq!(job.stop_at_maximum(), Err(StopRefused::NotAtMaximum));
    // Undelivered, the warning comes back at the next record, and neither a
    // stop nor a checkpoint counts until it reaches the customer.
    job.checkpoint(CheckpointRef("undelivered".to_owned()));
    assert_eq!(
        job.record_usage(100),
        vec![
            JobSignal::Warning95 {
                used_units: 100,
                maximum_units: 100
            },
            JobSignal::AtMaximum
        ]
    );
    assert_eq!(job.stop_at_maximum(), Err(StopRefused::NoWarning));
    assert!(job.confirm_warning());
    assert_eq!(job.record_usage(100), vec![JobSignal::AtMaximum]);
    assert_eq!(job.stop_at_maximum(), Err(StopRefused::NoCheckpoint));
    job.checkpoint(CheckpointRef("ckpt-2".to_owned()));
    let stop = job.stop_at_maximum().expect("stop");
    assert_eq!(stop.notice.checkpoint, CheckpointRef("ckpt-2".to_owned()));
    assert_eq!(stop.notice.used_units, 100);
    assert_eq!(stop.notice.maximum, maximum(100));
    assert_eq!(job.stop_at_maximum(), Err(StopRefused::Stopped));
    // A checkpoint that lands after the stop leaves the offer's in place.
    job.checkpoint(CheckpointRef("late".to_owned()));
    assert_eq!(
        job.resume(&stop.resume, maximum(200), SHOWN),
        Ok(CheckpointRef("ckpt-2".to_owned()))
    );
}

#[test]
fn a_job_that_jumps_past_its_maximum_warns_before_it_can_stop() {
    let mut job = JobMaximum::start("job", maximum(100), SHOWN).expect("start");
    assert_eq!(
        job.record_usage(120),
        vec![
            JobSignal::Warning95 {
                used_units: 120,
                maximum_units: 100
            },
            JobSignal::AtMaximum
        ]
    );
    job.checkpoint(CheckpointRef("before-warning".to_owned()));
    assert_eq!(job.stop_at_maximum(), Err(StopRefused::NoWarning));
    assert!(job.confirm_warning());
    assert_eq!(job.stop_at_maximum(), Err(StopRefused::NoCheckpoint));
    job.checkpoint(CheckpointRef("ckpt".to_owned()));
    assert!(job.stop_at_maximum().is_ok());
}

#[test]
fn a_stopped_job_resumes_in_one_step_from_its_checkpoint_on_a_fresh_admission() {
    let gpu = PaidConnector {
        connector: "gpu".to_owned(),
        unit_cost: 1,
        cost_unit: gpu_seconds(),
        rates: vec![UnitRate {
            unit: units(),
            per: 10,
            cost: 1,
        }],
        ..search()
    };
    let run = Run::start(
        RunDeclaration::declared(BudgetLine {
            limit_units: 30,
            ..line()
        })
        .with_connector("gpu"),
        None,
    );
    // The job reserves its whole maximum: 100 GPU seconds, 10 units.
    let chunk = run.admission.admit_paid(&gpu, 100).expect("whole maximum");
    assert_eq!(chunk.facts().reserved_units, 10);
    let mut job = JobMaximum::start("job", maximum(100), SHOWN).expect("start");
    job.record_usage(100);
    assert!(job.confirm_warning());
    job.checkpoint(CheckpointRef("ckpt".to_owned()));
    let stop = job.stop_at_maximum().expect("stop");
    run.admission
        .dispatch_paid(chunk.lease(), &gpu)
        .expect("chunk ran");
    let chunk_lease = chunk.lease().id().to_owned();
    chunk
        .settle(CallOutcome::Used(100))
        .expect("settle the chunk");

    let mut stale = stop.resume.clone();
    stale.job = "another".to_owned();
    assert_eq!(
        job.resume(&stale, maximum(200), SHOWN),
        Err(ResumeRefused::StaleOffer)
    );
    assert_eq!(
        job.resume(&stop.resume, maximum(100), SHOWN),
        Err(ResumeRefused::MaximumNotRaised)
    );
    assert_eq!(
        job.resume(&stop.resume, maximum(200), None),
        Err(ResumeRefused::MaximumNotRaised)
    );
    assert_eq!(
        job.resume(&stop.resume, maximum(200), SHOWN),
        Ok(CheckpointRef("ckpt".to_owned()))
    );
    assert_eq!(
        job.resume(&stop.resume, maximum(300), SHOWN),
        Err(ResumeRefused::NotStopped)
    );
    // The next chunk takes its own admission.
    let next = run.admission.admit_paid(&gpu, 100).expect("next chunk");
    assert_ne!(next.lease().id(), chunk_lease);
    assert_eq!((run.used(), run.reserved()), (10, 10));
}
