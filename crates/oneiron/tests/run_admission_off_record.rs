//! Census row L5-25 (DEC-0005 world privacy, fix 12; Astra unbuilt-bp1b-p02
//! delta, Finding 1): a call that serves a caller whose off-record session
//! keeps no record names no source rows, so no receipt of it names those
//! rows or their worlds. The host marks the call's handle
//! `RunAdmission::off_record` where the request arrives. The mark holds
//! through every later `RunAdmission::sourced`, so code deeper in the call
//! (a decision seat, a reranker) that names its evidence rows still names
//! none, and the receipt sink is never asked for their worlds.
//!
//! `cargo test --locked -p oneiron --all-features --test
//! run_admission_off_record`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferRoute, PaidConnector, Payer,
    RunAdmission, RunDeclaration, RunEvent, RunReceipt, RunReceiptSink,
};
use oneiron::{EntityId, llm};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// What the run's line reserves at least, in tokens.
const CALL_RESERVE: u64 = 500;

/// A host sink that reads every named source row as in `worlds`, counts how
/// often it was asked, and keeps its rows in order.
struct CountingReceipts {
    worlds: Vec<EntityId>,
    asked: AtomicUsize,
    rows: MemoryReceipts,
}

impl RunReceiptSink for CountingReceipts {
    fn record(&self, receipt: RunReceipt) {
        self.rows.record(receipt);
    }

    fn source_worlds(&self, rows: &[EntityId]) -> Option<Vec<EntityId>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        (!rows.is_empty()).then(|| self.worlds.clone())
    }
}

fn sink_in(world: EntityId) -> Arc<CountingReceipts> {
    Arc::new(CountingReceipts {
        worlds: vec![world],
        asked: AtomicUsize::new(0),
        rows: MemoryReceipts::default(),
    })
}

fn run_over(receipts: &Arc<CountingReceipts>) -> RunAdmission {
    RunAdmission::new(
        format!("off-record:{}", EntityId::now().to_hex()),
        RunDeclaration::undeclared(BudgetLine {
            limit_units: 10_000,
            reserve_units: CALL_RESERVE,
            unit: LeaseUnit::tokens(),
        }),
        None,
        receipts.clone(),
    )
}

fn paid_connector() -> TestResult<PaidConnector> {
    Ok(PaidConnector {
        connector: "fixture-search".to_owned(),
        route: OfferRoute::new("fixture-search", "https://search.test:443")?,
        locality: llm::ModelLocality::OwnServer,
        payer: Payer::CustomerKey,
        credential_binding: Some("customer-key-1".to_owned()),
        catalog_revision: None,
        custody: KeyCustody::T0,
        unit_cost: 1,
        cost_unit: LeaseUnit::tokens(),
        rates: Vec::new(),
    })
}

/// Admits one paid call through `handle` and settles it unstarted.
fn admit_once(handle: &RunAdmission) -> TestResult {
    let permit = handle
        .admit_paid(&paid_connector()?, 10)
        .map_err(|denied| format!("paid call refused at admission: {denied:?}"))?;
    drop(permit);
    Ok(())
}

/// Each `Admitted` receipt's source rows and their worlds, in order.
type Sourced = (Option<Vec<EntityId>>, Option<Vec<EntityId>>);

fn admitted_sources(receipts: &CountingReceipts) -> Vec<Sourced> {
    receipts
        .rows
        .rows()
        .into_iter()
        .filter_map(|row| match row.event {
            RunEvent::Admitted(facts) => Some((facts.source_rows, facts.source_worlds)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_sourced_run_names_its_rows_and_their_worlds() -> TestResult {
    let harbor = EntityId::now();
    let row = EntityId::now();
    let receipts = sink_in(harbor);
    admit_once(&run_over(&receipts).sourced(Some(vec![row])))?;

    assert_eq!(
        admitted_sources(&receipts),
        vec![(Some(vec![row]), Some(vec![harbor]))],
        "a call the host sourced names its rows and their worlds",
    );
    assert_eq!(receipts.asked.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn an_off_record_run_names_no_rows_however_it_is_sourced() -> TestResult {
    let harbor = EntityId::now();
    let row = EntityId::now();
    let receipts = sink_in(harbor);
    let run = run_over(&receipts);
    // Marked where the request arrives, before deeper code names its rows,
    // and marked over a handle already sourced.
    admit_once(&run.off_record().sourced(Some(vec![row])))?;
    admit_once(&run.sourced(Some(vec![row])).off_record())?;

    assert_eq!(
        admitted_sources(&receipts),
        vec![(None, None), (None, None)],
        "an off-record call names no source rows and no worlds",
    );
    assert_eq!(
        receipts.asked.load(Ordering::SeqCst),
        0,
        "the sink is never asked for an off-record call's worlds",
    );
    Ok(())
}

#[test]
fn every_handle_made_from_an_off_record_run_stays_unsourced() -> TestResult {
    let harbor = EntityId::now();
    let row = EntityId::now();
    let receipts = sink_in(harbor);
    let marked = run_over(&receipts).off_record();
    let handle = marked
        .initiated_by(Some(EntityId::now()))
        .with_work_context(marked.work_context())
        .sourced(Some(vec![row]));
    assert_eq!(handle.source_rows(), None);
    admit_once(&handle)?;

    assert_eq!(admitted_sources(&receipts), vec![(None, None)]);
    assert_eq!(receipts.asked.load(Ordering::SeqCst), 0);
    Ok(())
}
