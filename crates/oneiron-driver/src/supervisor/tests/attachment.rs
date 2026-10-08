//! The generic pass-attachment seam: asked after the pass meter, refusal is
//! pre-admission, and a linked host signal stops the supervisor both ways.
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::super::attachment::{
    AttachedPassFuture, LinkedShutdown, PassAttachment, PassAttachmentSource, WakePassFuture,
};
use super::super::pass::{PassRunError, run_one_pass};
use super::super::run::{WakeSupervisor, WakeSupervisorReport};
use super::*;
use crate::tick::{HintSignal, PushTick};
use oneiron::llm::{BudgetLease, FatalLlmError, LlmGenerateFuture, LlmRequest, LlmStreamResult};
use oneiron::{
    DreamerClaimAuthoringStrategy, LlmBackend, ModelId, WakeCancellation, WriteActor,
    llm::HostInferenceBinding,
};
use tokio::sync::watch;

struct RefusingBackend(Arc<AtomicUsize>);

impl LlmBackend for RefusingBackend {
    fn generate<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(FatalLlmError::InvalidRequest.into()) })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(FatalLlmError::InvalidRequest.into())
    }
}

#[derive(Clone, Copy)]
enum Answer {
    Refuse,
    Nothing,
    Serve,
    ServeThenFail,
}

#[derive(Default)]
struct Observed {
    guard_ids: Vec<String>,
    backends: Vec<Arc<dyn LlmBackend>>,
    pass_results: Vec<bool>,
}

struct Source {
    answer: Answer,
    observed: Arc<Mutex<Observed>>,
    shutdown: Option<Arc<dyn LinkedShutdown>>,
}

struct Attached {
    fail: bool,
    observed: Arc<Mutex<Observed>>,
}

impl PassAttachment for Attached {
    fn serve<'p>(self: Box<Self>, pass: WakePassFuture<'p>) -> AttachedPassFuture<'p> {
        Box::pin(async move {
            let result = pass.await;
            self.observed
                .lock()
                .unwrap()
                .pass_results
                .push(result.is_ok());
            let served = if self.fail {
                Err("attached work broke".to_owned())
            } else {
                Ok(())
            };
            (result, served)
        })
    }
}

impl PassAttachmentSource for Source {
    fn attach(
        &self,
        _vault: &Vault,
        backend: &Arc<dyn LlmBackend>,
        guard: &BudgetGuard,
    ) -> Result<Option<Box<dyn PassAttachment>>> {
        let mut observed = self.observed.lock().unwrap();
        observed.guard_ids.push(guard.read().attempt_id);
        observed.backends.push(Arc::clone(backend));
        drop(observed);
        match self.answer {
            Answer::Refuse => Err(oneiron::Error::InvalidConfig("attachment refused".into())),
            Answer::Nothing => Ok(None),
            Answer::Serve | Answer::ServeThenFail => Ok(Some(Box::new(Attached {
                fail: matches!(self.answer, Answer::ServeThenFail),
                observed: Arc::clone(&self.observed),
            }))),
        }
    }

    fn linked_shutdown(&self) -> Option<Arc<dyn LinkedShutdown>> {
        self.shutdown.clone()
    }
}

struct TestLinked(watch::Sender<bool>);

impl LinkedShutdown for TestLinked {
    fn trigger(&self) {
        self.0.send_replace(true);
    }

    fn is_triggered(&self) -> bool {
        *self.0.borrow()
    }

    fn triggered(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let mut rx = self.0.subscribe();
        Box::pin(async move {
            let _ = rx.wait_for(|stopped| *stopped).await;
        })
    }
}

fn factory(
    vault: &Vault,
    answer: Answer,
    shutdown: Option<Arc<dyn LinkedShutdown>>,
) -> (
    ConsolidationExecutorFactory,
    Arc<Mutex<Observed>>,
    Arc<AtomicUsize>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Observed::default()));
    let model = ModelId::new("test/model@v1").unwrap();
    let factory = ConsolidationExecutorFactory::new(
        Arc::new(RefusingBackend(Arc::clone(&calls))),
        DreamerClaimAuthoringStrategy::SinglePass,
        vault.dreamer_authority().unwrap(),
        model.clone(),
        HostInferenceBinding::Advertised {
            model,
            locality: oneiron::ModelLocality::OwnServer,
        },
        None,
        Box::new(UnusedSink),
    )
    .with_pass_attachment(Box::new(Source {
        answer,
        observed: Arc::clone(&observed),
        shutdown,
    }));
    (factory, observed, calls)
}

async fn one_pass(
    vault: &Vault,
    factory: &mut ConsolidationExecutorFactory,
    budget_id: &str,
) -> std::result::Result<oneiron::WakePassReport, PassRunError> {
    let clock: NowSeconds = Arc::new(|| 10);
    run_one_pass(
        vault,
        &test_config(),
        budget_id,
        &clock,
        factory,
        &Tick::Hint(HintSignal::default()),
        &WakeCancellation::new(),
    )
    .await
}

#[tokio::test]
async fn refused_attachment_stops_the_pass_before_admission() {
    let (_dir, vault) = open_vault();
    let (mut factory, observed, calls) = factory(&vault, Answer::Refuse, None);
    let result = one_pass(&vault, &mut factory, "refused:p0").await;
    assert!(matches!(
        result,
        Err(PassRunError::PreAdmission(oneiron::Error::InvalidConfig(_)))
    ));
    // Asked with the pass's own meter, then nothing durable was written.
    assert_eq!(observed.lock().unwrap().guard_ids, ["refused:p0"]);
    assert!(
        DreamerRunnerStore::new(&vault)
            .budget("refused:p0")
            .unwrap()
            .is_none()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn absent_attachment_runs_the_plain_pass() {
    let (_dir, vault) = open_vault();
    let (mut factory, observed, _calls) = factory(&vault, Answer::Nothing, None);
    assert!(one_pass(&vault, &mut factory, "plain:p0").await.is_ok());
    assert!(observed.lock().unwrap().pass_results.is_empty());
}

#[tokio::test]
async fn attachment_drives_the_pass_with_the_factory_backend() {
    let (_dir, vault) = open_vault();
    let (mut factory, observed, _calls) = factory(&vault, Answer::Serve, None);
    assert!(one_pass(&vault, &mut factory, "served:p0").await.is_ok());
    let observed = observed.lock().unwrap();
    assert_eq!(observed.pass_results, [true]);
    assert!(Arc::ptr_eq(&observed.backends[0], factory.backend()));
}

#[tokio::test]
async fn attachment_failure_fails_the_pass_it_served() {
    let (_dir, vault) = open_vault();
    let (mut factory, observed, _calls) = factory(&vault, Answer::ServeThenFail, None);
    let result = one_pass(&vault, &mut factory, "broken:p0").await;
    assert!(matches!(
        result,
        Err(PassRunError::Failed(oneiron::Error::InvalidConfig(_)))
    ));
    assert_eq!(observed.lock().unwrap().pass_results, [true]);
}

#[tokio::test]
async fn linked_shutdown_and_supervisor_handle_stop_each_other() {
    for host_first in [true, false] {
        let (_dir, vault) = open_vault();
        let linked = Arc::new(TestLinked(watch::channel(false).0));
        let shared: Arc<dyn LinkedShutdown> = linked.clone();
        let (factory, _observed, _calls) = factory(&vault, Answer::Nothing, Some(shared));
        let (ticks, _wake, _hint) = PushTick::channel(1_000);
        let supervisor = WakeSupervisor::new(&vault, ticks, factory, test_config());
        let handle = supervisor.shutdown_handle();
        let stopped = AtomicBool::new(false);
        let (report, ()) = tokio::join!(supervisor.run(), async {
            if host_first {
                linked.trigger();
            } else {
                handle.shutdown();
            }
            stopped.store(true, Ordering::SeqCst);
        });
        assert!(stopped.load(Ordering::SeqCst));
        assert_eq!(report, WakeSupervisorReport::default());
        assert!(
            linked.is_triggered(),
            "the handle trips the host signal too"
        );
    }
}

#[test]
fn a_factory_without_a_source_attaches_nothing() {
    let (_dir, vault) = open_vault();
    let factory = ConsolidationExecutorFactory::new(
        Arc::new(RefusingBackend(Arc::new(AtomicUsize::new(0)))),
        DreamerClaimAuthoringStrategy::SinglePass,
        WriteActor::new(
            seed_actor(&vault, 21, oneiron::registry::ENTITY_TYPE_PERSON),
            oneiron::edge::EdgeActorClass::Agent,
        ),
        ModelId::new("test/model@v1").unwrap(),
        HostInferenceBinding::Registered,
        None,
        Box::new(UnusedSink),
    );
    let guard = BudgetGuard::new("bare", 10, oneiron::BudgetExhaustionPolicy::Suspend);
    assert!(factory.pass_attachment(&vault, &guard).unwrap().is_none());
    assert!(factory.linked_shutdown().is_none());
}
