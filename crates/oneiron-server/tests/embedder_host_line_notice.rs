//! 0053-EMB on census L1-27 (ARCH-0053 `#embedding-admission-built`; Engine
//! rulings 0053-EMB-MONEY = A, 0053-EMB-EXHAUST-NOTICE = B and
//! 0053-EMB-DUP = A, 15 Nov). A served vault's paid embedding requests spend
//! on the embedder slot's line: the vault's background line, built from the
//! vault's budget policy for its system principal, or the host's own line
//! when it pushed one ("A host may push its own embedding line instead").
//! A request the line refuses is never sent, and the vault's Owners are told
//! once that the line is spent, not once per batch.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use engine_stack::run_on_engine_stack;
use oneiron::inbox::NotificationKind;
use oneiron::llm::BudgetDenied;
use oneiron::llm::run_admission::{MemoryReceipts, RunDenied, RunEvent};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor,
};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::embedding_line::{send_as_remote_rung, with_bound_endpoint_slot};

/// The one text each batch sends.
const TEXT: &str = "a note the background line pays to embed";
/// The producer of a spent background line's owner notice.
const SPENT_LINE_PRODUCER: &str = "budget.background_line";

/// What one batch of [`TEXT`] reserves and settles: its bytes plus the
/// model's eight special tokens.
fn batch_tokens() -> u64 {
    u64::try_from(TEXT.len()).expect("text length") + 8
}

/// A device vault, its embedded owner, and the vault's system principal.
fn vault() -> (tempfile::TempDir, Arc<Vault>, EntityId, EntityId) {
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let system = vault
        .dreamer_authority()
        .expect("the vault's system principal")
        .entity_ref();
    (dir, vault, owner, system)
}

/// The owner's policy pack with one `budget_policy` row: `system` capped at
/// one and a half batches.
fn cap_the_system_principal(vault: &Vault, owner: EntityId, system: EntityId) {
    oneiron::conversation_dag::test_support::put_test_policy_manifest(
        vault,
        WriteActor::new(owner, EdgeActorClass::Human),
        EntityId::now(),
        &serde_json::json!({
            "schema_version": "1.2", "pack_id": "background-line-cap", "pack_version": "v1",
            "min_engine_version": "0.0.0",
            "defaults": {"criticality": "normal", "sensitivity": "normal"},
            "rules": [], "actor_ceilings": [],
            "budget_policy": [{"actor": system.to_hex(), "cap": batch_tokens() * 3 / 2}],
        }),
    )
    .expect("install the owner's budget row");
}

/// A server over `vault`, as serve builds one before it holds an embedder.
fn server(vault: &Arc<Vault>) -> SyncServer {
    SyncServer::new(Arc::clone(vault), SyncServerConfig::default()).expect("sync server")
}

/// Sends `batches` batches of [`TEXT`] as the server's remote rung does,
/// and answers which the door admitted and how many requests went out.
fn send_batches(
    server: &SyncServer,
    receipts: &Arc<MemoryReceipts>,
    batches: usize,
) -> (Vec<bool>, usize) {
    let posted = AtomicUsize::new(0);
    let admitted = (0..batches)
        .map(|_| {
            send_as_remote_rung(server, receipts.clone(), &[TEXT], &mut || {
                posted.fetch_add(1, Ordering::SeqCst);
                Ok::<_, oneiron::Error>(vec![vec![0.0_f32; 4]])
            })
            .is_ok()
        })
        .collect();
    (admitted, posted.load(Ordering::SeqCst))
}

/// The run rows that refused a request because its line was spent.
fn spent_refusals(receipts: &MemoryReceipts) -> usize {
    receipts
        .rows()
        .iter()
        .filter(|row| {
            matches!(
                row.event,
                RunEvent::Denied {
                    reason: RunDenied::Budget {
                        denied: BudgetDenied::Exhausted
                    },
                    ..
                }
            )
        })
        .count()
}

/// The spent-line notices in `owner`'s inbox.
fn spent_line_notices(vault: &Vault, owner: EntityId) -> usize {
    vault
        .memory(owner, EdgeActorClass::Human)
        .inbox_list(None, 100)
        .expect("the owner's inbox")
        .rows
        .iter()
        .filter(|row| {
            row.kind == NotificationKind::Ask && row.source.producer == SPENT_LINE_PRODUCER
        })
        .count()
}

/// Runs `body` on a blocking thread of a runtime on the engine's stack, as
/// serve builds its embedder slot off the runtime's async threads
/// (`commands::serve`): an endpoint slot's blocking HTTP client panics when
/// it is built inside async code. A failed assertion fails the test with its
/// own message.
fn on_a_blocking_engine_thread(name: &str, body: impl FnOnce() + Send + 'static) {
    run_on_engine_stack(name, move || async move {
        if let Err(error) = tokio::task::spawn_blocking(body).await {
            std::panic::resume_unwind(error.into_panic());
        }
    });
}

/// The owner caps the vault's system principal at one and a half batches.
/// The background line admits the first batch, refuses the next three before
/// they are sent, and tells the owner once, not once per refused batch.
#[test]
fn a_spent_background_line_tells_the_owners_once() {
    on_a_blocking_engine_thread("spent-line-notice", || {
        let (_dir, vault, owner, system) = vault();
        cap_the_system_principal(&vault, owner, system);
        let server = with_bound_endpoint_slot(server(&vault)).expect("bound slot");
        let receipts = Arc::new(MemoryReceipts::default());

        let (admitted, posted) = send_batches(&server, &receipts, 4);

        assert_eq!(admitted, [true, false, false, false]);
        assert_eq!(posted, 1, "a refused batch went out");
        assert_eq!(spent_refusals(&receipts), 3, "{:?}", receipts.rows());
        assert_eq!(
            spent_line_notices(&vault, owner),
            1,
            "the owner is told once for the spent line"
        );
    });
}

/// When the host pushes its line, against when the server takes its
/// embedder slot.
#[derive(Clone, Copy)]
enum HostPush {
    BeforeTheSlot,
    AfterTheSlot,
    /// Before the slot, and then a second line with nothing in it.
    TwiceBeforeTheSlot,
}

/// A host line of two batches pays instead of the vault's background line,
/// whose owner cap would admit one: two batches go out on the host's line,
/// the third is refused, and the owner is told once. A second push keeps the
/// first line, in the server and in the slot it takes later.
fn a_host_line_pays_instead_of_the_vault_line(push: HostPush) {
    let (_dir, vault, owner, system) = vault();
    cap_the_system_principal(&vault, owner, system);
    let host_line = BudgetGuard::with_reserve_units(
        "host-embedding",
        batch_tokens() * 2,
        1,
        BudgetExhaustionPolicy::Suspend,
    );
    let server = match push {
        HostPush::BeforeTheSlot => {
            with_bound_endpoint_slot(server(&vault).with_embedding_line(host_line.clone()))
        }
        HostPush::AfterTheSlot => with_bound_endpoint_slot(server(&vault))
            .map(|server| server.with_embedding_line(host_line.clone())),
        HostPush::TwiceBeforeTheSlot => with_bound_endpoint_slot(
            server(&vault)
                .with_embedding_line(host_line.clone())
                .with_embedding_line(BudgetGuard::with_reserve_units(
                    "second-host-embedding",
                    0,
                    1,
                    BudgetExhaustionPolicy::Suspend,
                )),
        ),
    }
    .expect("bound slot");
    let receipts = Arc::new(MemoryReceipts::default());

    let (admitted, posted) = send_batches(&server, &receipts, 3);

    assert_eq!(
        admitted,
        [true, true, false],
        "the host's line admits two batches, past the owner's cap on the vault's line"
    );
    assert_eq!(posted, 2, "a refused batch went out");
    assert_eq!(
        host_line.read().used_units,
        batch_tokens() * 2,
        "the host's line carries the spend"
    );
    assert_eq!(spent_refusals(&receipts), 1, "{:?}", receipts.rows());
    assert_eq!(spent_line_notices(&vault, owner), 1);
}

#[test]
fn a_host_line_pushed_before_the_slot_pays_instead_of_the_vault_line() {
    on_a_blocking_engine_thread("host-line-before-slot", || {
        a_host_line_pays_instead_of_the_vault_line(HostPush::BeforeTheSlot);
    });
}

#[test]
fn a_host_line_pushed_after_the_slot_pays_instead_of_the_vault_line() {
    on_a_blocking_engine_thread("host-line-after-slot", || {
        a_host_line_pays_instead_of_the_vault_line(HostPush::AfterTheSlot);
    });
}

#[test]
fn a_second_host_line_keeps_the_first() {
    on_a_blocking_engine_thread("host-line-pushed-twice", || {
        a_host_line_pays_instead_of_the_vault_line(HostPush::TwiceBeforeTheSlot);
    });
}

/// With no `budget_policy` row and no host line, the background line admits
/// every batch, as before: spend changes for no one, and no one is told.
#[test]
fn with_no_cap_and_no_host_line_every_batch_goes_out_untold() {
    on_a_blocking_engine_thread("background-line-uncapped", || {
        let (_dir, vault, owner, _system) = vault();
        let server = with_bound_endpoint_slot(server(&vault)).expect("bound slot");
        let receipts = Arc::new(MemoryReceipts::default());

        let (admitted, posted) = send_batches(&server, &receipts, 3);

        assert_eq!(admitted, [true, true, true]);
        assert_eq!(posted, 3);
        assert_eq!(spent_refusals(&receipts), 0, "{:?}", receipts.rows());
        assert_eq!(spent_line_notices(&vault, owner), 0);
    });
}
