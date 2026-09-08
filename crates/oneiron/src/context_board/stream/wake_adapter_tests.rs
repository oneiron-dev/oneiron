//! Durable-mailbox adapter-install scenario tests.

use super::*;

/// One durable TASK row plus the routing actor that owns it — the layer-1
/// mailbox an adapter delivery accelerates but never replaces.
struct MailboxRow {
    actor_ref: String,
    task_ref: crate::entity_id::EntityId,
}

/// The durable side of the ladder: a real vault whose TASK rows are
/// re-read, never reconstructed, to prove the mailbox outlives every
/// adapter attempt.
struct DurableMailbox {
    vault: crate::Vault,
    rows: Vec<crate::entity_id::EntityId>,
    _dir: tempfile::TempDir,
}

impl DurableMailbox {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = crate::Vault::open(dir.path(), crate::config::VaultConfig::default())
            .expect("open mailbox vault");
        Self {
            vault,
            rows: Vec::new(),
            _dir: dir,
        }
    }

    /// Mint one harness-instance actor and its durable TASK row through
    /// the real `tasks.create` verb.
    ///
    /// The create runs on the PERSON actor's own `human` lane, because a
    /// fresh vault's seeded policy is what decides here: it grants `auto`
    /// to the `human` actor class for EVERY actor, while agent-class
    /// `auto` is reserved to the single first-party connector id. Minting
    /// these three seeds as agents would therefore park two of them as
    /// proposals — an artefact of the seeded ceiling, not a fact about
    /// the delivery ladder under test. The gate is still consulted on
    /// every mint and must still answer Auto; nothing here bypasses it,
    /// fabricates a receipt, or writes a TASK row directly.
    fn mint(&mut self, seed: u8) -> MailboxRow {
        use crate::edge::EdgeActorClass;
        use crate::registry::ENTITY_TYPE_PERSON;
        use crate::task_verb::TaskCreateSpec;
        use crate::temporal::TimeRange;

        let actor =
            crate::entity_id::EntityId::from_bytes([seed; 16]).expect("harness instance actor id");
        self.vault
            .put_entity(
                &actor,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"harness-instance-actor",
            )
            .expect("store harness instance actor");
        let created = self
            .vault
            .memory(actor, EdgeActorClass::Human)
            .tasks_create(&TaskCreateSpec::new(
                rmpv::Value::from("wake-mailbox"),
                None,
                None,
                Some(120),
            ))
            .expect("mint durable mailbox row");
        assert!(created.effected);
        let task_ref = created.task_ref.expect("durable mailbox task ref");
        self.rows.push(task_ref);
        MailboxRow {
            actor_ref: actor.to_hex(),
            task_ref,
        }
    }

    /// Re-READ every minted row from the vault. Nothing here consults the
    /// ephemeral dispatch state, so a false answer means the durable
    /// transport actually lost the message.
    fn all_persisted(&self) -> bool {
        let live = self
            .vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TASK)
            .expect("re-read durable mailbox rows");
        self.rows.iter().all(|row| live.contains(row))
    }
}

/// The wake ONE-1702 mints for a durable row. Its fields are private and
/// have no crate-external construction path, which is exactly why this
/// fixture lives in the owning module.
fn mailbox_event(row: &MailboxRow, event: &str) -> VerifiedOwnTaskEvent {
    VerifiedOwnTaskEvent {
        task_ref: row.task_ref.to_hex(),
        actor_ref: row.actor_ref.clone(),
        event_ref: event.into(),
    }
}

/// The layer a report actually resolved on, or `None` when the bundle did
/// not deliver.
fn delivered_layer(
    chosen: Option<WakeAdapterKind>,
    disposition: &WakeReportDisposition,
) -> Option<u8> {
    match disposition {
        WakeReportDisposition::Delivered { .. } => chosen.map(WakeAdapterKind::layer),
        WakeReportDisposition::Reoffered { .. } | WakeReportDisposition::Exhausted { .. } => None,
    }
}

fn attach_wake_connection(r: &mut BoardStreamRegistry, c: &StreamConnectionId, actor: &str) {
    r.attach_connection(
        c.clone(),
        BoardRenderMode::Stream,
        actor.into(),
        BTreeSet::from([SubscriptionScope::MyTasks, SubscriptionScope::ConsultsToMe]),
        0,
    );
}

/// Wake-adapter install + delivery observations.
struct WakeAdapterInstall {
    /// Adapter installs performed (ONE for the hook-capable instance;
    /// the weak-hook instance gets NO adapter — it lands on the
    /// fallback layer of the 08b §5 r4v2 ladder; F16 canon correction).
    adapter_installs: usize,
    /// Distinct actor keys the TWO instances registered under
    /// (config-dir keying makes them two actors regardless of lane).
    distinct_actor_keys: usize,
    /// True iff the undelivered message stayed persisted in the vault
    /// mailbox until delivery (durable transport layer).
    mailbox_persisted_until_delivery: bool,
    /// Deliveries via a harness adapter (layer 2).
    deliveries_via_adapter: usize,
    /// Deliveries via the hard fallback (layer 3).
    deliveries_via_fallback: usize,
    /// True iff the hook-capable instance's wake was delivered through
    /// its installed adapter (layer 2 — the instance that owns the one
    /// adapter install).
    hook_capable_delivered_via_adapter: bool,
    /// True iff the weak-hook instance's wake was delivered through the
    /// hard fallback (layer 3 — it has no adapter to use).
    weak_hook_delivered_via_fallback: bool,
}

/// ONE-1703 fixture: two instances of the SAME harness under different
/// config dirs — one with lifecycle hooks (gets the adapter install),
/// one weak-hook (no adapter; fallback lane); send one wake to each.
fn arm_wake_adapter_install() -> WakeAdapterInstall {
    let mut mailbox = DurableMailbox::open();
    let hook_row = mailbox.mint(0xE1);
    let weak_row = mailbox.mint(0xE2);
    let transport_row = mailbox.mint(0xE3);
    let hook_capable = StreamConnectionId("hook-capable".into());
    let weak_hook = StreamConnectionId("weak-hook".into());
    let mut r = BoardStreamRegistry::default();
    attach_wake_connection(&mut r, &hook_capable, &hook_row.actor_ref);
    attach_wake_connection(&mut r, &weak_hook, &weak_row.actor_ref);

    // ── Phase 1 · install per instance, one wake each, both delivered ──
    // Same harness, same lane, two config dirs: two instances, and the
    // hook-capable one is the only owner of a layer-2 adapter.
    let hook_instance = HarnessInstanceKey::new("wake-instance:v1:claude-code:/cfg/hooked");
    let weak_instance = HarnessInstanceKey::new("wake-instance:v1:claude-code:/cfg/weak");
    let hook_receipt = r
        .bind_instance(
            &hook_capable,
            hook_instance.clone(),
            BTreeSet::from([
                WakeAdapterKind::ClaudeCodeMonitor,
                WakeAdapterKind::TmuxSendKeys,
            ]),
        )
        .expect("bind hook-capable instance");
    let weak_receipt = r
        .bind_instance(
            &weak_hook,
            weak_instance,
            BTreeSet::from([WakeAdapterKind::TmuxSendKeys]),
        )
        .expect("bind weak-hook instance");
    let adapter_installs = [&hook_receipt, &weak_receipt]
        .into_iter()
        .flat_map(|receipt| receipt.installed.iter())
        .filter(|kind| kind.layer() == 2)
        .count();
    let distinct_actor_keys = [&hook_receipt, &weak_receipt]
        .into_iter()
        .map(|receipt| receipt.instance.as_str())
        .collect::<BTreeSet<_>>()
        .len();

    // Wakes mint only through the real ONE-1702 floor.
    assert_eq!(
        r.route_event(BoardEvent::OwnTaskFailed {
            event: mailbox_event(&hook_row, "hook-own-task-failed"),
            line: "attempt failed".into(),
        })
        .wake_enqueued,
        1
    );
    // Per-instance isolation: the hook-capable wake is invisible next door.
    assert_eq!(r.next_wake_dispatch(&weak_hook), None);
    assert_eq!(r.next_wake(&weak_hook), None);
    assert_eq!(
        r.route_event(BoardEvent::ConsultArrived {
            event: mailbox_event(&weak_row, "weak-consult-arrived"),
            line: "consult arrived".into(),
        })
        .wake_enqueued,
        1
    );

    let hook_dispatch = r
        .next_wake_dispatch(&hook_capable)
        .expect("hook-capable dispatch");
    assert_eq!(hook_dispatch.instance, hook_instance);
    assert_eq!(
        hook_dispatch.chosen,
        Some(WakeAdapterKind::ClaudeCodeMonitor)
    );
    assert_eq!(hook_dispatch.coalesced, 1);
    // Durable-row law: re-read the mailbox immediately before the report.
    let mut mailbox_persisted_until_delivery = mailbox.all_persisted();
    let hook_disposition = r
        .report_wake_delivery(
            &hook_capable,
            hook_dispatch.dispatch_seq,
            WakeAdapterKind::ClaudeCodeMonitor,
            WakeDeliveryOutcome::Delivered,
        )
        .expect("hook-capable delivery report");

    let weak_dispatch = r
        .next_wake_dispatch(&weak_hook)
        .expect("weak-hook dispatch");
    assert_eq!(weak_dispatch.chosen, Some(WakeAdapterKind::TmuxSendKeys));
    assert_eq!(weak_dispatch.coalesced, 1);
    assert_eq!(weak_dispatch.envelopes[0].event_ref, "weak-consult-arrived");
    mailbox_persisted_until_delivery &= mailbox.all_persisted();
    let weak_disposition = r
        .report_wake_delivery(
            &weak_hook,
            weak_dispatch.dispatch_seq,
            WakeAdapterKind::TmuxSendKeys,
            WakeDeliveryOutcome::Delivered,
        )
        .expect("weak-hook delivery report");
    // Success drains exactly the bundle it resolved.
    assert_eq!(r.next_wake(&hook_capable), None);
    assert_eq!(r.next_wake(&weak_hook), None);

    let hook_layer = delivered_layer(hook_dispatch.chosen, &hook_disposition);
    let weak_layer = delivered_layer(weak_dispatch.chosen, &weak_disposition);
    let mut install = WakeAdapterInstall {
        adapter_installs,
        distinct_actor_keys,
        mailbox_persisted_until_delivery,
        deliveries_via_adapter: [hook_layer, weak_layer]
            .into_iter()
            .flatten()
            .filter(|layer| *layer == 2)
            .count(),
        deliveries_via_fallback: [hook_layer, weak_layer]
            .into_iter()
            .flatten()
            .filter(|layer| *layer == 3)
            .count(),
        hook_capable_delivered_via_adapter: hook_layer == Some(2),
        weak_hook_delivered_via_fallback: weak_layer == Some(3),
    };

    // ── Phase 2 · the ladder degrades on NEW hook-capable wakes ────────
    // Only `mailbox_persisted_until_delivery` keeps accruing evidence
    // below; the other six observations are frozen at Phase 1.
    let before = r.wake_dispatch_observations();
    for event in ["degrade-1", "degrade-2"] {
        r.route_event(BoardEvent::OwnTaskFailed {
            event: mailbox_event(&hook_row, event),
            line: "attempt failed".into(),
        });
    }
    let degraded = r
        .next_wake_dispatch(&hook_capable)
        .expect("degrading dispatch");
    assert_eq!(degraded.chosen, Some(WakeAdapterKind::ClaudeCodeMonitor));
    assert_eq!(degraded.coalesced, 2);
    // Coalescing preserves the original queue order.
    assert_eq!(
        degraded
            .envelopes
            .iter()
            .map(|envelope| envelope.event_ref.as_str())
            .collect::<Vec<_>>(),
        ["degrade-1", "degrade-2"]
    );
    assert_eq!(
        r.report_wake_delivery(
            &hook_capable,
            degraded.dispatch_seq,
            WakeAdapterKind::ClaudeCodeMonitor,
            WakeDeliveryOutcome::Failed,
        ),
        Ok(WakeReportDisposition::Reoffered {
            failed: WakeAdapterKind::ClaudeCodeMonitor,
            next: WakeAdapterKind::TmuxSendKeys,
            envelopes: 2,
        })
    );
    install.mailbox_persisted_until_delivery &= mailbox.all_persisted();
    let reoffered = r
        .next_wake_dispatch(&hook_capable)
        .expect("re-offered dispatch");
    // The same unit, the same ordered envelopes, one layer lower.
    assert_eq!(reoffered.dispatch_seq, degraded.dispatch_seq);
    assert_eq!(reoffered.envelopes, degraded.envelopes);
    assert_eq!(reoffered.chosen, Some(WakeAdapterKind::TmuxSendKeys));
    assert_eq!(
        r.report_wake_delivery(
            &hook_capable,
            reoffered.dispatch_seq,
            WakeAdapterKind::TmuxSendKeys,
            WakeDeliveryOutcome::Failed,
        ),
        Ok(WakeReportDisposition::Exhausted { envelopes: 2 })
    );
    install.mailbox_persisted_until_delivery &= mailbox.all_persisted();
    // A neighbour instance is untouched by these reports.
    assert_eq!(r.next_wake_dispatch(&weak_hook), None);
    assert_eq!(r.next_wake(&weak_hook), None);
    let degraded_observations = r.wake_dispatch_observations();
    assert_eq!(
        degraded_observations.delivery_failures,
        before.delivery_failures + 2
    );
    assert_eq!(
        degraded_observations.dispatch_units_created,
        before.dispatch_units_created + 1
    );
    assert_eq!(
        degraded_observations.envelopes_coalesced,
        before.envelopes_coalesced + 2
    );
    assert_eq!(
        degraded_observations.exhausted_dispatches,
        before.exhausted_dispatches + 1
    );
    assert_eq!(
        degraded_observations.exhausted_envelopes,
        before.exhausted_envelopes + 2
    );
    assert_eq!(
        degraded_observations.delivered_dispatches,
        before.delivered_dispatches
    );
    assert_eq!(
        degraded_observations.transport_only_dispatches,
        before.transport_only_dispatches
    );

    // ── Phase 3 · a transport-only instance resolves at layer 1 alone ──
    let transport_only = StreamConnectionId("transport-only".into());
    attach_wake_connection(&mut r, &transport_only, &transport_row.actor_ref);
    r.bind_instance(
        &transport_only,
        HarnessInstanceKey::new("wake-instance:v1:codex:/cfg/bare"),
        BTreeSet::new(),
    )
    .expect("bind transport-only instance");
    r.route_event(BoardEvent::OwnTaskFailed {
        event: mailbox_event(&transport_row, "transport-only-failed"),
        line: "attempt failed".into(),
    });
    let terminal = r
        .next_wake_dispatch(&transport_only)
        .expect("transport-only dispatch");
    assert_eq!(terminal.chosen, None);
    assert_eq!(terminal.coalesced, 1);
    let transport_observations = r.wake_dispatch_observations();
    assert_eq!(
        transport_observations.transport_only_dispatches,
        degraded_observations.transport_only_dispatches + 1
    );
    assert_eq!(
        transport_observations.exhausted_dispatches,
        degraded_observations.exhausted_dispatches
    );
    assert_eq!(
        transport_observations.exhausted_envelopes,
        degraded_observations.exhausted_envelopes
    );
    // The row survives layer-2 failure, layer-3 failure, and the
    // transport-only resolution: layer 1 is the correctness floor.
    install.mailbox_persisted_until_delivery &= mailbox.all_persisted();

    // ── Phase 4 · N wakes coalesce into ONE unit; later arrivals wait ──
    let burst = ["burst-1", "burst-2", "burst-3"];
    for event in burst {
        r.route_event(BoardEvent::OwnTaskFailed {
            event: mailbox_event(&hook_row, event),
            line: "attempt failed".into(),
        });
    }
    let bundle = r
        .next_wake_dispatch(&hook_capable)
        .expect("coalesced dispatch");
    assert_eq!(bundle.coalesced, burst.len());
    assert_eq!(bundle.envelopes.len(), burst.len());
    r.route_event(BoardEvent::OwnTaskFailed {
        event: mailbox_event(&hook_row, "after-dispatch"),
        line: "attempt failed".into(),
    });
    let repolled = r
        .next_wake_dispatch(&hook_capable)
        .expect("re-polled dispatch");
    assert_eq!(repolled.dispatch_seq, bundle.dispatch_seq);
    assert_eq!(repolled.envelopes, bundle.envelopes);
    assert_eq!(
        r.connection_state(&hook_capable)
            .expect("hook-capable state")
            .wakes
            .len(),
        1
    );

    install
}

/// ONE-1703 · 08b §5 (r4v2): adapters install PER INSTANCE (config-dir
/// keyed); the vault mailbox is the durable transport; "weak-hook CLIs
/// land lower on the delivery ladder" — so the conforming shape here is
/// exactly 1 adapter install + 1 adapter delivery + 1 fallback delivery
/// across 2 distinct actor keys.
#[test]
fn wake_adapters_install_per_instance_over_durable_mailbox() {
    let install = arm_wake_adapter_install();
    assert_eq!(install.adapter_installs, 1);
    assert_eq!(install.distinct_actor_keys, 2);
    assert!(install.mailbox_persisted_until_delivery);
    assert_eq!(install.deliveries_via_adapter, 1);
    assert_eq!(install.deliveries_via_fallback, 1);
    assert!(install.hook_capable_delivered_via_adapter);
    assert!(install.weak_hook_delivered_via_fallback);
}
