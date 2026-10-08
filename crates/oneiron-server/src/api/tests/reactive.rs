//! Local-first reactive read sync/refresh/ignore/lag/origins plus engine-observer vault write path.

use super::*;

/// Entity documents share a monthly ledger window but must not share a local
/// read invalidation. A real durable text edit flows through the server's
/// document relay; the matching query re-reads and its sibling does not.
#[tokio::test]
async fn local_entity_document_edit_refreshes_only_matching_read() {
    let (_dir, server) = test_server();
    let learned_at = 1_770_000_000;
    let first = seeded_test_entity_id(0x1437_0010);
    let second = seeded_test_entity_id(0x1437_0011);
    seed_reactive_turn(server.vault(), &first, learned_at);
    seed_reactive_turn(server.vault(), &second, learned_at);
    let (first_probe, first_reads) = reactive_probe(first, vec![ReactiveDependency::Doc(first)]);
    let (second_probe, second_reads) =
        reactive_probe(second, vec![ReactiveDependency::Doc(second)]);
    let mut first_read = open_local_reactive_read(&server, first_probe).expect("first read");
    let mut second_read = open_local_reactive_read(&server, second_probe).expect("second read");
    assert_eq!(reactive_reads(&first_reads), 1);
    assert_eq!(reactive_reads(&second_reads), 1);

    let document = server
        .reassert_manager
        .documents()
        .open(first)
        .expect("open document");
    document
        .edit_text(0, 0, "one edit")
        .expect("durable document edit");
    assert_eq!(document.text().unwrap(), "one edit");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        first_read.refresh_on_change(),
    )
    .await
    .expect("document relay reaches local query")
    .expect("matching read succeeds");
    assert_eq!(reactive_reads(&first_reads), 2);
    assert_eq!(first_read.revision(), 1);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            second_read.refresh_on_change(),
        )
        .await
        .is_err(),
        "an entity in the same window must not re-read"
    );
    assert_eq!(reactive_reads(&second_reads), 1);
    assert_eq!(second_read.revision(), 0);
}

/// Production wiring, end to end: a real LMDB write, mirrored into the window
/// by the engine's own LMDB→CRDT path, reaches a reactive read through
/// Observer B's local tee. The other entity is in the SAME window, but its
/// query does not re-read. No encoded frame is injected in this fixture.
#[tokio::test]
async fn local_vault_write_reaches_reactive_read_through_engine_observer() {
    let (_dir, server) = test_server();
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let doc = server
        .get_or_create_window(&window_key)
        .await
        .expect("open window");

    let id = seeded_test_entity_id(0x1437_0009);
    let other = seeded_test_entity_id(0x1437_0015);
    seed_reactive_turn(server.vault(), &other, learned_at);
    assert_eq!(
        oneiron::sync::window::reverse_rematerialize(server.vault(), &doc, &window_key)
            .expect("mirror initial sibling"),
        1
    );
    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::Doc(id)]);
    let (other_probe, other_reads) = reactive_probe(other, vec![ReactiveDependency::Doc(other)]);
    let mut read = open_local_reactive_read(&server, probe).expect("open reactive read");
    let mut other_read = open_local_reactive_read(&server, other_probe).expect("open sibling read");
    assert!(read.snapshot().is_none());
    assert!(other_read.snapshot().is_some());

    seed_reactive_turn(server.vault(), &id, learned_at);
    assert_eq!(
        oneiron::sync::window::reverse_rematerialize(server.vault(), &doc, &window_key)
            .expect("mirror local write into the window"),
        1
    );

    let refreshed =
        tokio::time::timeout(std::time::Duration::from_secs(5), read.refresh_on_change())
            .await
            .expect("observer notice reaches the reactive read")
            .expect("refresh succeeds")
            .is_some();
    assert!(refreshed, "the reactive read serves the newly written body");
    assert_eq!(read.revision(), 1);
    assert_eq!(reactive_reads(&reads), 2);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            other_read.refresh_on_change()
        )
        .await
        .is_err(),
        "Observer B must name only the changed entity, not its whole window"
    );
    assert_eq!(other_read.revision(), 0);
    assert_eq!(reactive_reads(&other_reads), 1);
}

/// A remote ledger commit is materialized by Observer B before its local tee
/// notifies. Only the changed entity's document dependency can re-read.
#[tokio::test]
async fn observer_b_materialization_refreshes_only_changed_entity() {
    use loro::CommitOptions;

    let (_dir, server) = test_server();
    let learned_at = 1_770_000_000u64;
    let window = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let doc = server
        .get_or_create_window(&window)
        .await
        .expect("open window");
    let first = seeded_test_entity_id(0x1437_0016);
    let second = seeded_test_entity_id(0x1437_0017);
    // The second entity is already present before either local query opens.
    let mut blob = vec![1u8];
    for _ in 0..3 {
        blob.extend_from_slice(&learned_at.to_be_bytes());
    }
    blob.extend_from_slice(b"remote body");
    doc.get_map("entities")
        .insert(&second.to_hex(), blob.as_slice())
        .expect("write sibling");
    doc.commit_with(CommitOptions::new().origin("conn:7"));

    let (first_probe, first_reads) = reactive_probe(first, vec![ReactiveDependency::Doc(first)]);
    let (second_probe, second_reads) =
        reactive_probe(second, vec![ReactiveDependency::Doc(second)]);
    let mut first_read = open_local_reactive_read(&server, first_probe).expect("first read");
    let mut second_read = open_local_reactive_read(&server, second_probe).expect("second read");
    assert!(first_read.snapshot().is_none());
    assert_eq!(
        second_read.snapshot().as_deref(),
        Some(b"remote body".as_slice())
    );

    doc.get_map("entities")
        .insert(&first.to_hex(), blob.as_slice())
        .expect("write first");
    doc.commit_with(CommitOptions::new().origin("conn:7"));
    let snapshot = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        first_read.refresh_on_change(),
    )
    .await
    .expect("Observer B emits an entity notice")
    .expect("local read succeeds");
    assert_eq!(snapshot.as_deref(), Some(b"remote body".as_slice()));
    assert_eq!(reactive_reads(&first_reads), 2);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            second_read.refresh_on_change(),
        )
        .await
        .is_err(),
        "a sibling in the same window must not re-read"
    );
    assert_eq!(reactive_reads(&second_reads), 1);
}

/// Publication is before hard purge, so a tombstone notification must not
/// consume the local read's invalidation while the old body is still readable.
/// Only the committed scrub/purge notice may wake it.
async fn assert_local_deletion_refreshes_only_target(reason: oneiron::DeleteReason) {
    let (_dir, server) = test_server();
    let learned_at = 1_770_000_000;
    let window = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let doc = server
        .get_or_create_window(&window)
        .await
        .expect("open window");
    let id = seeded_test_entity_id(0x1437_0018);
    let sibling = seeded_test_entity_id(0x1437_0019);
    for entity in [id, sibling] {
        seed_reactive_turn(server.vault(), &entity, learned_at);
    }
    assert_eq!(
        oneiron::sync::window::reverse_rematerialize(server.vault(), &doc, &window)
            .expect("mirror entities"),
        2
    );
    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::Doc(id)]);
    let (sibling_probe, sibling_reads) =
        reactive_probe(sibling, vec![ReactiveDependency::Doc(sibling)]);
    let mut read = open_local_reactive_read(&server, probe).expect("open target read");
    let mut sibling_read = open_local_reactive_read(&server, sibling_probe).expect("open sibling");
    let before = read.snapshot().clone();
    assert!(before.is_some());

    let outcome = server
        .vault()
        .delete_entity_with_reason(&id, reason)
        .expect("delete");
    assert!(outcome.existed);
    let refreshed =
        tokio::time::timeout(std::time::Duration::from_secs(5), read.refresh_on_change())
            .await
            .expect("post-commit notice")
            .expect("re-read");
    assert_eq!(
        refreshed,
        &server.vault().get(&id).expect("stored post-delete state")
    );
    assert_ne!(refreshed, &before);
    assert_eq!(reactive_reads(&reads), 2);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            sibling_read.refresh_on_change()
        )
        .await
        .is_err(),
        "same-window sibling must retain its snapshot"
    );
    assert_eq!(reactive_reads(&sibling_reads), 1);
}

#[tokio::test]
async fn soft_delete_refreshes_only_deleted_local_entity() {
    assert_local_deletion_refreshes_only_target(oneiron::DeleteReason::UserDelete).await;
}

#[tokio::test]
async fn hard_delete_waits_for_purge_then_refreshes_only_deleted_local_entity() {
    assert_local_deletion_refreshes_only_target(oneiron::DeleteReason::UserHardDelete).await;
}

struct IncomingEdges {
    parent: oneiron::EntityId,
    dependencies: [ReactiveDependency; 1],
    reads: Arc<std::sync::atomic::AtomicUsize>,
}
impl ReactiveLocalQuery for IncomingEdges {
    type Output = Vec<oneiron::EntityId>;
    fn dependencies(&self) -> &[ReactiveDependency] {
        &self.dependencies
    }
    fn read(&self, vault: &oneiron::Vault) -> oneiron::Result<Self::Output> {
        self.reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(vault
            .edges_in(&self.parent)?
            .into_iter()
            .filter(|edge| edge.kind == oneiron::EdgeKind::ChildOf)
            .map(|edge| edge.target)
            .collect())
    }
}

/// The wire delta names child X and old parent A, but replay installs the
/// losing candidate X→B from the live CRDT map in the same LMDB transaction.
/// B's incoming-edge read must re-run; an unrelated parent remains untouched.
#[tokio::test]
async fn replayed_child_of_parent_invalidates_incoming_edge_read() {
    use loro::CommitOptions;
    use oneiron::sync::bridge::{encode_edge_value_for_crdt, format_edge_key};

    let (_dir, server) = test_server();
    let learned_at = 1_770_000_000;
    let window = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let doc = server
        .get_or_create_window(&window)
        .await
        .expect("open window");
    let child = seeded_test_entity_id(0x1437_0020);
    let a = seeded_test_entity_id(0x1437_0021);
    let b = seeded_test_entity_id(0x1437_0022);
    let other = seeded_test_entity_id(0x1437_0023);
    for entity in [child, a, b, other] {
        seed_reactive_turn(server.vault(), &entity, learned_at);
    }
    assert_eq!(
        oneiron::sync::window::reverse_rematerialize(server.vault(), &doc, &window)
            .expect("mirror endpoints"),
        4
    );
    let kind = oneiron::EdgeKind::ChildOf;
    let key_a = format_edge_key(&child, kind, &a);
    let key_b = format_edge_key(&child, kind, &b);
    for (key, timestamp) in [(&key_a, 100), (&key_b, 90)] {
        let value = encode_edge_value_for_crdt(kind, 1.0, timestamp, None, None).unwrap();
        doc.get_map("edges").insert(key, value.as_slice()).unwrap();
    }
    doc.commit_with(CommitOptions::new().origin("conn:7"));
    assert_eq!(server.vault().sources(&a, kind, None).unwrap(), vec![child]);
    assert!(server.vault().sources(&b, kind, None).unwrap().is_empty());

    let counter_b = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter_other = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut b_read = open_local_reactive_read(
        &server,
        IncomingEdges {
            parent: b,
            dependencies: [ReactiveDependency::Doc(b)],
            reads: counter_b.clone(),
        },
    )
    .unwrap();
    let mut other_read = open_local_reactive_read(
        &server,
        IncomingEdges {
            parent: other,
            dependencies: [ReactiveDependency::Doc(other)],
            reads: counter_other.clone(),
        },
    )
    .unwrap();
    assert!(b_read.snapshot().is_empty());

    doc.get_map("edges").delete(&key_a).unwrap();
    doc.commit_with(CommitOptions::new().origin("conn:7"));
    let refreshed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        b_read.refresh_on_change(),
    )
    .await
    .expect("replayed parent invalidation")
    .expect("incoming edge read");
    assert_eq!(refreshed, &vec![child]);
    assert_eq!(reactive_reads(&counter_b), 2);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            other_read.refresh_on_change()
        )
        .await
        .is_err(),
        "unrelated parent must not re-read"
    );
    assert_eq!(reactive_reads(&counter_other), 1);
}

/// A winner added for X displaces the already projected X→A link. The wire
/// delta names only X and B, so A must be reported from committed projection
/// effects, not merely from the input or the replay candidates.
#[tokio::test]
async fn new_child_of_winner_invalidates_displaced_parent_read() {
    use loro::CommitOptions;
    use oneiron::sync::bridge::{encode_edge_value_for_crdt, format_edge_key};

    let (_dir, server) = test_server();
    let learned_at = 1_770_000_000;
    let window = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let doc = server.get_or_create_window(&window).await.unwrap();
    let child = seeded_test_entity_id(0x1437_0030);
    let a = seeded_test_entity_id(0x1437_0031);
    let b = seeded_test_entity_id(0x1437_0032);
    let other = seeded_test_entity_id(0x1437_0033);
    for id in [child, a, b, other] {
        seed_reactive_turn(server.vault(), &id, learned_at);
    }
    assert_eq!(
        oneiron::sync::window::reverse_rematerialize(server.vault(), &doc, &window).unwrap(),
        4
    );
    let kind = oneiron::EdgeKind::ChildOf;
    let old = format_edge_key(&child, kind, &a);
    let new = format_edge_key(&child, kind, &b);
    doc.get_map("edges")
        .insert(
            &old,
            encode_edge_value_for_crdt(kind, 1.0, 100, None, None)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
    doc.commit_with(CommitOptions::new().origin("conn:7"));
    assert_eq!(server.vault().sources(&a, kind, None).unwrap(), vec![child]);

    let a_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let other_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut a_read = open_local_reactive_read(
        &server,
        IncomingEdges {
            parent: a,
            dependencies: [ReactiveDependency::Doc(a)],
            reads: a_reads.clone(),
        },
    )
    .unwrap();
    let mut other_read = open_local_reactive_read(
        &server,
        IncomingEdges {
            parent: other,
            dependencies: [ReactiveDependency::Doc(other)],
            reads: other_reads.clone(),
        },
    )
    .unwrap();
    assert_eq!(a_read.snapshot(), &vec![child]);
    doc.get_map("edges")
        .insert(
            &new,
            encode_edge_value_for_crdt(kind, 1.0, 200, None, None)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
    doc.commit_with(CommitOptions::new().origin("conn:7"));
    assert_eq!(server.vault().sources(&b, kind, None).unwrap(), vec![child]);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            a_read.refresh_on_change()
        )
        .await
        .expect("displaced parent notice")
        .expect("read")
        .is_empty()
    );
    assert_eq!(reactive_reads(&a_reads), 2);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            other_read.refresh_on_change()
        )
        .await
        .is_err()
    );
    assert_eq!(reactive_reads(&other_reads), 1);
}

/// Headerless residue has no entity-row `existed` flag, but purging its vector
/// changes a local indexed read. The positive in-transaction scope probe is
/// the notice gate, not the entity-row boolean returned by deindex.
#[tokio::test]
async fn headerless_vector_delete_refreshes_only_its_local_read() {
    struct VectorRead {
        id: oneiron::EntityId,
        dependencies: [ReactiveDependency; 1],
        reads: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ReactiveLocalQuery for VectorRead {
        type Output = Option<Vec<f32>>;
        fn dependencies(&self) -> &[ReactiveDependency] {
            &self.dependencies
        }
        fn read(&self, vault: &oneiron::Vault) -> oneiron::Result<Self::Output> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            vault.get_vector(&self.id)
        }
    }
    let dir = tempfile::tempdir().expect("vector vault dir");
    let mut config = oneiron::VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    let vault = Arc::new(oneiron::Vault::open(dir.path(), config).unwrap());
    let server = Arc::new(
        crate::server::SyncServer::new(
            vault,
            crate::config::SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let orphan = seeded_test_entity_id(0x1437_0034);
    let other = seeded_test_entity_id(0x1437_0035);
    server
        .vault()
        .put_vector(&orphan, &[0.1, 0.2, 0.3, 0.4])
        .unwrap();
    server
        .vault()
        .put_vector(&other, &[0.5, 0.6, 0.7, 0.8])
        .unwrap();
    assert!(server.vault().get(&orphan).unwrap().is_none());
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let other_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut read = open_local_reactive_read(
        &server,
        VectorRead {
            id: orphan,
            dependencies: [ReactiveDependency::Doc(orphan)],
            reads: reads.clone(),
        },
    )
    .unwrap();
    let mut other_read = open_local_reactive_read(
        &server,
        VectorRead {
            id: other,
            dependencies: [ReactiveDependency::Doc(other)],
            reads: other_reads.clone(),
        },
    )
    .unwrap();
    assert!(read.snapshot().is_some());
    let outcome = server
        .vault()
        .delete_entity_with_reason(&orphan, oneiron::DeleteReason::GdprDelete)
        .unwrap();
    assert!(!outcome.existed);
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), read.refresh_on_change())
            .await
            .expect("post-commit orphan notice")
            .expect("read")
            .is_none()
    );
    assert_eq!(reactive_reads(&reads), 2);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            other_read.refresh_on_change()
        )
        .await
        .is_err()
    );
    assert_eq!(reactive_reads(&other_reads), 1);
}

/// A local read of an identity-topology event's public, typed body.
struct ReactiveIdentityEvent {
    id: oneiron::EntityId,
    dependencies: [ReactiveDependency; 1],
    reads: Arc<std::sync::atomic::AtomicUsize>,
}

impl ReactiveLocalQuery for ReactiveIdentityEvent {
    type Output = Option<oneiron::identity_topology::StoredIdentityOpEvent>;

    fn dependencies(&self) -> &[ReactiveDependency] {
        &self.dependencies
    }

    fn read(&self, vault: &oneiron::Vault) -> oneiron::Result<Self::Output> {
        self.reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        vault.identity_topology_event(&self.id)
    }
}

fn seed_reactive_merge(
    vault: &oneiron::Vault,
    actor: oneiron::EntityId,
    head: oneiron::EntityId,
    shell: oneiron::EntityId,
    at: u64,
) -> oneiron::EntityId {
    use oneiron::identity_topology::{
        IdentityOpEvidence, IdentityOpWrite, IdentityTopologyOp, MergeOp, SurvivorshipPlan,
    };
    match vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![shell],
                survivor: head,
                evidence: IdentityOpEvidence::default(),
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(oneiron::ClaimSource::Inferred).with_actor(
                oneiron::WriteActor::new(actor, oneiron::EdgeActorClass::Human),
            ),
            at,
        )
        .expect("apply bound merge")
    {
        oneiron::identity_topology::IdentityOpOutcome::Applied { event, .. } => event,
        other => panic!("merge did not apply: {other:?}"),
    }
}

/// The merge redirect shell retains its own body until the head's hard erase.
/// That erase also clears the shell in one transaction; both document IDs
/// must reach local readers, without waking an unrelated third entity.
#[tokio::test]
async fn hard_delete_head_refreshes_redirect_shell_read() {
    let (_dir, server) = test_server();
    let at = 1_770_000_000;
    let actor = seeded_test_entity_id(0x1437_0036);
    let head = seeded_test_entity_id(0x1437_0037);
    let shell = seeded_test_entity_id(0x1437_0038);
    let unrelated = seeded_test_entity_id(0x1437_0039);
    let other_head = seeded_test_entity_id(0x1437_0044);
    let other_shell = seeded_test_entity_id(0x1437_0045);
    for id in [actor, head, shell, unrelated, other_head, other_shell] {
        server
            .vault()
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: at, end: at },
                at,
                b"redirect shell body",
            )
            .unwrap();
    }
    server
        .get_or_create_window(&oneiron::sync::WindowKey::from_timestamp(at))
        .await
        .unwrap();
    let event = seed_reactive_merge(server.vault(), actor, head, shell, at + 1);
    let other_event = seed_reactive_merge(server.vault(), actor, other_head, other_shell, at + 2);
    assert_eq!(server.vault().resolve_entity(&shell).unwrap(), vec![head]);
    let (probe, reads) = reactive_probe(shell, vec![ReactiveDependency::Doc(shell)]);
    let (other_probe, other_reads) =
        reactive_probe(unrelated, vec![ReactiveDependency::Doc(unrelated)]);
    let mut read = open_local_reactive_read(&server, probe).unwrap();
    let mut other_read = open_local_reactive_read(&server, other_probe).unwrap();
    let event_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let other_event_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut event_read = open_local_reactive_read(
        &server,
        ReactiveIdentityEvent {
            id: event,
            dependencies: [ReactiveDependency::Doc(event)],
            reads: event_reads.clone(),
        },
    )
    .unwrap();
    let mut other_event_read = open_local_reactive_read(
        &server,
        ReactiveIdentityEvent {
            id: other_event,
            dependencies: [ReactiveDependency::Doc(other_event)],
            reads: other_event_reads.clone(),
        },
    )
    .unwrap();
    assert!(event_read.snapshot().as_ref().unwrap().actor.is_some());
    assert!(
        other_event_read
            .snapshot()
            .as_ref()
            .unwrap()
            .actor
            .is_some()
    );
    assert!(
        read.snapshot()
            .as_ref()
            .is_some_and(|body| !body.is_empty())
    );
    assert!(
        server
            .vault()
            .delete_entity_with_reason(&head, oneiron::DeleteReason::UserHardDelete)
            .unwrap()
            .existed
    );
    let refreshed =
        tokio::time::timeout(std::time::Duration::from_secs(5), read.refresh_on_change())
            .await
            .expect("redirect shell notice")
            .expect("read");
    assert_eq!(refreshed, &server.vault().get(&shell).unwrap());
    assert_ne!(refreshed, &Some(b"redirect shell body".to_vec()));
    assert_eq!(reactive_reads(&reads), 2);
    let refreshed_event = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        event_read.refresh_on_change(),
    )
    .await
    .expect("rewritten local event notice")
    .expect("event read");
    assert_eq!(
        refreshed_event,
        &server.vault().identity_topology_event(&event).unwrap()
    );
    assert!(refreshed_event.as_ref().unwrap().actor.is_none());
    assert_eq!(reactive_reads(&event_reads), 2);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            other_event_read.refresh_on_change()
        )
        .await
        .is_err(),
        "unrelated event must not re-read"
    );
    assert_eq!(reactive_reads(&other_event_reads), 1);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            other_read.refresh_on_change()
        )
        .await
        .is_err()
    );
    assert_eq!(reactive_reads(&other_reads), 1);
}

#[tokio::test]
async fn remote_hard_tombstone_refreshes_redirect_shell_read() {
    use loro::CommitOptions;

    let (_dir, server) = test_server();
    let at = 1_770_000_000;
    let actor = seeded_test_entity_id(0x1437_0040);
    let head = seeded_test_entity_id(0x1437_0041);
    let shell = seeded_test_entity_id(0x1437_0042);
    let other = seeded_test_entity_id(0x1437_0043);
    let other_head = seeded_test_entity_id(0x1437_0046);
    let other_shell = seeded_test_entity_id(0x1437_0047);
    for id in [actor, head, shell, other, other_head, other_shell] {
        server
            .vault()
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: at, end: at },
                at,
                b"remote shell body",
            )
            .unwrap();
    }
    let doc = server
        .get_or_create_window(&oneiron::sync::WindowKey::from_timestamp(at))
        .await
        .unwrap();
    let event = seed_reactive_merge(server.vault(), actor, head, shell, at + 1);
    let other_event = seed_reactive_merge(server.vault(), actor, other_head, other_shell, at + 2);
    let (probe, reads) = reactive_probe(shell, vec![ReactiveDependency::Doc(shell)]);
    let (other_probe, other_reads) = reactive_probe(other, vec![ReactiveDependency::Doc(other)]);
    let mut read = open_local_reactive_read(&server, probe).unwrap();
    let mut other_read = open_local_reactive_read(&server, other_probe).unwrap();
    let event_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let other_event_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut event_read = open_local_reactive_read(
        &server,
        ReactiveIdentityEvent {
            id: event,
            dependencies: [ReactiveDependency::Doc(event)],
            reads: event_reads.clone(),
        },
    )
    .unwrap();
    let mut other_event_read = open_local_reactive_read(
        &server,
        ReactiveIdentityEvent {
            id: other_event,
            dependencies: [ReactiveDependency::Doc(other_event)],
            reads: other_event_reads.clone(),
        },
    )
    .unwrap();
    assert!(event_read.snapshot().as_ref().unwrap().actor.is_some());
    assert!(
        other_event_read
            .snapshot()
            .as_ref()
            .unwrap()
            .actor
            .is_some()
    );
    assert!(
        read.snapshot()
            .as_ref()
            .is_some_and(|body| !body.is_empty())
    );
    let mut tombstone = vec![2u8]; // user_hard_delete v2
    tombstone.extend_from_slice(&at.to_le_bytes());
    tombstone.extend_from_slice(&[7u8; 16]);
    doc.get_map("tombstones")
        .insert(&head.to_hex(), tombstone.as_slice())
        .unwrap();
    doc.commit_with(CommitOptions::new().origin("conn:7"));
    assert_eq!(server.vault().get(&head).unwrap(), None);
    let refreshed =
        tokio::time::timeout(std::time::Duration::from_secs(5), read.refresh_on_change())
            .await
            .expect("remote redirect shell notice")
            .expect("read");
    assert_eq!(refreshed, &server.vault().get(&shell).unwrap());
    assert_eq!(reactive_reads(&reads), 2);
    let refreshed_event = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        event_read.refresh_on_change(),
    )
    .await
    .expect("rewritten remote event notice")
    .expect("event read");
    assert_eq!(
        refreshed_event,
        &server.vault().identity_topology_event(&event).unwrap()
    );
    assert!(refreshed_event.as_ref().unwrap().actor.is_none());
    assert_eq!(reactive_reads(&event_reads), 2);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            other_event_read.refresh_on_change()
        )
        .await
        .is_err(),
        "unrelated event must not re-read"
    );
    assert_eq!(reactive_reads(&other_event_reads), 1);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            other_read.refresh_on_change()
        )
        .await
        .is_err()
    );
    assert_eq!(reactive_reads(&other_reads), 1);
}

/// The NOTE's public document read contains pins. Erasing an unrelated source
/// changes that NOTE through its reverse pin index, not an incident edge.
struct ReactiveNotePins {
    id: oneiron::EntityId,
    dependencies: [ReactiveDependency; 1],
    reads: Arc<std::sync::atomic::AtomicUsize>,
}
impl ReactiveLocalQuery for ReactiveNotePins {
    type Output = oneiron::note::NoteDocumentView;
    fn dependencies(&self) -> &[ReactiveDependency] {
        &self.dependencies
    }
    fn read(&self, vault: &oneiron::Vault) -> oneiron::Result<Self::Output> {
        self.reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        vault.note_document(self.id)
    }
}

fn seed_reactive_citation(
    server: &Arc<SyncServer>,
    counter: u128,
) -> (oneiron::EntityId, oneiron::EntityId, oneiron::EntityId) {
    let actor = seeded_test_entity_id(counter);
    server
        .vault()
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"citation actor",
        )
        .unwrap();
    let claim = seeded_test_entity_id(counter + 1);
    let memory = server.vault().memory(actor, oneiron::EdgeActorClass::Human);
    memory
        .claim_upsert(&oneiron::memory::ClaimInput {
            id: Some(claim.to_hex()),
            predicate: "profile.name".into(),
            subject_ref: actor.to_hex(),
            value: serde_json::json!("source"),
            confidence: 0.9,
            source: "user_stated".into(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .unwrap();
    memory.bless_brief_kind().unwrap();
    let source = oneiron::EntityId::from_hex(
        &memory
            .author_take(oneiron::note::TakeTarget::Subject(actor), "erased quote")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let pin = server.vault().pin_note_span(source, claim, 0, 6).unwrap();
    let citing =
        oneiron::EntityId::from_hex(&memory.author_brief("authored text", &[pin]).unwrap().id_hex)
            .unwrap();
    let other =
        oneiron::EntityId::from_hex(&memory.author_brief("unrelated text", &[]).unwrap().id_hex)
            .unwrap();
    (source, citing, other)
}

#[tokio::test]
async fn local_and_remote_hard_delete_refresh_citing_note_only() {
    use loro::CommitOptions;
    for remote in [false, true] {
        let (_dir, server) = test_server();
        let (source, citing, other) = seed_reactive_citation(&server, 0x1437_0050);
        // Drain the document relay from fixture creation before subscribing;
        // only the subsequent erasure belongs to these retained reads.
        tokio::task::yield_now().await;
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let other_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut read = open_local_reactive_read(
            &server,
            ReactiveNotePins {
                id: citing,
                dependencies: [ReactiveDependency::Doc(citing)],
                reads: reads.clone(),
            },
        )
        .unwrap();
        let mut other_read = open_local_reactive_read(
            &server,
            ReactiveNotePins {
                id: other,
                dependencies: [ReactiveDependency::Doc(other)],
                reads: other_reads.clone(),
            },
        )
        .unwrap();
        assert_eq!(read.snapshot().pins.len(), 1);
        if remote {
            let window = oneiron::sync::WindowKey::from_timestamp(
                server.vault().get_learned_at(&source).unwrap(),
            );
            let doc = server.get_or_create_window(&window).await.unwrap();
            let mut tombstone = vec![2u8];
            tombstone.extend_from_slice(&1_770_000_000u64.to_le_bytes());
            tombstone.extend_from_slice(&[9u8; 16]);
            doc.get_map("tombstones")
                .insert(&source.to_hex(), tombstone.as_slice())
                .unwrap();
            doc.commit_with(CommitOptions::new().origin("conn:7"));
        } else {
            server
                .vault()
                .delete_entity_with_reason(&source, oneiron::DeleteReason::UserHardDelete)
                .unwrap();
        }
        let current =
            tokio::time::timeout(std::time::Duration::from_secs(5), read.refresh_on_change())
                .await
                .expect("citing NOTE notice")
                .expect("citing read");
        assert_eq!(current, &server.vault().note_document(citing).unwrap());
        assert!(current.pins.is_empty());
        assert_eq!(reactive_reads(&reads), 2);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                other_read.refresh_on_change()
            )
            .await
            .is_err(),
            "unrelated NOTE must not re-read"
        );
        assert_eq!(reactive_reads(&other_reads), 1);
    }
}

struct ReactiveEdgeFlags {
    id: oneiron::EntityId,
    incoming: bool,
    dependencies: [ReactiveDependency; 1],
    reads: Arc<std::sync::atomic::AtomicUsize>,
}
impl ReactiveLocalQuery for ReactiveEdgeFlags {
    type Output = Vec<(
        oneiron::EntityId,
        Option<oneiron::edge::EdgeProvenanceFlags>,
    )>;
    fn dependencies(&self) -> &[ReactiveDependency] {
        &self.dependencies
    }
    fn read(&self, vault: &oneiron::Vault) -> oneiron::Result<Self::Output> {
        self.reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(if self.incoming {
            vault.edges_in(&self.id)?
        } else {
            vault.edges_out(&self.id)?
        }
        .into_iter()
        .filter(|edge| edge.kind == oneiron::EdgeKind::Mentions)
        .map(|edge| (edge.target, edge.provenance))
        .collect())
    }
}

#[tokio::test]
async fn local_and_remote_provenance_deletes_refresh_both_edge_endpoints() {
    use loro::CommitOptions;
    for remote in [false, true] {
        for hard in [false, true] {
            let (_dir, server) = test_server();
            let source = seeded_test_entity_id(0x1437_0060);
            let target = seeded_test_entity_id(0x1437_0061);
            let other = seeded_test_entity_id(0x1437_0062);
            let other_target = seeded_test_entity_id(0x1437_0063);
            for id in [source, target, other, other_target] {
                server
                    .vault()
                    .put_entity(
                        &id,
                        oneiron::registry::ENTITY_TYPE_PERSON,
                        oneiron::TimeRange { start: 1, end: 1 },
                        1,
                        b"provenance endpoint",
                    )
                    .unwrap();
            }
            server
                .vault()
                .put_edge(&source, oneiron::EdgeKind::Mentions, &target, 0.5)
                .unwrap();
            server
                .vault()
                .put_edge(&other, oneiron::EdgeKind::Mentions, &other_target, 0.5)
                .unwrap();
            let claim = seeded_test_entity_id(0x1437_0064);
            let subject =
                oneiron::provenance::EdgeRef::new(source, oneiron::EdgeKind::Mentions, target);
            server
                .vault()
                .put_edge_provenance(
                    &claim,
                    &subject,
                    &oneiron::provenance::EdgeProvenanceClaimBody::new(
                        source,
                        0.8,
                        oneiron::provenance::SupersessionStatus::Confirmed,
                    ),
                    oneiron::EdgeActorClass::Human,
                    100,
                )
                .unwrap();
            let output_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let input_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let other_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut out = open_local_reactive_read(
                &server,
                ReactiveEdgeFlags {
                    id: source,
                    incoming: false,
                    dependencies: [ReactiveDependency::Doc(source)],
                    reads: output_reads.clone(),
                },
            )
            .unwrap();
            let mut inn = open_local_reactive_read(
                &server,
                ReactiveEdgeFlags {
                    id: target,
                    incoming: true,
                    dependencies: [ReactiveDependency::Doc(target)],
                    reads: input_reads.clone(),
                },
            )
            .unwrap();
            let mut untouched = open_local_reactive_read(
                &server,
                ReactiveEdgeFlags {
                    id: other,
                    incoming: false,
                    dependencies: [ReactiveDependency::Doc(other)],
                    reads: other_reads.clone(),
                },
            )
            .unwrap();
            assert!(out.snapshot().iter().any(|(_, flags)| flags.is_some()));
            assert!(inn.snapshot().iter().any(|(_, flags)| flags.is_some()));
            if remote {
                let window = oneiron::sync::WindowKey::from_timestamp(
                    server.vault().get_learned_at(&claim).unwrap(),
                );
                let doc = server.get_or_create_window(&window).await.unwrap();
                let mut tombstone = vec![if hard { 2u8 } else { 1u8 }];
                tombstone.extend_from_slice(&1_770_000_000u64.to_le_bytes());
                tombstone.extend_from_slice(&[8u8; 16]);
                doc.get_map("tombstones")
                    .insert(&claim.to_hex(), tombstone.as_slice())
                    .unwrap();
                doc.commit_with(CommitOptions::new().origin("conn:7"));
            } else {
                server
                    .vault()
                    .delete_entity_with_reason(
                        &claim,
                        if hard {
                            oneiron::DeleteReason::UserHardDelete
                        } else {
                            oneiron::DeleteReason::UserDelete
                        },
                    )
                    .unwrap();
            }
            for (read, count) in [(&mut out, &output_reads), (&mut inn, &input_reads)] {
                let current = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    read.refresh_on_change(),
                )
                .await
                .expect("subject edge endpoint notice")
                .expect("read");
                assert!(current.iter().all(|(_, flags)| flags.is_none()));
                assert_eq!(reactive_reads(count), 2);
            }
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    untouched.refresh_on_change()
                )
                .await
                .is_err()
            );
            assert_eq!(reactive_reads(&other_reads), 1);
        }
    }
}
