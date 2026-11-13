//! L5-17 (the lead's ruling on ASK L5-17-DESIGN, 13 Nov 14:03: A with no
//! refusal): an Owner's copy that someone is owed the audit of writes an
//! owed row before it leaves. When the audit's own write does not commit, a
//! housekeeping pass writes the audit row and the members' notices from it;
//! when even the owed row cannot be written, the copy is still served and
//! the host log names its export id. A solo owner's copy that carries no
//! thread is audited as before. An erase drops the erased person from each
//! owed row.
//!
//! The faults come through `oneiron::test_doors::export_audit_owed`, built
//! only under `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test export_audit_owed_notice`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::inbox::{NotificationBody, decode_notification_body};
use oneiron::registry::{ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::test_doors::export_audit_owed::{
    fail_next_export_audit_write, fail_next_owed_export_audit_write, owed_export_audits,
};
use oneiron::test_doors::inquiry::erase_actor_in_tables_in_order;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use serde_json::json;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// The owned vault, its embedded owner, and the members B and C of a private
/// thread rooted at `root` that the owner is not in.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    member_b: EntityId,
    member_c: EntityId,
    root: EntityId,
    _dir: tempfile::TempDir,
}

/// An owned vault and its embedded owner. `open_owned` holds the writer
/// lease the owner's doors ask for.
fn owned_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    (dir, vault, owner)
}

/// The owner seats B and C in a group room; B opens a thread under its
/// trunk whose audience is B and C alone. The opener must be in the
/// audience, so the owner cannot open it.
fn private_thread() -> Fixture {
    let (dir, vault, owner) = owned_vault();
    let member_b = EntityId::now();
    let member_c = EntityId::now();
    let now = vault.now_recorded_at();
    for member in [member_b, member_c] {
        vault
            .put_entity(
                &member,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"human",
            )
            .expect("a live member PERSON");
    }
    let host = vault.memory(owner, EdgeActorClass::Human);
    let conversation = EntityId::from_hex(
        &host
            .conversations_create(&ConversationCreateInput {
                id: None,
                occurred_start: None,
                occurred_end: None,
                learned_at: None,
                body: json!({
                    "v": 1,
                    "kind": "group",
                    "member_ids": [owner.to_hex(), member_b.to_hex(), member_c.to_hex()],
                    "title": "owed export audit room",
                }),
                text: None,
            })
            .expect("the group room")
            .id,
    )
    .expect("a room id");
    let trunk = EntityId::from_hex(
        &host
            .conversations_records_append(&DagRecordAppendInput {
                conversation: conversation.to_hex(),
                parent: None,
                reply_to: None,
                containing_turn: None,
                addr: None,
                to: None,
                advance: true,
                body: json!({"txt": "the plan", "speaker": "user"}),
                text: None,
                occurred_start: None,
                occurred_end: None,
                learned_at: None,
                session: None,
                quote: None,
                thread_audience: None,
            })
            .expect("the room's trunk TURN")
            .id,
    )
    .expect("a trunk id");
    let opener = vault.memory(member_b, EdgeActorClass::Human);
    let now = vault.now_recorded_at();
    let root = vault
        .reply_in_thread(
            &opener,
            trunk,
            &AppendRecord {
                conversation,
                parent: None,
                reply_to: None,
                quote: None,
                address: AddressMode::Broadcast,
                recipients: Vec::new(),
                advance: false,
                kind: ENTITY_TYPE_TURN,
                containing_turn: None,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                body: rmp_serde::to_vec_named(&json!({"txt": "between us", "speaker": "user"}))
                    .expect("a body"),
                text: Vec::new(),
                session: None,
                actor: WriteActor::new(member_b, EdgeActorClass::Human),
                thread_audience: Some(BTreeSet::from([member_b, member_c])),
            },
        )
        .expect("B opens the private thread")
        .id;
    assert_eq!(
        vault.thread_roots(trunk).expect("thread roots"),
        vec![root],
        "FIXTURE: the private thread hangs off the trunk"
    );
    Fixture {
        vault,
        owner,
        member_b,
        member_c,
        root,
        _dir: dir,
    }
}

/// How many notices of the export `export` of the thread rooted at `root`
/// `person`'s inbox holds.
fn export_notices(vault: &Vault, person: EntityId, root: EntityId, export: EntityId) -> usize {
    let event = format!(
        "vault_exported:{}:{}:{}",
        root.to_hex(),
        export.to_hex(),
        person.to_hex()
    );
    notifications_for(vault, person)
        .into_iter()
        .filter(|body| body.source.producer == "rooms.private_thread" && body.source.event == event)
        .count()
}

/// Every thread export notice in `person`'s inbox, whatever export it names.
fn any_export_notices(vault: &Vault, person: EntityId) -> usize {
    notifications_for(vault, person)
        .into_iter()
        .filter(|body| body.source.detail.as_deref() == Some("vault_exported"))
        .count()
}

/// Every inbox notification addressed to `person`.
fn notifications_for(vault: &Vault, person: EntityId) -> Vec<NotificationBody> {
    vault
        .entities_by_type_page(ENTITY_TYPE_NOTIFICATION, None, 1000)
        .expect("notifications")
        .into_iter()
        .filter_map(|id| vault.get_raw(&id).expect("a notification row"))
        .map(|raw| decode_notification_body(&raw[ENTITY_METADATA_HEADER_LEN..]).expect("a body"))
        .filter(|body| body.recipient.as_deref() == Some(person.to_hex().as_str()))
        .collect()
}

fn housekeeping_pass(vault: &Vault) {
    vault
        .housekeeping_all(HousekeepingBudget::unbounded())
        .expect("the housekeeping pass reads its schedule");
}

/// The fields of every event logged on this thread while it is the
/// default subscriber, as text.
#[derive(Clone, Default)]
struct HostLog(Arc<Mutex<Vec<Vec<(String, String)>>>>);

/// Collects one event's fields.
struct FieldText<'a>(&'a mut Vec<(String, String)>);

impl Visit for FieldText<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push((field.name().to_owned(), format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().to_owned(), value.to_owned()));
    }
}

impl Subscriber for HostLog {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = Vec::new();
        event.record(&mut FieldText(&mut fields));
        self.0.lock().expect("host log").push(fields);
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

impl HostLog {
    /// Whether an event names `export` in its `export` field and says
    /// `words` in its message.
    fn names(&self, export: EntityId, words: &str) -> bool {
        let export = export.to_hex();
        self.0.lock().expect("host log").iter().any(|fields| {
            fields
                .iter()
                .any(|(name, value)| name == "export" && *value == export)
                && fields
                    .iter()
                    .any(|(name, value)| name == "message" && value.contains(words))
        })
    }
}

#[test]
fn a_failed_export_audit_is_delivered_by_the_next_housekeeping_pass() {
    let fx = private_thread();
    fail_next_export_audit_write();
    let copy = fx
        .vault
        .export_whole_vault(true)
        .expect("the Owner's archive is served though its audit write fails");
    assert!(!copy.bytes().is_empty(), "the archive holds the vault");
    assert!(
        fx.vault.export_receipts().expect("receipts").is_empty(),
        "the failed write left no audit row yet"
    );
    assert_eq!(
        any_export_notices(&fx.vault, fx.member_b),
        0,
        "the failed write told B nothing yet"
    );

    housekeeping_pass(&fx.vault);

    let receipts = fx.vault.export_receipts().expect("receipts");
    assert_eq!(
        receipts.len(),
        1,
        "the next housekeeping pass writes the audit row the failed write left owed"
    );
    let receipt = &receipts[0];
    assert_eq!(receipt.exporter, fx.owner);
    assert_eq!(
        receipt.bytes,
        Some(u64::try_from(copy.bytes().len()).unwrap())
    );
    for member in [fx.member_b, fx.member_c] {
        assert_eq!(
            export_notices(&fx.vault, member, fx.root, receipt.export),
            1,
            "the pass tells each member of the private thread of that export, once"
        );
    }
    assert!(
        owed_export_audits(&fx.vault).expect("owed rows").is_empty(),
        "the pass drops the owed row it wrote"
    );

    housekeeping_pass(&fx.vault);
    assert_eq!(
        fx.vault.export_receipts().expect("receipts").len(),
        1,
        "a later pass writes the row no more"
    );
    assert_eq!(
        export_notices(&fx.vault, fx.member_b, fx.root, receipt.export),
        1
    );
}

#[test]
fn an_export_whose_owed_row_is_not_written_is_served_and_host_logged() {
    let fx = private_thread();
    let log = HostLog::default();
    fail_next_owed_export_audit_write();
    let copy = tracing::subscriber::with_default(log.clone(), || fx.vault.export_whole_vault(true))
        .expect("the Owner's archive is served though its owed row is not written");
    assert!(!copy.bytes().is_empty(), "the archive holds the vault");
    let receipts = fx.vault.export_receipts().expect("receipts");
    assert_eq!(
        receipts.len(),
        1,
        "the audit write itself still runs, best effort"
    );
    let export = receipts[0].export;
    assert!(
        log.names(export, "the owed row was not written"),
        "the host log names the export whose owed row was not written"
    );
    assert!(
        owed_export_audits(&fx.vault).expect("owed rows").is_empty(),
        "no owed row stands"
    );
    assert_eq!(export_notices(&fx.vault, fx.member_b, fx.root, export), 1);
}

#[test]
fn a_solo_owner_export_with_no_one_owed_is_unchanged() {
    let (_dir, vault, _owner) = owned_vault();
    let now = vault.now_recorded_at();
    vault
        .put_entity(
            &EntityId::now(),
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"human",
        )
        .expect("a row to export");
    fail_next_export_audit_write();
    let copy = vault
        .export_whole_vault(true)
        .expect("the solo owner's archive is served though its audit write fails");
    assert!(!copy.bytes().is_empty(), "the archive holds the vault");
    assert!(
        owed_export_audits(&vault).expect("owed rows").is_empty(),
        "no one is owed the audit of a solo owner's copy that carries no thread"
    );
    housekeeping_pass(&vault);
    assert!(
        vault.export_receipts().expect("receipts").is_empty(),
        "its audit stays best effort: the failed write is not written later"
    );

    let copy = vault.export_whole_vault(true).expect("the next archive");
    let receipts = vault.export_receipts().expect("receipts");
    assert_eq!(
        receipts.len(),
        1,
        "an export whose write commits has its row"
    );
    assert_eq!(
        receipts[0].bytes,
        Some(u64::try_from(copy.bytes().len()).unwrap())
    );
    assert!(owed_export_audits(&vault).expect("owed rows").is_empty());
}

#[test]
fn an_erased_member_leaves_no_id_in_an_owed_row() {
    let fx = private_thread();
    fail_next_export_audit_write();
    fx.vault
        .export_whole_vault(true)
        .expect("the Owner's archive is served though its audit write fails");
    let owed = owed_export_audits(&fx.vault).expect("owed rows");
    assert_eq!(owed.len(), 1, "the failed audit write left its owed row");
    let (export, named) = owed.into_iter().next().unwrap();
    assert_eq!(
        named,
        BTreeSet::from([fx.member_b, fx.member_c]),
        "the owed row keeps the thread's binding as the copy read it"
    );

    let ran = erase_actor_in_tables_in_order(&fx.vault, &fx.member_b, &["EXPORT_AUDIT_OWED"])
        .expect("erase");
    assert_eq!(ran, 1, "the owed table registers an actor scrub");
    let owed = owed_export_audits(&fx.vault).expect("owed rows");
    assert_eq!(
        owed.get(&export),
        Some(&BTreeSet::from([fx.member_c])),
        "B's erase leaves no id of B in the owed row"
    );

    housekeeping_pass(&fx.vault);
    let receipts = fx.vault.export_receipts().expect("receipts");
    assert_eq!(receipts.len(), 1, "the pass still writes the audit row");
    assert_eq!(receipts[0].export, export);
    assert_eq!(
        export_notices(&fx.vault, fx.member_c, fx.root, export),
        1,
        "the pass still tells C"
    );
}
