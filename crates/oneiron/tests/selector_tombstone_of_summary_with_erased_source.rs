//! A band-narrowed federation selector window carries the delete of an epoch
//! summary whose source was erased first (FIX-LIST
//! SELECTOR-TOMBSTONE-JUDGED-BY-WORD-SOURCES), public API and test doors only.
//!
//! The vault holds an unstamped CLAIM C and an epoch summary S written from
//! it. A member P holds a live Member federation grant whose Scope admits
//! every record, and P's selector names one band, the conversation family
//! S belongs to. A band filter turns off the open fallback that carries the
//! tombstone of a row the export does not keep (`sync/selector/tombstones.rs`),
//! so S's tombstone rides P's window only when the export keeps S.
//!
//! The window the vault exports holds S's body beside S's tombstone, as a
//! window does that merged a peer's delete over a body it still held: a peer
//! vault whose owner deleted S gives the tombstone. S stays live here. A row
//! this vault itself marked deleted is withheld from every export whole
//! (`withdrawn_delete_carriers`), so only such a window brings a tombstoned
//! body to the member gate.
//!
//! While C reads, the export keeps S and its tombstone rides. The owner then
//! erases C with a plain delete, which leaves a header-only CLAIM shell and
//! keeps S's `DerivedFrom` edge. The member gate's word-source walk
//! (`member_reads_word_sources` in `sync/selector/authorize/filter.rs`) reads
//! the shell as a claim that does not decode and refuses S. It judged a
//! tombstoned row too, so the export dropped S and with it S's tombstone: P
//! keeps a row the owner deleted. A tombstone carries no words, so a deleted
//! row now skips the walk; the label gate and the tombstone pass's capture
//! check still judge it.
//!
//! Two guards pin the other side: the same window through P's open selector
//! carries the tombstone (the fallback, on the base too), and a co-Owner's
//! band-narrowed window carries it.
//!
//! The epoch summary is a stored SUMMARY row in the pinned epoch codec, with
//! its `DerivedFrom` edge, written through the public put: no compaction run,
//! no model. Each `FIXTURE:` assertion checks the setup, never the defect.
//! The `MISSED-DELETE:` assertion comes last.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_tombstone_of_summary_with_erased_source`.
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    SelectorRange,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY, TypeByteFamily};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::{load_window_from_state, reverse_rematerialize};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc,
    put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, DeleteReason,
    EPOCH_SUMMARY_BODY_KEYS, EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL, EdgeKind, EntityId,
    Vault, VaultConfig, decode_epoch_summary_body,
};
use oneiron_authority::federation::scope_codec::read_preset;
use rmpv::Value;

/// The shared vault the federation grant names.
const SHARED_VAULT_ID: u64 = 7;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// One stated, unstamped CLAIM about `subject` holding `text` and learned at
/// `now`, as `selector_nested_epoch_word_sources.rs` seeds one.
fn seed_claim(vault: &Vault, subject: EntityId, text: &str, now: u64) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        Value::from(text),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    vault.put_claim(&id, &body, at(now), now).expect("a record");
    id
}

/// The body of one epoch summary of `session`'s log, epoch `epoch`, holding
/// `text`: the pinned epoch codec, its keys in `EPOCH_SUMMARY_BODY_KEYS`
/// order.
fn epoch_body(session: EntityId, epoch: u64, text: &str) -> Vec<u8> {
    let values = [
        Value::from(EPOCH_SUMMARY_BODY_VERSION),
        Value::from(session.to_hex()),
        Value::Nil,
        Value::from(epoch),
        Value::from(1_u64),
        Value::from(1_u64),
        Value::from(EPOCH_SUMMARY_LEVEL),
        Value::from(text),
        Value::from(EntityId::now().to_hex()),
    ];
    let body = Value::Map(
        EPOCH_SUMMARY_BODY_KEYS
            .iter()
            .map(|key| Value::from(*key))
            .zip(values)
            .collect(),
    );
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("an epoch summary body");
    let decoded = decode_epoch_summary_body(&bytes)
        .expect("FIXTURE: the body decodes under the strict epoch codec");
    assert_eq!(decoded.epoch, epoch, "FIXTURE: the body is epoch {epoch}");
    bytes
}

/// Keeps `doc` as the vault's own window `key`, as the engine persists a
/// window: its snapshot and version vector.
fn persist_window(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    let window = key.as_str();
    vault
        .sync_state_put(
            &format!("d:w:{window}"),
            &doc.export(ExportMode::Snapshot).expect("window snapshot"),
        )
        .expect("FIXTURE: the window snapshot is kept");
    vault
        .sync_state_put(&format!("sv:w:{window}"), &doc.oplog_vv().encode())
        .expect("FIXTURE: the window version is kept");
    vault
        .sync_state_put(&format!("svf:w:{window}"), &[1_u8])
        .expect("FIXTURE: the window version flag is kept");
}

/// The bytes the window map `name` of `doc` holds under `key`.
fn window_bytes(doc: &LoroDoc, name: &str, key: &str) -> Vec<u8> {
    match doc.get_map(name).get(key) {
        Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => bytes.to_vec(),
        _ => panic!("FIXTURE: the window's {name} map holds bytes under {key}"),
    }
}

/// The tombstone a peer vault's window carries of the epoch summary `id`
/// with body `body` once its owner deletes it: the peer holds the same row,
/// packs and keeps its window, and purges the row.
fn peer_tombstone_of(id: EntityId, body: &[u8]) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("tempdir");
    let peer =
        open_member_vault(dir.path(), VaultConfig::device(), &[]).expect("FIXTURE: the peer vault");
    peer.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let now = peer.now_recorded_at();
    peer.put_entity(&id, ENTITY_TYPE_SUMMARY, at(now), now, body)
        .expect("FIXTURE: the peer's epoch summary");
    let key = WindowKey::from_timestamp(now);
    let packed = create_window_doc("selector", &key);
    reverse_rematerialize(&peer, &packed, &key).expect("FIXTURE: the peer's window pack");
    persist_window(&peer, &packed, &key);
    assert!(
        peer.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
            .expect("FIXTURE: the peer owner's delete")
            .existed,
        "FIXTURE: the peer's epoch summary existed"
    );
    let window = load_window_from_state(&peer, "local", &key).expect("FIXTURE: the peer's window");
    window_bytes(&window, "tombstones", &id.to_hex())
}

/// Whether each export carried the epoch summary's tombstone.
struct Carried {
    /// P's band-narrowed window while the summary's source reads.
    banded_with_live_source: bool,
    /// P's open window after the source's erase.
    open_after_erase: bool,
    /// P's band-narrowed window after the source's erase.
    banded_after_erase: bool,
}

/// Plants the unstamped claim and the epoch summary written from it, gives
/// the member a live federation grant of `role` whose Scope admits every
/// record, builds a window that holds the summary's body beside a peer's
/// tombstone of it, and exports that window through the member's open and
/// band-narrowed selectors, before and after the owner erases the claim.
fn export_through(role: FederationGrantRole, preset: FederationGrantPreset) -> Carried {
    let dir = tempfile::tempdir().expect("tempdir");
    let member = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("fixture vault");
    // The erase signs as this install first, so the vault needs the keystore
    // a host installs after each open.
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    // Every row is learned now, so all of them pack into one window.
    let now = vault.now_recorded_at();
    let person_body =
        rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" })).expect("body");
    vault
        .put_entity(&member, ENTITY_TYPE_PERSON, at(now), now, &person_body)
        .expect("a member PERSON");
    // The claim's subject: `put_claim` refuses a subject that does not exist.
    let subject = EntityId::now();
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at(now), now, &person_body)
        .expect("the claim's subject");

    let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(scope, member, role, preset);
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
        .expect("the member's federation grant");
    let open = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    // SUMMARY's band: the conversation family.
    let banded = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![],
        vec![SelectorRange::Family(TypeByteFamily::Conversation)],
    );
    for selector in [&open, &banded] {
        authorize_sync_selector(&vault, scope, selector)
            .expect("FIXTURE: the member's selector is authorized");
    }

    let claim = seed_claim(&vault, subject, "an unstamped note", now);
    let summary = EntityId::now();
    let body = epoch_body(
        EntityId::now(),
        1,
        "the first epoch retells an unstamped note",
    );
    vault
        .put_entity(&summary, ENTITY_TYPE_SUMMARY, at(now), now, &body)
        .expect("an epoch summary");
    vault
        .put_edge(&summary, EdgeKind::DerivedFrom, &claim, 1.0)
        .expect("the epoch's DerivedFrom edge");
    // A row with no birth stamp rides no selector window at all, which would
    // make every assertion below vacuous.
    for id in [claim, summary] {
        assert!(
            vault
                .record_scope(&id)
                .expect("record scope read")
                .is_some(),
            "FIXTURE: {} holds its birth stamp",
            id.to_hex()
        );
    }

    let key = WindowKey::from_timestamp(now);
    let packed = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &packed, &key).expect("the window pack");
    let summary_blob = window_bytes(&packed, "entities", &summary.to_hex());
    let tombstone = peer_tombstone_of(summary, &body);

    // The summary's body under its canonical key beside the peer's tombstone.
    let window = create_window_doc("selector", &key);
    window
        .get_map("entities")
        .insert(&summary.to_hex(), summary_blob.as_slice())
        .expect("FIXTURE: the window holds the summary's body");
    window
        .get_map("tombstones")
        .insert(&summary.to_hex(), tombstone.as_slice())
        .expect("FIXTURE: the window holds the summary's tombstone");
    window.commit();
    let carries = |selector: &SyncSelector| {
        filtered_window_doc(&vault, &window, &key, scope, selector)
            .expect("the member's selector window")
            .get_map("tombstones")
            .get(&summary.to_hex())
            .is_some()
    };
    let banded_with_live_source = carries(&banded);

    // A plain delete: the claim keeps a header-only shell and the summary's
    // `DerivedFrom` edge to it.
    assert!(
        vault
            .delete_entity_with_reason(&claim, DeleteReason::UserDelete)
            .expect("FIXTURE: the owner's erase")
            .existed,
        "FIXTURE: the erased claim existed"
    );
    assert!(
        vault
            .record_scope(&summary)
            .expect("record scope read")
            .is_some(),
        "FIXTURE: the epoch summary is still held here after its source's erase"
    );
    Carried {
        banded_with_live_source,
        open_after_erase: carries(&open),
        banded_after_erase: carries(&banded),
    }
}

#[test]
fn a_band_narrowed_members_window_carries_the_delete_of_an_epoch_whose_source_was_erased_first() {
    let carried = export_through(FederationGrantRole::Member, FederationGrantPreset::Member);
    assert!(
        carried.banded_with_live_source,
        "FIXTURE: the Member's band-narrowed window carries the epoch summary's tombstone while \
         its source reads"
    );
    assert!(
        carried.open_after_erase,
        "FIXTURE: the Member's open window carries the epoch summary's tombstone after its \
         source's erase"
    );
    assert!(
        carried.banded_after_erase,
        "MISSED-DELETE: the Member's band-narrowed window drops the tombstone of an epoch summary \
         whose source was erased first, so the member keeps a row the owner deleted"
    );
}

#[test]
fn a_co_owners_band_narrowed_window_carries_the_same_delete() {
    let carried = export_through(FederationGrantRole::Owner, FederationGrantPreset::Owner);
    let withheld: Vec<&str> = [
        (
            carried.banded_with_live_source,
            "band-narrowed, source live",
        ),
        (carried.open_after_erase, "open, source erased"),
        (carried.banded_after_erase, "band-narrowed, source erased"),
    ]
    .into_iter()
    .filter(|(carried, _)| !carried)
    .map(|(_, export)| export)
    .collect();
    assert!(
        withheld.is_empty(),
        "OVER-REFUSAL: the co-Owner's window withholds the epoch summary's tombstone in the \
         {withheld:?} export"
    );
}
