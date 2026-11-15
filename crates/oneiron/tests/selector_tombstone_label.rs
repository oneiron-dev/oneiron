//! A federation selector window carries no tombstone of a relationship row
//! its member does not read (OPUS-LEAKS round 3, FIX-LIST
//! SELECTOR-TOMBSTONE-LABEL).
//!
//! The fixture is the one of `tests/selector_relationship_label.rs`: a member
//! P holds a live Member federation grant whose Scope admits every record,
//! and a `core:read` policy grant, but no grant on a relationship R and no
//! membership in it. P's own read lane reads an open CLAIM and not a CLAIM
//! keyed to R. The test packs the window and keeps it as the vault's own,
//! then the owner purges both CLAIMs (a hard delete). It exports the vault's
//! window through P's selector.
//!
//! An open, All-world selector carries the tombstone of a row it does not
//! keep (`sync/selector/tombstones.rs`), and the label gate of round 2
//! judges rows only, so it never withholds their tombstones. A tombstone
//! names the row's id, the delete's reason, its time and its request. The
//! open CLAIM's tombstone rides P's window; the test asserts the R CLAIM's
//! tombstone does not.
//!
//! The fixture also lands two PERSON rows through the sync replay door, as
//! rows from the owner's other device land: one open, and one whose
//! `source_audience` names R. A replicated row other than a CLAIM takes no
//! record-scope stamp (FIX 11925), so the relationship gate withholds the R
//! PERSON from P for want of a scope, and its delete has no scope to capture
//! (FIX-LIST SELECTOR-TOMBSTONE-UNSCOPED-ROW-NO-CAPTURE). The owner purges
//! both. The open PERSON's tombstone rides P's window; the test asserts the
//! R PERSON's tombstone does not.
//!
//! Both deletes are hard. A plain delete keeps a header-only CLAIM shell and
//! the shell's window edges, so `withheld_claim_carriers` reads the shell as
//! a CLAIM whose body does not decode, and the export withholds its
//! tombstone from every member, an Owner too (FIX-LIST
//! SELECTOR-SOFT-DELETED-CLAIM-TOMBSTONE-WITHHELD). That path carries no
//! tombstone, so it cannot leak one.
//!
//! A second test gives the same grant the Owner role: a co-Owner reads the
//! whole vault, so both R tombstones ride its window. It guards the fix
//! against refusing an Owner.
//!
//! A third test builds the window from a peer's bytes. A peer vault packs
//! both CLAIMs and purges them. This vault never held either row, so no
//! delete of its own captured a relationship read, and the window it exports
//! carries each body under an UPPERCASE alias of the row's id and each
//! tombstone under the canonical lowercase id. A case-shifted key still names
//! the row (ONE-1158), so the body under it decides: the open CLAIM's
//! tombstone rides, and the R CLAIM's does not.
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The `LEAK:`
//! assertion comes last.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_tombstone_label`.
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::window::{load_window_from_state, reverse_rematerialize};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, authorize_sync_selector, filtered_window_doc,
    put_selector_test_federation_grant,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::{open_member_vault, put_replicated_row};
use oneiron::write_envelope::claim_body::{encode_relationship_scope, relationship_scope_of};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, DeleteReason,
    EntityId, Vault, VaultConfig,
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

/// A stated CLAIM about `subject` learned at `now`, keyed to `relationship`
/// when one is named.
fn record(vault: &Vault, subject: EntityId, relationship: Option<EntityId>, now: u64) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("a profile fact"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    body.rel = relationship_scope_of(relationship);
    vault.put_claim(&id, &body, at(now), now).expect("a record");
    id
}

/// A PERSON from the owner's other device, landed through the sync replay
/// door, so it has no record-scope stamp here (FIX 11925). With
/// `relationship`, its `source_audience` names it, as a provisional confirm
/// writes for a name said only there.
fn replicated_person(vault: &Vault, relationship: Option<EntityId>, now: u64) -> EntityId {
    let id = EntityId::now();
    let mut fields = vec![(Value::from("name"), Value::from("Yuki"))];
    if let Some(relationship) = relationship {
        fields.push((
            Value::from("source_audience"),
            Value::Map(vec![
                (
                    Value::from("rel"),
                    encode_relationship_scope(relationship_scope_of(Some(relationship)).as_ref()),
                ),
                (Value::from("private"), Value::Boolean(false)),
            ]),
        ));
    }
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Map(fields)).expect("PERSON body");
    put_replicated_row(vault, &id, ENTITY_TYPE_PERSON, now, &body)
        .expect("FIXTURE: the replicated PERSON lands");
    id
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

/// The R rows one selector export saw purged, and whether the window
/// carried each one's tombstone.
struct Export {
    /// The purged R CLAIM and R PERSON, and whether each tombstone rode the
    /// window.
    labelled: [(&'static str, bool); 2],
}

/// Plants the open CLAIM and the R CLAIM, lands the open PERSON and the R
/// PERSON through the sync replay door, gives `member` a live federation
/// grant of `role` whose Scope admits every record, keeps the packed window
/// as the vault's own, purges all four rows, and exports the vault's window
/// through the member's selector. With `check_read_lane`, the fixture first
/// checks that the member's own read lane reads the open CLAIM and neither
/// the R CLAIM nor the R PERSON.
fn export_through(
    role: FederationGrantRole,
    preset: FederationGrantPreset,
    check_read_lane: bool,
) -> Export {
    let dir = tempfile::tempdir().expect("tempdir");
    let member = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("fixture vault");
    // Every delete signs as this install first, so the vault needs the
    // keystore a host installs after each open.
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    // Every row is learned now, so all of them sit in one window.
    let now = vault.now_recorded_at();
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            at(now),
            now,
            b"relationship",
        )
        .expect("a relationship");
    vault
        .put_entity(
            &member,
            ENTITY_TYPE_PERSON,
            at(now),
            now,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" })).expect("body"),
        )
        .expect("a member outside the relationship");

    let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(scope, member, role, preset);
    // Both roles export under the same Scope, so the role is the only
    // difference between the two tests.
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
        .expect("the member's federation grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, scope, &selector)
        .expect("FIXTURE: the member's selector is authorized");

    let open_claim = record(&vault, member, None, now);
    let purged_claim = record(&vault, member, Some(relationship), now);
    let open_person = replicated_person(&vault, None, now);
    let purged_person = replicated_person(&vault, Some(relationship), now);

    let reads = |id: EntityId| {
        vault
            .memory(member, EdgeActorClass::Human)
            .get_entity(&id.to_hex())
            .expect("member read")
            .value
            .is_some()
    };
    if check_read_lane {
        assert!(
            reads(open_claim),
            "FIXTURE: the member reads the open CLAIM"
        );
        assert!(
            !reads(purged_claim),
            "FIXTURE: the member does not read the R CLAIM"
        );
        assert!(
            !reads(purged_person),
            "FIXTURE: the member does not read the R PERSON"
        );
    }

    let key = WindowKey::from_timestamp(now);
    let packed = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &packed, &key).expect("the window pack");
    for id in [open_claim, purged_claim] {
        assert!(
            packed.get_map("entities").get(&id.to_hex()).is_some(),
            "FIXTURE: the packed window holds {}",
            id.to_hex()
        );
    }
    persist_window(&vault, &packed, &key);

    // Hard deletes only: a plain delete's CLAIM shell withholds the
    // tombstone from every member (see the module doc).
    let purged = [open_claim, purged_claim, open_person, purged_person];
    for id in purged {
        assert!(
            vault
                .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
                .expect("FIXTURE: the owner's delete")
                .existed,
            "FIXTURE: the purged row {} existed",
            id.to_hex()
        );
    }
    let window = load_window_from_state(&vault, "local", &key).expect("the vault's window");
    for id in purged {
        assert!(
            window.get_map("tombstones").get(&id.to_hex()).is_some(),
            "FIXTURE: the vault's window holds the tombstone of {}",
            id.to_hex()
        );
    }

    let selected = filtered_window_doc(&vault, &window, &key, scope, &selector)
        .expect("the member's selector window");
    let carries = |id: EntityId| selected.get_map("tombstones").get(&id.to_hex()).is_some();
    assert!(
        carries(open_claim),
        "FIXTURE: the selector window carries the open CLAIM's tombstone"
    );
    assert!(
        carries(open_person),
        "FIXTURE: the selector window carries the open PERSON's tombstone"
    );
    Export {
        labelled: [
            ("purged R CLAIM", carries(purged_claim)),
            ("purged R PERSON", carries(purged_person)),
        ],
    }
}

#[test]
fn a_selector_window_carries_no_tombstone_of_a_relationship_row_its_member_does_not_read() {
    let export = export_through(
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
        true,
    );
    let leaked: Vec<&str> = export
        .labelled
        .into_iter()
        .filter(|(_, carried)| *carried)
        .map(|(kind, _)| kind)
        .collect();
    assert!(
        leaked.is_empty(),
        "LEAK: the selector window carries the tombstone of the {leaked:?} to a member who does not read R"
    );
}

#[test]
fn a_co_owners_selector_window_carries_the_relationship_tombstones() {
    let export = export_through(
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
        false,
    );
    let withheld: Vec<&str> = export
        .labelled
        .into_iter()
        .filter(|(_, carried)| !*carried)
        .map(|(kind, _)| kind)
        .collect();
    assert!(
        withheld.is_empty(),
        "OVER-REFUSAL: the selector window withholds the tombstone of the {withheld:?} from a co-Owner"
    );
}

/// The bytes the window map `name` of `doc` holds under `key`.
fn window_bytes(doc: &LoroDoc, name: &str, key: &str) -> Vec<u8> {
    match doc.get_map(name).get(key) {
        Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => bytes.to_vec(),
        _ => panic!("FIXTURE: the window's {name} map holds bytes under {key}"),
    }
}

/// What a peer vault's window carried of one CLAIM its owner purged: the
/// row's id, the body the window packed while the row was live, and the
/// tombstone the purge wrote.
struct PeerPurge {
    id: EntityId,
    body: Vec<u8>,
    tombstone: Vec<u8>,
}

/// Plants an open CLAIM and a CLAIM keyed to `relationship`, both about
/// `member`, in a peer vault; packs and keeps its window; purges both; and
/// returns what that window carried of each, the open CLAIM first.
fn peer_purges(member: EntityId, relationship: EntityId) -> (PeerPurge, PeerPurge) {
    let dir = tempfile::tempdir().expect("tempdir");
    let peer = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("FIXTURE: the peer vault");
    peer.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let now = peer.now_recorded_at();
    peer.put_entity(
        &relationship,
        ENTITY_TYPE_RELATIONSHIP,
        at(now),
        now,
        b"relationship",
    )
    .expect("FIXTURE: the peer's relationship");
    peer.put_entity(
        &member,
        ENTITY_TYPE_PERSON,
        at(now),
        now,
        &rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" })).expect("body"),
    )
    .expect("FIXTURE: the peer's member");
    let open = record(&peer, member, None, now);
    let keyed = record(&peer, member, Some(relationship), now);

    let key = WindowKey::from_timestamp(now);
    let packed = create_window_doc("selector", &key);
    reverse_rematerialize(&peer, &packed, &key).expect("FIXTURE: the peer's window pack");
    let open_body = window_bytes(&packed, "entities", &open.to_hex());
    let keyed_body = window_bytes(&packed, "entities", &keyed.to_hex());
    persist_window(&peer, &packed, &key);
    for id in [open, keyed] {
        assert!(
            peer.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
                .expect("FIXTURE: the peer owner's delete")
                .existed,
            "FIXTURE: the peer's CLAIM existed"
        );
    }
    let window = load_window_from_state(&peer, "local", &key).expect("FIXTURE: the peer's window");
    let tombstone = |id: EntityId| window_bytes(&window, "tombstones", &id.to_hex());
    (
        PeerPurge {
            id: open,
            body: open_body,
            tombstone: tombstone(open),
        },
        PeerPurge {
            id: keyed,
            body: keyed_body,
            tombstone: tombstone(keyed),
        },
    )
}

#[test]
fn a_selector_window_carries_no_tombstone_beside_a_case_shifted_relationship_row_its_member_does_not_read()
 {
    let member = EntityId::now();
    let relationship = EntityId::now();
    let (open, keyed) = peer_purges(member, relationship);

    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("fixture vault");
    let now = vault.now_recorded_at();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            at(now),
            now,
            b"relationship",
        )
        .expect("a relationship");
    vault
        .put_entity(
            &member,
            ENTITY_TYPE_PERSON,
            at(now),
            now,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": "member" })).expect("body"),
        )
        .expect("a member outside the relationship");
    let scope = FederationGrantScope::vault(SHARED_VAULT_ID);
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(
        scope,
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    grant.authority_scope = read_preset();
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
        .expect("the member's federation grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, scope, &selector)
        .expect("FIXTURE: the member's selector is authorized");

    let key = WindowKey::from_timestamp(now);
    let window = create_window_doc("selector", &key);
    for purge in [&open, &keyed] {
        let alias = purge.id.to_hex().to_uppercase();
        assert_ne!(
            alias,
            purge.id.to_hex(),
            "FIXTURE: the alias key differs from the canonical key"
        );
        window
            .get_map("entities")
            .insert(&alias, purge.body.as_slice())
            .expect("FIXTURE: the window holds the body under the alias key");
        window
            .get_map("tombstones")
            .insert(&purge.id.to_hex(), purge.tombstone.as_slice())
            .expect("FIXTURE: the window holds the tombstone");
    }
    window.commit();

    let selected = filtered_window_doc(&vault, &window, &key, scope, &selector)
        .expect("the member's selector window");
    let carries = |id: EntityId| selected.get_map("tombstones").get(&id.to_hex()).is_some();
    assert!(
        carries(open.id),
        "FIXTURE: the selector window carries the open CLAIM's tombstone"
    );
    assert!(
        !carries(keyed.id),
        "LEAK: the selector window carries the tombstone of the R CLAIM whose body it holds under a case-shifted key to a member who does not read R"
    );
}
