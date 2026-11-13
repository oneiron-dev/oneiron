//! A federation selector window carries no tombstone of a relationship row
//! its member does not read (OPUS-LEAKS round 3, FIX-LIST
//! SELECTOR-TOMBSTONE-LABEL).
//!
//! The fixture is the one of `tests/selector_relationship_label.rs`: a member
//! P holds a live Member federation grant whose Scope admits every record,
//! and a `core:read` policy grant, but no grant on a relationship R and no
//! membership in it. P's own read lane reads an open CLAIM and neither of
//! two CLAIMs keyed to R. The test packs the window and keeps it as the
//! vault's own, then the owner deletes the open CLAIM and one R CLAIM (a
//! plain delete, which keeps a shell) and purges the other R CLAIM (a hard
//! delete). It exports the vault's window through P's selector.
//!
//! An open, All-world selector carries the tombstone of a row it does not
//! keep (`sync/selector/tombstones.rs`), and the label gate of round 2
//! judges rows only, so it never withholds their tombstones. A tombstone
//! names the row's id, the delete's reason, its time and its request. The
//! open CLAIM's tombstone rides P's window; the test asserts no R CLAIM's
//! tombstone does.
//!
//! A second test gives the same grant the Owner role: a co-Owner reads the
//! whole vault, so both R tombstones ride its window. It guards the fix
//! against refusing an Owner.
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The `LEAK:`
//! assertion comes last.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test selector_tombstone_label`.
// `put_selector_test_federation_grant` exists only under `test-hooks`.
#![cfg(all(oneiron_test_support, feature = "test-hooks"))]

use loro::{ExportMode, LoroDoc};
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
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::write_envelope::claim_body::relationship_scope_of;
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

/// The R CLAIMs one selector export saw deleted, and whether the window
/// carried each one's tombstone.
struct Export {
    /// Each deleted R CLAIM with how it was deleted, and whether its
    /// tombstone rode the window.
    labelled: [(&'static str, bool); 2],
}

/// Plants the open CLAIM and the two R CLAIMs, gives `member` a live
/// federation grant of `role` whose Scope admits every record, keeps the
/// packed window as the vault's own, deletes the three CLAIMs, and exports
/// the vault's window through the member's selector. With
/// `check_read_lane`, the fixture first checks that the member's own read
/// lane reads the open CLAIM and neither R CLAIM.
fn export_through(
    role: FederationGrantRole,
    preset: FederationGrantPreset,
    check_read_lane: bool,
) -> Export {
    let dir = tempfile::tempdir().expect("tempdir");
    let member = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[member.to_hex()])
        .expect("fixture vault");
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
    let shell_claim = record(&vault, member, Some(relationship), now);
    let purged_claim = record(&vault, member, Some(relationship), now);

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
            !reads(shell_claim) && !reads(purged_claim),
            "FIXTURE: the member reads neither R CLAIM"
        );
    }

    let key = WindowKey::from_timestamp(now);
    let packed = create_window_doc("selector", &key);
    reverse_rematerialize(&vault, &packed, &key).expect("the window pack");
    for id in [open_claim, shell_claim, purged_claim] {
        assert!(
            packed.get_map("entities").get(&id.to_hex()).is_some(),
            "FIXTURE: the packed window holds {}",
            id.to_hex()
        );
    }
    persist_window(&vault, &packed, &key);

    for (id, reason) in [
        (open_claim, DeleteReason::UserDelete),
        (shell_claim, DeleteReason::UserDelete),
        (purged_claim, DeleteReason::UserHardDelete),
    ] {
        assert!(
            vault
                .delete_entity_with_reason(&id, reason)
                .expect("FIXTURE: the owner's delete")
                .existed,
            "FIXTURE: the deleted CLAIM existed"
        );
    }
    let window = load_window_from_state(&vault, "local", &key).expect("the vault's window");
    for id in [open_claim, shell_claim, purged_claim] {
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
    Export {
        labelled: [
            ("deleted R CLAIM", carries(shell_claim)),
            ("purged R CLAIM", carries(purged_claim)),
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
