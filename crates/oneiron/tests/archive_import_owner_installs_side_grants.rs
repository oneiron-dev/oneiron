#![cfg(oneiron_test_support)]
//! The owner's restore installs held grant and consent side tables live (SIDE-4b).
//!
//! Public doors only; neutral fixtures (`owen`, `yuki`); vaults in tempdirs. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as in
//! `archive_import_retained_side_rows.rs`.
//!
//! * `the_owner_restore_installs_the_room_admin_grant_and_a_repeat_reports_it_unchanged`
//!   (sync-gated): the owner import installs one CONVERSATION_ROLE_GRANT row live, the
//!   grantee's Admin-only act (managing another member's room records) succeeds on the
//!   destination while a Member's stays refused, and a repeat owner import reports one
//!   unchanged live row. The destination is preseeded through public doors plus one window
//!   sync (see `mirror_room_window_into`): the room guard and the grant landing then read
//!   the ledger and twin the import itself cannot rebuild.
//! * `the_actorless_import_installs_nothing_and_retains_the_grant_byte_for_byte`: the
//!   actorless import of a grant archive installs nothing and keeps the grant tuple byte for
//!   byte. Passes at the base too (guards the retain-only doors).
//! * `a_grant_without_its_live_grantee_is_held_back_missing_live_entity`: the destination
//!   keeps a live room while its grantee is a deleted shell, so the owner import reports one
//!   held-back row with reason `missing_live_entity` for the grantee (not the room) and
//!   still retains the tuple byte for byte.
//! * `a_revoked_standing_grant_restores_revoked_and_authorizes_nothing`: the owner import
//!   installs the revoked CONSENT_STANDING_GRANT row live, the restored row reads Revoked,
//!   no active grant survives, and the bound act evaluates Ask.
//! * `the_owner_restore_installs_the_approve_once_tap_and_only_the_first_use_runs`: the owner
//!   import installs one available CONSENT_APPROVE_ONCE_MARKER row; the covered send runs once
//!   on it and a second use is refused, while the actorless destination asks.
//! * `the_owner_restore_installs_the_voice_consent_and_enrollment_admits`: the owner import
//!   installs one VOICE_IDENTITY_CONSENT row for its live person, and an enrollment citing
//!   it is admitted; on the actorless destination the same enrollment is refused.
//! * `the_owner_restore_installs_the_voice_render_grant_and_the_actorless_import_leaves_none`:
//!   the owner import installs one VOICE_REF_RENDER_CONSENT row that reads Granted.
//! * `a_connector_slate_is_held_back_as_a_non_portable_reference`: a CONNECTOR_GRANT_SLATE
//!   row installs on no destination (its key binding travels in no disposition).
//!
//! No test covers CONSENT_WIDEN_PROPOSAL: the export's credential pass holds every row of
//! that table out of an archive, so the owner's restore has no landing for it.
//! HOOKS_GRANT has no landing at import: every import restores a hook binding claim as
//! Proposed, and a grant needs its binding approved. The owner's accept of the restore's inbox
//! group installs it (RULING ARCHIVE-HOOK-GRANT = A):
//! * `the_owner_accept_of_the_restore_group_installs_the_archived_hook_grant`: the grant is
//!   absent after the owner import; the accept-all lands the binding and installs the archived
//!   grant, the binding reads under it, the card counted it, the answer names it, and the
//!   accept's bundle receipt carries the second reason code.
//! * `a_rejected_restore_group_installs_no_hook_grant`: a reject-all installs nothing. Passes
//!   at the base too (guards the rule).
//! * `a_partly_accepted_restore_group_installs_no_hook_grant`: the owner rejects one member
//!   alone and then accepts the rest; no grant installs. Passes at the base too.
//!   The answers are read as JSON, so the new fields compile at the base.
//! No test covers PENDING_GATE_CONSENT: a tray row names a gate decision of its source vault,
//! which no import installs, and the owner's restore already lists each restored open claim
//! in its inbox group, so the owner's restore has no landing for it.
//!
//! Every vault a test deletes from installs a process-memory device keystore first: the
//! delete's plan phase loads the install signing key, so a delete without one fails.
//! New report counts are read through `serde_json::to_value` of the SIDE-1 summary, so this
//! file compiles on 4aad95477a58; an absent field fails its assertion as a missing outcome,
//! never as a setup panic. The semantic role read goes through the public Admin-only act
//! (`Vault::erase_room_person`), never through the body's roles map alone.
//! `cargo test --locked -p oneiron --all-features --test archive_import_owner_installs_side_grants`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::io::Cursor;

use oneiron::agent_inbox_lens::InboxRunGroupsRequest;
use oneiron::authority::HostSlipIssuer;
use oneiron::connector_key::{SlateDataClass, SlateToolManifest, draft_connector_slate};
use oneiron::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ComposedEffect, ConsentDecision,
    ConsentGrantStatus, EffectFacts, GrantBound,
};
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice, RoomRole};
use oneiron::inbox::InboxGroupResolveRequest;
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlementVerdict,
};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use oneiron::runtime_hooks::HookGrant;
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{HookActorClass, HookAuthor, PackInstallDisposition};
use oneiron::voice_identity::ref_bank::{VoiceRefSubjectKind, VoiceRenderDecision};
use oneiron::voice_identity::{
    VoiceConsentBasis, VoiceConsentEventV1, VoiceConsentState, VoiceEmbeddingFamily,
    VoiceEmbeddingSpaceV1, VoiceEnrollmentLegalContext, VoiceEnrollmentOrigin,
    VoiceEnrollmentRequest, VoiceEnrollmentSampleV1, VoicePrintPurpose,
};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, DeleteReason, EdgeActorClass, EntityId, Memory,
    ModelLocality, TimeRange, Vault, WriteActor,
};
use retained_side_rows::{
    export_whole, open_later_vault, open_source_vault, owner_proof, retained_rows, rows_for,
};

/// A fixed entity id from one repeated byte. The banned bytes (00, 11, 42,
/// 47, A1..A6, D7, E1, FF) belong to other fixtures.
fn fixed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("a non-reserved repeated byte is a valid entity id")
}

/// The `field` count for `table` in a `retained_side_rows` JSON summary, when
/// the table entry and the field are both present.
fn table_count(summary: &serde_json::Value, table: &str, field: &str) -> Option<u64> {
    summary
        .get("tables")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("source_table").and_then(|name| name.as_str()) == Some(table))?
        .get(field)?
        .as_u64()
}

/// The held-back list for `table` in a `retained_side_rows` JSON summary,
/// when the table entry and the list are both present.
fn held_back_for_table(summary: &serde_json::Value, table: &str) -> Option<serde_json::Value> {
    summary
        .get("tables")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("source_table").and_then(|name| name.as_str()) == Some(table))?
        .get("held_back")
        .cloned()
}

/// Puts a PERSON row for `id` holding `name`, at `occurred`/`learned_at`.
fn put_person_at(vault: &Vault, id: EntityId, name: &[u8], occurred: TimeRange, learned_at: u64) {
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, occurred, learned_at, name)
        .expect("the vault stores the fixture person");
}

/// The stamps of the 2026-03 sync window (`sync_edge_kind_gating.rs`'s month). A source and a
/// preseeded destination both write the room and its persons at these, so each destination
/// row is the row the archive carries: the import refuses a stored row of the same id that
/// differs, and never overwrites it.
const WINDOW_OCCURRED: TimeRange = TimeRange { start: 1, end: 1 };
const WINDOW_LEARNED_AT: u64 = 1_772_400_000;

/// Installs a process-memory device keystore, as a host does after each open:
/// the delete's plan phase loads the install signing key before its first
/// write (`steward_member_asks.rs` precedent).
fn install_keystore(vault: &Vault) {
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
}

/// Asserts yuki's Admin grant semantically on `vault`: yuki manages owen's room records (the
/// Admin-only act the room policy opens to Admin and shuts for Member), while owen's matching
/// act stays refused.
fn assert_admin_semantics(
    vault: &Vault,
    room: EntityId,
    owen: EntityId,
    yuki: EntityId,
    side: &str,
) {
    let manages = vault.erase_room_person(room, owen, WriteActor::new(yuki, EdgeActorClass::Human));
    assert!(
        manages.is_ok(),
        "the Admin grant lets yuki manage owen's room records on {side}: {manages:?}"
    );
    let refused = vault.erase_room_person(room, yuki, WriteActor::new(owen, EdgeActorClass::Human));
    assert!(
        refused.is_err(),
        "a Member cannot manage another member's room records on {side}: {refused:?}"
    );
}

/// Seats owen and yuki in a group room at `occurred`/`learned_at`, with no role granted: the
/// vault owner creates the room empty (so the creator's implicit Owner never falls on owen,
/// and no initial member's entry mints a reserved TASK fact, which the actorless import
/// refuses and whose id two vaults would share), then joins owen and yuki. Returns the room,
/// owen and yuki.
fn seat_room(
    vault: &Vault,
    occurred: TimeRange,
    learned_at: u64,
) -> (EntityId, EntityId, EntityId) {
    let room = fixed_id(0x6B);
    let owen = fixed_id(0x6C);
    let yuki = fixed_id(0x6D);
    put_person_at(vault, owen, b"owen", occurred, learned_at);
    put_person_at(vault, yuki, b"yuki", occurred, learned_at);
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault names its embedded owner actor");
    vault
        .create_conversation_with_text(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![],
                ..Default::default()
            },
            WriteActor::new(owner, EdgeActorClass::Human),
            occurred,
            learned_at,
            &[],
        )
        .expect("the owner creates the empty group room");
    for (member, name) in [(owen, "owen"), (yuki, "yuki")] {
        vault
            .join_member(
                room,
                member,
                WriteActor::new(owner, EdgeActorClass::Human),
                occurred.start,
                HistoryChoice::Share,
            )
            .unwrap_or_else(|err| panic!("{name} joins the room: {err:?}"));
    }
    (room, owen, yuki)
}

/// Builds the room seating owen and yuki ([`seat_room`]) with yuki holding the Admin grant,
/// at `occurred`/`learned_at`. Returns the room, owen and yuki. Asserts the grant's semantic
/// effect on the source.
fn build_admin_grant_room(
    source: &Vault,
    occurred: TimeRange,
    learned_at: u64,
) -> (EntityId, EntityId, EntityId) {
    let (room, owen, yuki) = seat_room(source, occurred, learned_at);
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("the source names its embedded owner actor");
    source
        .set_room_role(
            room,
            yuki,
            RoomRole::Admin,
            WriteActor::new(owner, EdgeActorClass::Human),
        )
        .expect("the owner grants yuki the Admin role");
    assert_admin_semantics(source, room, owen, yuki, "the source");
    (room, owen, yuki)
}

/// A source vault whose room seats owen and yuki with yuki holding the Admin grant, stamped
/// now: the vault, the room, owen and yuki.
fn room_source_with_admin_grant() -> (tempfile::TempDir, Vault, EntityId, EntityId, EntityId) {
    let (dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let (room, owen, yuki) = build_admin_grant_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    (dir, source, room, owen, yuki)
}

/// Seats owen and yuki in the room on a fresh vault with empty roles, through the public
/// doors and at the stamps a window-stamped source used ([`seat_room`]): the membership the
/// import's room guard and the grant landing read, without the grant itself.
fn preseed_destination_room(dest: &Vault) {
    seat_room(dest, WINDOW_OCCURRED, WINDOW_LEARNED_AT);
}

/// Mirrors the source's 2026-03 window (room, owen, yuki) into the destination through the
/// public sync path (`sync_edge_kind_gating.rs` shape): the room body arrives with its twin
/// roles entry, while the ledger and ROLE_GRANTS stay the destination's own (entities and
/// edges travel; side tables do not). The destination keeps its preseeded ledger, gains the
/// twin, and holds no grant: the import's room guard then passes and the archived grant
/// installs.
#[cfg(feature = "sync")]
fn mirror_room_window_into(source: &Vault, dest: &Vault) {
    use oneiron::sync::bridge::Materializer;
    use oneiron::sync::schema::create_window_doc;
    use oneiron::sync::types::WindowKey;
    use oneiron::sync::window;
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("side-grants", &window_key);
    let mirrored = window::reverse_rematerialize(source, &doc, &window_key)
        .expect("the source window mirrors");
    assert!(
        mirrored >= 3,
        "the window carries the room, owen and yuki: {mirrored}"
    );
    let materializer = Materializer::new();
    let restored = window::forward_rematerialize(dest, &doc, &materializer, &window_key)
        .expect("the destination window lands");
    // The destination's persons are already the source's rows byte for byte, and a
    // byte-identical row is skipped uncounted; the room row differs by its roles entry.
    assert!(
        restored >= 1,
        "the destination lands the room row with its roles entry: {restored}"
    );
}

/// Deletes `room` and its Admin grantee `grantee` from `source`: the grant row survives (only
/// a Leave deletes it) while both entities leave the export, so the archive carries the grant
/// and neither principal.
fn delete_room_and_grantee(source: &Vault, room: EntityId, grantee: EntityId) {
    install_keystore(source);
    assert!(
        source
            .delete_entity_with_reason(&room, DeleteReason::UserDelete)
            .expect("delete the source room")
            .existed,
        "the source room existed before its delete"
    );
    assert!(
        source
            .delete_entity_with_reason(&grantee, DeleteReason::UserDelete)
            .expect("delete the source grantee")
            .existed,
        "the source grantee existed before its delete"
    );
}

/// The owner restore installs the room Admin grant live; a repeat reports it unchanged.
///
/// The source is stamped into the 2026-03 sync window (`learned_at` 1_772_400_000, the
/// `sync_edge_kind_gating.rs` month); the role grant and the join keep the room's stamps, so
/// the room stays in the window. The destination preseeds its ledger, syncs the twin, and
/// only then imports.
#[cfg(feature = "sync")]
#[test]
fn the_owner_restore_installs_the_room_admin_grant_and_a_repeat_reports_it_unchanged() {
    let (_source_dir, source) = open_source_vault();
    let (room, owen, yuki) = build_admin_grant_room(&source, WINDOW_OCCURRED, WINDOW_LEARNED_AT);
    assert_eq!(
        source
            .conversation_body(room)
            .expect("read the source room")
            .roles
            .get(&yuki.to_hex()),
        Some(&RoomRole::Admin),
        "the source twin entry names yuki's Admin grant (secondary to the Admin-only act)"
    );
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "CONVERSATION_ROLE_GRANT");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one role-grant tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    preseed_destination_room(&dest);
    mirror_room_window_into(&source, &dest);
    assert_eq!(
        dest.conversation_body(room)
            .expect("read the synced room")
            .roles
            .get(&yuki.to_hex()),
        Some(&RoomRole::Admin),
        "the window sync carries the twin without minting the grant"
    );
    assert!(
        dest.erase_room_person(room, owen, WriteActor::new(yuki, EdgeActorClass::Human))
            .is_err(),
        "yuki is still a Member before the import: the sync minted no grant"
    );

    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import lands the room and its grant");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "CONVERSATION_ROLE_GRANT", "installed_rows"),
        Some(1),
        "the owner import reports one installed CONVERSATION_ROLE_GRANT row; an absent field means it installed nothing: {summary}"
    );
    assert_admin_semantics(&dest, room, owen, yuki, "the destination");
    assert_eq!(
        dest.conversation_body(room)
            .expect("read the restored room")
            .roles
            .get(&yuki.to_hex()),
        Some(&RoomRole::Admin),
        "the restored twin entry names yuki's Admin grant"
    );

    let repeat = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    let repeat_summary =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    assert_eq!(
        table_count(
            &repeat_summary,
            "CONVERSATION_ROLE_GRANT",
            "unchanged_live_rows"
        ),
        Some(1),
        "the repeat owner import reports one unchanged live CONVERSATION_ROLE_GRANT row; an absent field means it counted no live outcome: {repeat_summary}"
    );
    assert_eq!(
        table_count(&repeat_summary, "CONVERSATION_ROLE_GRANT", "installed_rows"),
        Some(0),
        "the repeat owner import installs no CONVERSATION_ROLE_GRANT row; an absent field means it counted no live outcome: {repeat_summary}"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&dest)),
            "CONVERSATION_ROLE_GRANT"
        ),
        source_tuple,
        "the destination archive carries the installed grant tuple byte for byte"
    );
}

/// The actorless import installs nothing and retains the grant byte for byte.
#[test]
fn the_actorless_import_installs_nothing_and_retains_the_grant_byte_for_byte() {
    let (_source_dir, source, room, _owen, yuki) = room_source_with_admin_grant();
    delete_room_and_grantee(&source, room, yuki);
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "CONVERSATION_ROLE_GRANT");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one role-grant tuple"
    );

    let (_bare_dir, bare) = open_later_vault();
    let receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert!(
        matches!(
            table_count(&summary, "CONVERSATION_ROLE_GRANT", "installed_rows"),
            None | Some(0)
        ),
        "the actorless import installs no CONVERSATION_ROLE_GRANT row: {summary}"
    );
    assert!(
        bare.conversation_body(room).is_err(),
        "the actorless import restores no room for the grant"
    );
    assert_eq!(
        bare.get_entity_type(&room).expect("read the absent room"),
        None,
        "the actorless destination never saw the room"
    );
    assert_eq!(
        bare.get_entity_type(&yuki)
            .expect("read the absent grantee"),
        None,
        "the actorless destination never saw the grantee"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&bare)),
            "CONVERSATION_ROLE_GRANT"
        ),
        source_tuple,
        "the actorless destination retains the grant tuple byte for byte"
    );
}

/// A grant without its live grantee is held back missing_live_entity.
///
/// The destination keeps a live room (preseeded, as in the first test) while its grantee is
/// a deleted shell: deleting a person neither refuses for room membership nor erases the
/// room. The archive carries the grant and neither principal, so the landing reaches past
/// the live room and holds the row back for the grantee.
#[test]
fn a_grant_without_its_live_grantee_is_held_back_missing_live_entity() {
    let (_source_dir, source) = open_source_vault();
    let (room, _owen, yuki) = build_admin_grant_room(&source, WINDOW_OCCURRED, WINDOW_LEARNED_AT);
    let (_dest_dir, dest) = open_later_vault();
    preseed_destination_room(&dest);
    install_keystore(&dest);
    assert!(
        dest.delete_entity_with_reason(&yuki, DeleteReason::UserDelete)
            .expect("delete the destination grantee")
            .existed,
        "the destination grantee existed before its delete"
    );
    assert!(
        dest.is_deleted_shell(&yuki)
            .expect("read the grantee shell"),
        "yuki is a deleted shell on the destination"
    );
    assert_eq!(
        dest.get_entity_type(&yuki).expect("read the shell type"),
        Some(ENTITY_TYPE_PERSON),
        "a deleted shell keeps its type byte"
    );
    assert_eq!(
        dest.get_entity_type(&room).expect("read the live room"),
        Some(ENTITY_TYPE_CONVERSATION),
        "the destination room stays live"
    );
    dest.conversation_body(room)
        .expect("the destination room reads live");

    delete_room_and_grantee(&source, room, yuki);
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "CONVERSATION_ROLE_GRANT");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one role-grant tuple"
    );

    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        held_back_for_table(&summary, "CONVERSATION_ROLE_GRANT"),
        Some(serde_json::json!([{"reason": "missing_live_entity", "rows": 1}])),
        "the owner import holds back one role-grant row as missing_live_entity; an absent field means it counted no held-back outcome: {summary}"
    );
    assert!(
        matches!(
            table_count(&summary, "CONVERSATION_ROLE_GRANT", "installed_rows"),
            None | Some(0)
        ),
        "the held-back grant installs nothing: {summary}"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&dest)),
            "CONVERSATION_ROLE_GRANT"
        ),
        source_tuple,
        "the destination retains the held-back grant tuple byte for byte"
    );
}

/// The action bound the consent fixtures cover: yuki may send to channel:team.
fn standing_bound() -> GrantBound {
    GrantBound::action(
        ActorBound::new("yuki").expect("the bound names yuki"),
        ActionClass::new("send").expect("the bound names send"),
        ActionEnvelope::new(["channel:team".to_owned()]).expect("the bound names channel:team"),
    )
    .expect("the action bound builds")
}

/// The irreversible send the bound covers, as the engine composes it.
fn covered_send(bound: &GrantBound) -> ComposedEffect {
    let facts = EffectFacts::new("channel.send")
        .expect("effect facts build")
        .with_external_observers(true);
    ComposedEffect::new(facts)
        .with_action_requirement(bound.clone())
        .expect("the send carries its action requirement")
}

/// A revoked standing grant restores revoked and authorizes nothing.
#[test]
fn a_revoked_standing_grant_restores_revoked_and_authorizes_nothing() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let bound = standing_bound();
    let grant_ref = bound.digest().to_hex();
    source
        .create_standing_grant(&source_owner, bound.clone())
        .expect("the owner mints the standing grant");
    assert_eq!(
        source
            .evaluate_consent_for(&covered_send(&bound), None)
            .expect("evaluate the covered send")
            .decision,
        ConsentDecision::Auto,
        "the covered send runs automatically while the grant stands"
    );
    source
        .revoke_consent_grant(&source_owner, &grant_ref)
        .expect("the owner revokes the standing grant");
    assert!(
        source
            .consent_grant(&grant_ref)
            .expect("read the source grant")
            .is_some_and(|row| row.status == ConsentGrantStatus::Revoked),
        "the source holds the revoked row"
    );
    assert_eq!(
        source
            .evaluate_consent_for(&covered_send(&bound), None)
            .expect("evaluate the covered send")
            .decision,
        ConsentDecision::Ask,
        "the covered send asks once the grant is revoked"
    );
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "CONSENT_STANDING_GRANT");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one standing-grant tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "CONSENT_STANDING_GRANT", "installed_rows"),
        Some(1),
        "the owner import reports one installed CONSENT_STANDING_GRANT row; an absent field means it installed nothing: {summary}"
    );
    assert!(
        dest.consent_grant(&grant_ref)
            .expect("read the restored grant")
            .is_some_and(|row| row.status == ConsentGrantStatus::Revoked && !row.is_active()),
        "the restored grant reads Revoked"
    );
    assert!(
        dest.active_standing_consent_grants()
            .expect("list the restored active grants")
            .is_empty(),
        "no active grant survives the revoked restore"
    );
    assert_eq!(
        dest.evaluate_consent_for(&covered_send(&bound), None)
            .expect("evaluate the covered send")
            .decision,
        ConsentDecision::Ask,
        "the covered send asks on the destination: the restored revocation authorizes nothing"
    );
}

/// owen's granted voice-print consent for meeting attribution, recorded by yuki.
fn voice_consent_event(subject: EntityId, recorder: EntityId) -> VoiceConsentEventV1 {
    VoiceConsentEventV1 {
        event_id: "consent-owen-1".to_owned(),
        subject_ref: subject,
        recorded_by_ref: recorder,
        occurred_at: 100,
        purposes: vec![VoicePrintPurpose::MeetingAttribution],
        basis: VoiceConsentBasis::ConversationalNotice {
            notice: "asked before recording".to_owned(),
        },
        state: VoiceConsentState::Granted,
    }
}

/// The pinned four-dimension embedding space the enrollment fixtures share.
fn voice_enrollment_space() -> VoiceEmbeddingSpaceV1 {
    VoiceEmbeddingSpaceV1::new(
        VoiceEmbeddingFamily::EcapaTdnn,
        "ecapa/voxceleb",
        "rev-1",
        16_000,
        4,
        "mono/16k/vad-v1",
    )
    .expect("pinned test embedding space")
}

/// One solo-session sample in [`voice_enrollment_space`].
fn voice_enrollment_sample() -> VoiceEnrollmentSampleV1 {
    VoiceEnrollmentSampleV1 {
        sample_id: "s-1".to_owned(),
        source_ref: "session-solo-1".to_owned(),
        language: "en".to_owned(),
        origin: VoiceEnrollmentOrigin::AuthenticatedSoloSession {
            session_ref: "session-solo-1".to_owned(),
            speaker_count: 1,
        },
        duration_ms: 4_000,
        source_sha256: "ab".repeat(32),
        vector: vec![1.0, 0.0, 0.0, 0.0],
    }
}

/// An enrollment of `subject` citing [`voice_consent_event`]'s grant.
fn voice_enrollment_request(subject: EntityId) -> VoiceEnrollmentRequest {
    VoiceEnrollmentRequest {
        subject_ref: subject,
        contact_ref: None,
        relationship_ref: None,
        consent_event_ref: "consent-owen-1".to_owned(),
        purpose: VoicePrintPurpose::MeetingAttribution,
        space: voice_enrollment_space(),
        samples: vec![voice_enrollment_sample()],
        requested_at: 200,
        legal: VoiceEnrollmentLegalContext::unresolved(),
    }
}

/// owen's granted render decision for the voice `voice-owen`, reaching the owner's own server.
fn voice_render_grant(subject: EntityId) -> VoiceRenderDecision {
    VoiceRenderDecision {
        event_id: "grant-owen-1".to_owned(),
        voice_id: "voice-owen".to_owned(),
        subject,
        subject_kind: VoiceRefSubjectKind::Person,
        recorded_by: subject,
        occurred_at: 1,
        reach: ModelLocality::OwnServer,
        basis: Some(VoiceConsentBasis::ConversationalNotice {
            notice: "render owen".to_owned(),
        }),
        state: VoiceConsentState::Granted,
    }
}

/// A read-only personal-data tool with a resolved input schema.
fn slate_tool(name: &str) -> SlateToolManifest {
    SlateToolManifest {
        name: name.to_owned(),
        data_class: SlateDataClass::Personal,
        header_parameters: Vec::new(),
        resolved_input_schema: Some(serde_json::json!({"type": "object"})),
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: true,
        idempotent: true,
        price: None,
    }
}

/// Stores a one-tool connector slate from the engine's own rule draft. Returns its id.
fn store_single_tool_slate(vault: &Vault, tool_name: &str) -> EntityId {
    let manifest = vec![slate_tool(tool_name)];
    let rows = draft_connector_slate(&manifest);
    let draft = serde_json::to_string(&rows).expect("typed slate draft");
    vault
        .store_connector_slate(&manifest, &draft)
        .expect("store the connector slate")
}

/// The owner restore installs an available approve-once marker; it authorizes one run.
#[test]
fn the_owner_restore_installs_the_approve_once_tap_and_only_the_first_use_runs() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let bound = standing_bound();
    let effect = covered_send(&bound);
    let digest = effect.digest();
    source
        .approve_once(&source_owner, digest)
        .expect("the owner approves the send once");
    assert!(
        source.approve_once(&source_owner, digest).is_err(),
        "a second approve over the same digest is refused while the tap stands"
    );
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "CONSENT_APPROVE_ONCE_MARKER");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one approve-once tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "CONSENT_APPROVE_ONCE_MARKER", "installed_rows"),
        Some(1),
        "the owner import reports one installed CONSENT_APPROVE_ONCE_MARKER row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&dest)),
            "CONSENT_APPROVE_ONCE_MARKER"
        ),
        source_tuple,
        "the destination archive carries the installed tap tuple byte for byte"
    );
    assert_eq!(
        dest.evaluate_consent_for(&effect, Some(&digest))
            .expect("evaluate the covered send")
            .decision,
        ConsentDecision::Auto,
        "the covered send runs automatically on the restored tap"
    );
    assert!(
        dest.evaluate_consent_for(&effect, Some(&digest)).is_err(),
        "the spent tap authorizes no second run"
    );

    let (_bare_dir, bare) = open_later_vault();
    let bare_receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    assert!(
        matches!(
            table_count(
                &bare_summary,
                "CONSENT_APPROVE_ONCE_MARKER",
                "installed_rows"
            ),
            None | Some(0)
        ),
        "the actorless import installs no CONSENT_APPROVE_ONCE_MARKER row: {bare_summary}"
    );
    assert_eq!(
        bare.evaluate_consent_for(&effect, Some(&digest))
            .expect("evaluate the covered send")
            .decision,
        ConsentDecision::Ask,
        "the covered send asks where no tap was restored"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&bare)),
            "CONSENT_APPROVE_ONCE_MARKER"
        ),
        source_tuple,
        "the actorless destination retains the tap tuple byte for byte"
    );
}

/// The owner restore installs a voice-print consent event; enrollment then admits it.
#[test]
fn the_owner_restore_installs_the_voice_consent_and_enrollment_admits() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let subject = fixed_id(0x30);
    let recorder = fixed_id(0x31);
    put_person_at(&source, subject, b"owen", occurred, now);
    put_person_at(&source, recorder, b"yuki", occurred, now);
    source
        .record_voice_consent(&voice_consent_event(subject, recorder))
        .expect("the source records the voice grant");
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "VOICE_IDENTITY_CONSENT");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one voice-consent tuple"
    );
    // The fixture's control, after the export so the archive carries no print: the request
    // is admitted where the consent is live.
    source
        .enroll_voice_print(&voice_enrollment_request(subject))
        .expect("enrollment admits the granted purpose on the source");

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "VOICE_IDENTITY_CONSENT", "installed_rows"),
        Some(1),
        "the owner import reports one installed VOICE_IDENTITY_CONSENT row; an absent field means it installed nothing: {summary}"
    );
    let print = dest
        .enroll_voice_print(&voice_enrollment_request(subject))
        .expect("enrollment admits the restored grant on the destination");
    assert_eq!(
        print.consent_event_ref,
        "consent-owen-1".to_owned(),
        "the restored enrollment cites the restored grant"
    );

    let (_bare_dir, bare) = open_later_vault();
    let bare_receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    assert!(
        matches!(
            table_count(&bare_summary, "VOICE_IDENTITY_CONSENT", "installed_rows"),
            None | Some(0)
        ),
        "the actorless import installs no VOICE_IDENTITY_CONSENT row: {bare_summary}"
    );
    assert!(
        bare.enroll_voice_print(&voice_enrollment_request(subject))
            .is_err(),
        "enrollment refuses where no consent was restored"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&bare)),
            "VOICE_IDENTITY_CONSENT"
        ),
        source_tuple,
        "the actorless destination retains the consent tuple byte for byte"
    );
}

/// The owner restore installs a voice render decision; the actorless import leaves none.
#[test]
fn the_owner_restore_installs_the_voice_render_grant_and_the_actorless_import_leaves_none() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let subject = fixed_id(0x32);
    put_person_at(&source, subject, b"owen", occurred, now);
    source
        .record_voice_render_consent(&voice_render_grant(subject))
        .expect("the source records the render grant");
    assert!(
        source
            .voice_render_consent("voice-owen")
            .expect("read the source render grant")
            .is_some_and(|row| row.decision.state == VoiceConsentState::Granted),
        "the source holds the granted render row"
    );
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "VOICE_REF_RENDER_CONSENT");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one render-consent tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "VOICE_REF_RENDER_CONSENT", "installed_rows"),
        Some(1),
        "the owner import reports one installed VOICE_REF_RENDER_CONSENT row; an absent field means it installed nothing: {summary}"
    );
    assert!(
        dest.voice_render_consent("voice-owen")
            .expect("read the restored render grant")
            .is_some_and(|row| row.decision.state == VoiceConsentState::Granted),
        "the restored render grant reads Granted"
    );

    let (_bare_dir, bare) = open_later_vault();
    let bare_receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    assert!(
        matches!(
            table_count(&bare_summary, "VOICE_REF_RENDER_CONSENT", "installed_rows"),
            None | Some(0)
        ),
        "the actorless import installs no VOICE_REF_RENDER_CONSENT row: {bare_summary}"
    );
    assert!(
        bare.voice_render_consent("voice-owen")
            .expect("read the absent render grant")
            .is_none(),
        "the actorless destination holds no render grant"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&bare)),
            "VOICE_REF_RENDER_CONSENT"
        ),
        source_tuple,
        "the actorless destination retains the render tuple byte for byte"
    );
}

/// A connector slate is held back as a non-portable reference on every destination.
#[test]
fn a_connector_slate_is_held_back_as_a_non_portable_reference() {
    let (_source_dir, source) = open_source_vault();
    let slate = store_single_tool_slate(&source, "read");
    assert!(
        source
            .connector_slate(slate)
            .expect("read the source slate")
            .is_some(),
        "the source holds the slate live"
    );
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "CONNECTOR_GRANT_SLATE");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one slate tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        held_back_for_table(&summary, "CONNECTOR_GRANT_SLATE"),
        Some(serde_json::json!([{"reason": "non_portable_reference", "rows": 1}])),
        "the owner import holds back one slate row as non_portable_reference; an absent field means it counted no held-back outcome: {summary}"
    );
    assert!(
        matches!(
            table_count(&summary, "CONNECTOR_GRANT_SLATE", "installed_rows"),
            None | Some(0)
        ),
        "the held-back slate installs nothing: {summary}"
    );
    assert!(
        dest.connector_slate(slate)
            .expect("read the absent slate")
            .is_none(),
        "the destination holds no live slate for the held-back row"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&dest)),
            "CONNECTOR_GRANT_SLATE"
        ),
        source_tuple,
        "the destination retains the held-back slate tuple byte for byte"
    );

    let (_bare_dir, bare) = open_later_vault();
    bare.import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    assert!(
        bare.connector_slate(slate)
            .expect("read the absent slate")
            .is_none(),
        "the actorless destination holds no live slate"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&bare)),
            "CONNECTOR_GRANT_SLATE"
        ),
        source_tuple,
        "the actorless destination retains the slate tuple byte for byte"
    );
}

/// A `profile.` predicate: the shipped default policy labels that prefix Normal, so the
/// owner's settle is not parked at the criticality floor (`archive_restore_inbox_group.rs`).
const NICKNAME: &str = "profile.nickname";

/// The pack the owner puts: one fact hook, shaped as in `pack_hook_owner_floor.rs`.
const HOOK_GRANT_PACK: &str = "example.hooksgrant";
/// Its one hook.
const HOOK_GRANT_HOOK: &str = "fact-note";

const HOOK_GRANT_PACK_MD: &str = "---
name: example.hooksgrant
description: One fact hook the owner grants.
version: 1.0.0
kind: capability
hooks: [\"fact-note\"]
---
A pack whose one fact hook the owner grants.
";

const HOOK_GRANT_HOOK_MD: &str = "---
name: fact-note
version: 1.0.0
verbs: [\"claim.landed:example.hooksgrant.input\"]
actors: [\"human\"]
phase: fact
outcomes: [\"propose\"]
---
Propose one note per landed input claim.
";

const HOOK_GRANT_BODY_JS: &str = "return {
  kind: \"propose\",
  claim: {
    subject: input.claim.subject,
    predicate: \"example.hooksgrant.note\",
    confidence: 1,
    value: { note: input.claim.value }
  }
};
";

/// The source: the owner's put binds the hook, and the owner grants it to a reader person.
/// Returns the vault, the binding and the grant the owner set. The keystore and this
/// install's signing keys are loaded before the put, as `pack_hook_owner_floor.rs` does.
fn hook_grant_source() -> (tempfile::TempDir, Vault, EntityId, HookGrant) {
    let (dir, source) = open_source_vault();
    install_keystore(&source);
    source
        .prepare_install_signing()
        .expect("load the source install's signing keys");
    let owner = owner_proof(&source);
    let files = vec![
        HubFile::new("PACK.md", HOOK_GRANT_PACK_MD),
        HubFile::new(
            format!("hooks/{HOOK_GRANT_HOOK}/HOOK.md"),
            HOOK_GRANT_HOOK_MD,
        ),
        HubFile::new(
            format!("hooks/{HOOK_GRANT_HOOK}/body.js"),
            HOOK_GRANT_BODY_JS,
        ),
    ];
    match source.put_pack(&owner, files) {
        Ok(PackInstallDisposition::Installed(receipt)) => {
            assert_eq!(receipt.pack_name, HOOK_GRANT_PACK);
        }
        other => panic!("the owner's put installs the pack and binds its hook: {other:?}"),
    }
    let mut bindings = source
        .pack_hook_bindings()
        .expect("read the source bindings");
    assert_eq!(bindings.len(), 1, "one binding: {bindings:?}");
    let (binding, row) = bindings.pop().expect("one binding");
    assert_eq!(row.pack, HOOK_GRANT_PACK);
    assert_eq!(row.hook, HOOK_GRANT_HOOK);
    assert_eq!(row.author, HookAuthor::Owner);
    assert!(row.enabled);
    let body = source
        .get_claim(&binding)
        .expect("read the binding claim")
        .expect("the binding claim stands");
    assert_eq!(body.approval, ClaimApprovalStatus::Approved);
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);

    let reader = fixed_id(0x5A);
    let now = source.now_recorded_at();
    put_person_at(
        &source,
        reader,
        b"hooks-grant-reader",
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    let grant = HookGrant {
        reader,
        reader_class: HookActorClass::Human,
        predicates: vec!["example.hooksgrant.note".to_owned()],
        worlds: Vec::new(),
    };
    source
        .set_hook_grant(&owner, binding, grant.clone())
        .expect("the owner sets the hook grant");
    assert_eq!(
        source.hook_grant(binding).expect("read the source grant"),
        Some(grant.clone()),
        "the source holds the grant the owner set"
    );
    (dir, source, binding, grant)
}

/// The owner writes `value` under `predicate` about `subject`
/// (`archive_restore_inbox_group.rs`).
fn owner_claim(vault: &Vault, subject: EntityId, predicate: &str, value: &str) -> EntityId {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let id = EntityId::now();
    let written = vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(id.to_hex()),
            predicate: predicate.to_owned(),
            subject_ref: subject.to_hex(),
            value: serde_json::json!(value),
            confidence: 1.0,
            confidence_details: None,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: Some(100),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .expect("the owner writes a claim");
    assert_ne!(written.approval, "proposed", "the owner's own write lands");
    id
}

/// `vault` rooted under a host, which binds its embedded owner under the root, with this
/// install's signing keys loaded (`archive_restore_inbox_group.rs`): the doors that answer a
/// restore group act only for the root owner.
fn root_under_a_host(vault: &Vault) {
    install_keystore(vault);
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    vault
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    let issuer =
        HostSlipIssuer::from_secret(b"archive-hook-grant-accept").expect("fixture host issuer");
    vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root binds the owner");
}

/// The archive restored as the destination's bound owner, into a destination rooted under a
/// host: the vault, its owner, the owner's proof and the restore receipt's ref.
fn restore_as_rooted_owner(
    archive: &[u8],
) -> (
    tempfile::TempDir,
    Vault,
    EntityId,
    AuthenticatedOwner,
    String,
) {
    let (dir, dest) = open_later_vault();
    root_under_a_host(&dest);
    let owner = owner_proof(&dest);
    let dest_owner = dest
        .ensure_embedded_owner_actor()
        .expect("the destination's embedded owner");
    let receipt = match dest.import_whole_vault_archive_from_as_owner(Cursor::new(archive), &owner)
    {
        Ok(receipt) => receipt,
        Err(error) => panic!("the owner's whole archive must restore: {error:?}"),
    };
    let receipt_ref = receipt
        .owner_restore_receipt_ref
        .expect("the owner door names its restore receipt");
    (dir, dest, dest_owner, owner, receipt_ref)
}

/// The restore groups of the owner's inbox page, as JSON.
fn restore_groups(memory: &Memory<'_>, owner: &AuthenticatedOwner) -> Vec<serde_json::Value> {
    let page = memory
        .inbox_groups_page(
            owner,
            &InboxRunGroupsRequest {
                limit: Some(200),
                after: None,
            },
        )
        .expect("the owner's inbox page");
    let page = serde_json::to_value(page).expect("the page as JSON");
    page["groups"]
        .as_array()
        .expect("the page's groups")
        .iter()
        .filter(|group| group["kind"] == "restore")
        .map(|group| group["group"].clone())
        .collect()
}

/// The one restore group of the page, keyed by the restore receipt.
fn the_restore_group(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    receipt_ref: &str,
) -> serde_json::Value {
    let groups = restore_groups(memory, owner);
    let [group] = groups.as_slice() else {
        panic!(
            "the owner's restore is one group of the inbox page, found {}: {groups:?}",
            groups.len()
        );
    };
    assert_eq!(
        group["receipt_ref"], receipt_ref,
        "the group is keyed by the restore receipt"
    );
    group.clone()
}

/// The owner's answer `verb` to the restore group `group_key`, as JSON.
fn resolve_restore_group(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    group_key: &str,
    verb: &str,
) -> serde_json::Value {
    let request: InboxGroupResolveRequest = serde_json::from_value(serde_json::json!({
        "kind": "restore",
        "group_key": group_key,
        "verb": verb,
    }))
    .expect("restore is an inbox group kind");
    let resolution = match memory.resolve_inbox_group_of_kind(owner, None, &request) {
        Ok(resolution) => resolution,
        Err(error) => panic!("the owner answers the restore group with {verb}: {error:?}"),
    };
    let resolution = serde_json::to_value(resolution).expect("the resolution as JSON");
    assert_eq!(resolution["kind"], "restore");
    resolution["resolution"].clone()
}

/// The member of `resolution` that names `claim`.
fn restore_member<'r>(
    resolution: &'r serde_json::Value,
    claim: &EntityId,
) -> &'r serde_json::Value {
    resolution["members"]
        .as_array()
        .expect("the members")
        .iter()
        .find(|member| member["claim_ref"] == claim.to_hex())
        .unwrap_or_else(|| panic!("{} is a member: {resolution:#}", claim.to_hex()))
}

/// The owner's accept of the restore group installs the archived hook grant.
///
/// The binding restores Proposed as a member of the restore's inbox group; the grant stays an
/// inert retained row until the owner accepts the group, and lands live with the accept.
#[test]
fn the_owner_accept_of_the_restore_group_installs_the_archived_hook_grant() {
    let (_source_dir, source, binding, grant) = hook_grant_source();
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(&retained_rows(&archive), "HOOKS_GRANT").len(),
        1,
        "the source archive holds one hook-grant tuple"
    );

    let (_dest_dir, dest, dest_owner, owner, receipt_ref) = restore_as_rooted_owner(&archive);
    assert_eq!(
        dest.hook_grant(binding)
            .expect("read the grant before the accept"),
        None,
        "the grant is inert until the owner accepts the group"
    );
    let memory = dest.memory(dest_owner, EdgeActorClass::Human);
    let card = the_restore_group(&memory, &owner, &receipt_ref);
    let group_key = card["group_key"].as_str().expect("group_key").to_owned();

    let resolution = resolve_restore_group(&memory, &owner, &group_key, "accept_all");
    assert_eq!(
        restore_member(&resolution, &binding)["verdict"],
        "landed",
        "the binding member landed: {resolution:#}"
    );
    assert!(
        resolution["members"]
            .as_array()
            .expect("members")
            .iter()
            .all(|member| member["verdict"] == "landed"),
        "no member waits in a fresh vault: {resolution:#}"
    );
    assert!(
        restore_groups(&memory, &owner).is_empty(),
        "an answered restore leaves the inbox"
    );
    assert_eq!(
        dest.get_claim(&binding)
            .expect("read the settled binding")
            .expect("the binding stands")
            .approval,
        ClaimApprovalStatus::Approved,
        "the accept approved the binding claim"
    );
    assert_eq!(
        dest.hook_grant(binding).expect("read the installed grant"),
        Some(grant.clone()),
        "the accept installed the archived hook grant: {resolution:#}"
    );
    assert_eq!(
        dest.effective_hook_grant(binding)
            .expect("the live binding reads under a grant"),
        grant,
        "the binding reads under the installed grant"
    );
    assert_eq!(
        card["hook_grants"], 1,
        "the card counted the grant before the accept: {card:#}"
    );
    assert_eq!(
        resolution["installed_hook_grants"],
        serde_json::json!([binding.to_hex()]),
        "the answer names the binding whose grant installed: {resolution:#}"
    );
    let bundle = resolution["receipt_ref"]
        .as_str()
        .and_then(|reference| reference.strip_prefix("gate:"))
        .unwrap_or_else(|| panic!("one bundle receipt: {resolution:#}"))
        .to_owned();
    let receipts = dest.gate_decisions(4096).expect("read the gate decisions");
    let receipt = receipts
        .iter()
        .find(|record| record.decision_id.to_hex() == bundle)
        .unwrap_or_else(|| panic!("the bundle receipt {bundle} is in the ledger"));
    assert_eq!(
        receipt.reason_codes,
        [
            "gate.restore.settle.approved",
            "gate.restore.settle.hook_grants_installed"
        ],
        "the accept's receipt shows that it installed a hook grant"
    );
}

/// A rejected restore group installs no hook grant. It passes at the base too: a guard of the
/// rule, not the red assertion.
#[test]
fn a_rejected_restore_group_installs_no_hook_grant() {
    let (_source_dir, source, binding, _grant) = hook_grant_source();
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(&retained_rows(&archive), "HOOKS_GRANT").len(),
        1,
        "the source archive holds one hook-grant tuple"
    );

    let (_dest_dir, dest, dest_owner, owner, receipt_ref) = restore_as_rooted_owner(&archive);
    let memory = dest.memory(dest_owner, EdgeActorClass::Human);
    let card = the_restore_group(&memory, &owner, &receipt_ref);
    let group_key = card["group_key"].as_str().expect("group_key").to_owned();

    let resolution = resolve_restore_group(&memory, &owner, &group_key, "reject_all");
    assert_eq!(
        restore_member(&resolution, &binding)["verdict"],
        "rejected",
        "the binding member was rejected: {resolution:#}"
    );
    assert!(
        resolution["installed_hook_grants"].is_null(),
        "a reject-all names no installed grant: {resolution:#}"
    );
    assert_eq!(
        dest.hook_grant(binding).expect("read the absent grant"),
        None,
        "a rejected restore group installs no hook grant"
    );
}

/// A partly accepted restore group installs no hook grant: the owner rejects one member alone
/// and then accepts the rest, so not every recorded member reads Approved after the accept.
/// It passes at the base too: a guard of the rule, not the red assertion.
#[test]
fn a_partly_accepted_restore_group_installs_no_hook_grant() {
    let (_source_dir, source, binding, grant) = hook_grant_source();
    let nickname = owner_claim(&source, grant.reader, NICKNAME, "Reader");
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(&retained_rows(&archive), "HOOKS_GRANT").len(),
        1,
        "the source archive holds one hook-grant tuple"
    );

    let (_dest_dir, dest, dest_owner, owner, receipt_ref) = restore_as_rooted_owner(&archive);
    let memory = dest.memory(dest_owner, EdgeActorClass::Human);
    let card = the_restore_group(&memory, &owner, &receipt_ref);
    let group_key = card["group_key"].as_str().expect("group_key").to_owned();

    // The owner rejects the nickname alone, through the single-claim doors.
    let review = memory
        .claim_review_as_owner(
            &owner,
            &ClaimProposalReviewRequest {
                claim_ref: nickname.to_hex(),
                grant_ref: None,
            },
        )
        .expect("the owner reviews the restored nickname");
    let settled = memory
        .claim_settle_as_owner(
            &owner,
            &ClaimSettleRequest {
                claim_ref: nickname.to_hex(),
                review_id: review.review_id,
                decision: ClaimSettleDecision::Reject,
                grant_ref: None,
            },
        )
        .expect("the owner rejects the restored nickname alone");
    assert_eq!(settled.verdict, ClaimSettlementVerdict::Rejected);

    let resolution = resolve_restore_group(&memory, &owner, &group_key, "accept_all");
    assert_eq!(
        restore_member(&resolution, &binding)["verdict"],
        "landed",
        "the binding member landed: {resolution:#}"
    );
    assert_eq!(
        dest.get_claim(&binding)
            .expect("read the settled binding")
            .expect("the binding stands")
            .approval,
        ClaimApprovalStatus::Approved,
        "the accept approved the binding claim"
    );
    assert_eq!(
        dest.get_claim(&nickname)
            .expect("read the rejected nickname")
            .expect("the nickname's record stays")
            .approval,
        ClaimApprovalStatus::Rejected,
        "the member the owner rejected alone stays rejected"
    );
    assert!(
        resolution["installed_hook_grants"].is_null(),
        "a partly accepted group names no installed grant: {resolution:#}"
    );
    assert_eq!(
        dest.hook_grant(binding).expect("read the absent grant"),
        None,
        "a partly accepted restore group installs no hook grant"
    );
}
