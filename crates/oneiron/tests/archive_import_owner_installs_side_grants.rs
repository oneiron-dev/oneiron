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
//! * `an_unexpired_widen_proposal_restores_unresolved_and_an_expired_one_is_held_back`: an
//!   unresolved unexpired CONSENT_WIDEN_PROPOSAL row installs and reads unresolved with no
//!   settlement, while an unresolved expired one reports one held-back row with reason
//!   `invalid_value` and installs nothing.
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

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::consent::{
    ActionClass, ActionEnvelope, ActorBound, ComposedEffect, ConsentDecision, ConsentGrantStatus,
    EffectFacts, GrantBound,
};
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice, RoomRole};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use oneiron::{DeleteReason, EdgeActorClass, EntityId, TimeRange, Vault, WriteActor};
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

/// Puts a PERSON row for `id` holding `name`, stamped now.
fn put_person(vault: &Vault, id: EntityId, name: &[u8]) {
    let now = vault.now_recorded_at();
    put_person_at(
        vault,
        id,
        name,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
}

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

/// Builds the room seating owen and yuki with yuki holding the Admin grant, at
/// `occurred`/`learned_at`: the vault owner creates the room over owen (so the creator's
/// implicit Owner never falls on owen), joins yuki second, and grants the role. Returns the
/// room, owen and yuki. Asserts the grant's semantic effect on the source.
fn build_admin_grant_room(
    source: &Vault,
    occurred: TimeRange,
    learned_at: u64,
) -> (EntityId, EntityId, EntityId) {
    let room = fixed_id(0x6B);
    let owen = fixed_id(0x6C);
    let yuki = fixed_id(0x6D);
    put_person_at(source, owen, b"owen", occurred, learned_at);
    put_person_at(source, yuki, b"yuki", occurred, learned_at);
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("the source names its embedded owner actor");
    source
        .create_conversation_with_text(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![owen],
                ..Default::default()
            },
            WriteActor::new(owner, EdgeActorClass::Human),
            occurred,
            learned_at,
            &[],
        )
        .expect("the owner creates the group room over owen");
    source
        .join_member(
            room,
            yuki,
            WriteActor::new(owner, EdgeActorClass::Human),
            occurred.start,
            HistoryChoice::Share,
        )
        .expect("yuki joins the room second");
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

/// Seats owen and yuki in `room` on a fresh vault with empty roles, through public doors: the
/// membership the import's room guard and the grant landing read, without the grant itself.
/// The vault owner creates and joins so owen stays a plain Member.
fn preseed_destination_room(dest: &Vault, room: EntityId, owen: EntityId, yuki: EntityId) {
    put_person(dest, owen, b"owen");
    put_person(dest, yuki, b"yuki");
    let owner = dest
        .ensure_embedded_owner_actor()
        .expect("the destination names its embedded owner actor");
    let at = dest.now_recorded_at();
    dest.create_conversation(
        room,
        &ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![owen],
            ..Default::default()
        },
        WriteActor::new(owner, EdgeActorClass::Human),
        at,
    )
    .expect("the owner seats the destination room");
    dest.join_member(
        room,
        yuki,
        WriteActor::new(owner, EdgeActorClass::Human),
        at,
        HistoryChoice::Share,
    )
    .expect("yuki joins the destination room second");
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
    assert!(
        restored >= 3,
        "the destination lands the room, owen and yuki: {restored}"
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
    let (room, owen, yuki) =
        build_admin_grant_room(&source, TimeRange { start: 1, end: 1 }, 1_772_400_000);
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
    preseed_destination_room(&dest, room, owen, yuki);
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
    let (_source_dir, source, room, owen, yuki) = room_source_with_admin_grant();
    let (_dest_dir, dest) = open_later_vault();
    preseed_destination_room(&dest, room, owen, yuki);
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

/// A verified agent slip for `agent`, mirroring `widen_agent_credential`
/// (`src/consent/tests.rs`): a PERSON holder, the agent class, and the host
/// root's scope, which carries the widen verbs.
fn agent_slip(vault: &Vault, agent: EntityId, slip_id: [u8; 32]) -> VerifiedSlip {
    let issuer = HostSlipIssuer::from_secret(b"side-grants-test-host-secret").expect("host issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    let mut claims = root.claims.clone();
    claims.slip_id = slip_id;
    claims.parent_id = None;
    claims.holder_ref = agent.to_hex();
    claims.actor_class = Some("agent".to_owned());
    claims.expires_at = claims.issued_at + 600;
    claims.ttl_secs = 600;
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("the agent slip");
    let challenge = b"side-grants-widen";
    let proof = issuer
        .binding_proof(&slip, challenge)
        .expect("binding proof");
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof)
        .expect("verified slip")
}

/// An unresolved unexpired widen proposal restores unresolved; an expired one is held back.
#[test]
fn an_unexpired_widen_proposal_restores_unresolved_and_an_expired_one_is_held_back() {
    // Unexpired: filed with a half-hour horizon, exported at once.
    let (_source_dir, source) = open_source_vault();
    let agent = fixed_id(0x72);
    put_person(&source, agent, b"yuki");
    let owner_ref = source
        .ensure_embedded_owner_actor()
        .expect("the source names its embedded owner actor")
        .to_hex();
    let credential = agent_slip(&source, agent, [0x73; 32]);
    let filed = source
        .propose_action_widen(
            &credential,
            standing_bound(),
            &owner_ref,
            source.now_recorded_at() + 1_800,
        )
        .expect("the agent files its widen proposal");
    assert_eq!(
        source
            .widen_proposal(&filed.proposal_ref)
            .expect("read the source proposal")
            .as_ref(),
        Some(&filed),
        "the source holds the filed proposal"
    );
    assert_eq!(
        source
            .widen_proposal_settlement(&filed.proposal_ref)
            .expect("read the source settlement"),
        None,
        "the filed proposal is unresolved"
    );
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "CONSENT_WIDEN_PROPOSAL");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one widen tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "CONSENT_WIDEN_PROPOSAL", "installed_rows"),
        Some(1),
        "the owner import reports one installed CONSENT_WIDEN_PROPOSAL row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        dest.widen_proposal(&filed.proposal_ref)
            .expect("read the restored proposal")
            .as_ref(),
        Some(&filed),
        "the restored proposal reads back as filed"
    );
    assert_eq!(
        dest.widen_proposal_settlement(&filed.proposal_ref)
            .expect("read the restored settlement"),
        None,
        "the restored proposal is still unresolved"
    );

    // Expired: filed with a two-second horizon, exported after it lapses.
    let (_stale_dir, stale) = open_source_vault();
    let stale_agent = fixed_id(0x75);
    put_person(&stale, stale_agent, b"owen");
    let stale_owner = stale
        .ensure_embedded_owner_actor()
        .expect("the stale source names its embedded owner actor")
        .to_hex();
    let stale_credential = agent_slip(&stale, stale_agent, [0x76; 32]);
    let expiring = stale
        .propose_action_widen(
            &stale_credential,
            standing_bound(),
            &stale_owner,
            stale.now_recorded_at() + 2,
        )
        .expect("the agent files its short proposal");
    assert_eq!(
        stale
            .widen_proposal_settlement(&expiring.proposal_ref)
            .expect("read the stale settlement"),
        None,
        "the short proposal is unresolved when filed"
    );
    std::thread::sleep(std::time::Duration::from_secs(3));
    let stale_archive = export_whole(&stale);
    let stale_tuple = rows_for(&retained_rows(&stale_archive), "CONSENT_WIDEN_PROPOSAL");
    assert_eq!(
        stale_tuple.len(),
        1,
        "the stale archive holds one widen tuple"
    );

    let (_stale_dest_dir, stale_dest) = open_later_vault();
    let stale_dest_owner = owner_proof(&stale_dest);
    let stale_receipt = stale_dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&stale_archive), &stale_dest_owner)
        .expect("the owner import succeeds");
    let stale_summary = serde_json::to_value(&stale_receipt.retained_side_rows)
        .expect("the stale summary serializes");
    assert_eq!(
        held_back_for_table(&stale_summary, "CONSENT_WIDEN_PROPOSAL"),
        Some(serde_json::json!([{"reason": "invalid_value", "rows": 1}])),
        "the owner import holds back one widen row as invalid_value; an absent field means it counted no held-back outcome: {stale_summary}"
    );
    assert_eq!(
        stale_dest
            .widen_proposal(&expiring.proposal_ref)
            .expect("read the missing proposal"),
        None,
        "the expired proposal installs nothing live"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&stale_dest)),
            "CONSENT_WIDEN_PROPOSAL"
        ),
        stale_tuple,
        "the destination retains the held-back widen tuple byte for byte"
    );
}
