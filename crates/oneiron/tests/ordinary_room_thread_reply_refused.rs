//! An ordinary room's witness lands every turn it mints on the room's trunk,
//! and the room's threads live on its conversation DAG. So a witness turn
//! whose message names a thread's TURN as its reply parent
//! (`room_reply_to`) or its thread anchor (`room_thread_of`) is refused,
//! rather than shown to the whole room (CHAT-ORDINARY-ROOM-REPLY-TO-TRUNK).
//! Chat's `reply_to`, a `rooms.speak` reply and an offer accepted on a thread
//! all stamp those keys, and all reach this witness.
//!
//! Fixture: owen, the vault's owner, who reads the vault's records under
//! the default policy manifest, in an ordinary group room he holds alone.
//! A trunk witness turn is the anchor. owen's DAG replies on it open a
//! private thread (audience owen) and a room-wide thread.
//!
//! Red on main (by assertion): there the witness lands each reply on the
//! trunk, a row that answers no turn and names no thread. The trunk control
//! passes on both.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test ordinary_room_thread_reply_refused`.

use std::collections::BTreeSet;

use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::Scope;
use oneiron::memory::{Memory, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::workspace_roster::RoomTurn;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owen: EntityId,
    room: EntityId,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn owen(&self) -> Memory<'_> {
        self.vault.memory(self.owen, EdgeActorClass::Human)
    }
}

/// owen reads the vault's records: a row added to the default policy
/// manifest, the shipped rows kept.
fn grant_reads(vault: &Vault, owen: EntityId) -> TestResult {
    let proof = vault
        .memory(owen, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let view =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    rows.push(PolicyScopedGrantRow {
        // Bare census keys carry no actor class.
        actor_class: None,
        actor_ref: Some(owen.to_hex()),
        effector: "core:read".into(),
        scope: Scope::top(),
        selectors: None,
        budget: None,
        receipt_required: false,
    });
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    Ok(())
}

/// An ordinary group room owen creates, and so hosts, holding owen alone.
fn ordinary_room(vault: &Vault, owen: EntityId) -> TestResult<EntityId> {
    let receipt = vault
        .memory(owen, EdgeActorClass::Human)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: serde_json::json!({
                "v": 1,
                "kind": "group",
                "member_ids": [owen.to_hex()],
                "title": "ordinary room",
            }),
            text: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owen = vault.ensure_embedded_owner_actor()?;
    grant_reads(&vault, owen)?;
    let room = ordinary_room(&vault, owen)?;
    Ok(Fixture {
        vault,
        owen,
        room,
        _directory: directory,
    })
}

/// owen's one-message witness turn in the room through the room speech
/// door, its message carrying `metadata`. Returns the TURN it names and the
/// door's answer.
fn speak(
    fixture: &Fixture,
    metadata: serde_json::Value,
) -> (EntityId, oneiron::memory::MemoryResult<()>) {
    let turn = EntityId::now();
    let spoken = fixture
        .owen()
        .rooms_speak(&WitnessTurn {
            conversation_ref: fixture.room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(metadata),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: fixture.vault.now_recorded_at(),
            assertions: Default::default(),
        })
        .map(|_| ());
    (turn, spoken)
}

/// owen's plain TURN for the DAG's thread reply door, read by `audience`
/// alone when it names one.
fn plain_turn(fixture: &Fixture, audience: Option<BTreeSet<EntityId>>) -> TestResult<AppendRecord> {
    let now = fixture.vault.now_recorded_at();
    Ok(AppendRecord {
        conversation: fixture.room,
        parent: None,
        reply_to: None,
        quote: None,
        address: AddressMode::Broadcast,
        recipients: vec![],
        advance: false,
        kind: ENTITY_TYPE_TURN,
        containing_turn: None,
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
        body: rmp_serde::to_vec_named(&serde_json::json!({"txt": "owen"}))?,
        text: vec![],
        session: None,
        actor: WriteActor::new(fixture.owen, EdgeActorClass::Human),
        thread_audience: audience,
    })
}

/// owen's reply on `anchor` through the DAG's thread reply door. Returns the
/// TURN.
fn thread_reply(
    fixture: &Fixture,
    anchor: EntityId,
    audience: Option<BTreeSet<EntityId>>,
) -> TestResult<EntityId> {
    let input = plain_turn(fixture, audience)?;
    Ok(fixture
        .vault
        .reply_in_thread(&fixture.owen(), anchor, &input)?
        .id)
}

/// A trunk witness turn, the anchor the threads hang from.
fn anchor(fixture: &Fixture) -> TestResult<EntityId> {
    let (turn, spoken) = speak(fixture, serde_json::json!({}));
    spoken?;
    Ok(turn)
}

/// The room row of `turn` in owen's room history, if the room keeps one.
fn row(fixture: &Fixture, turn: EntityId) -> TestResult<Option<RoomTurn>> {
    Ok(fixture
        .owen()
        .rooms_messages(fixture.room)?
        .into_iter()
        .find(|row| row.turn_id == turn.to_hex()))
}

/// The witness refused `spoken` as a thread reply, and the room keeps no
/// row for `turn`.
fn assert_refused_and_unlanded(
    fixture: &Fixture,
    turn: EntityId,
    spoken: oneiron::memory::MemoryResult<()>,
    case: &str,
) -> TestResult {
    let landed = row(fixture, turn)?;
    let error = match spoken {
        Ok(()) => {
            return Err(format!(
                "{case}: the witness took the reply and landed it as {landed:?}, \
                 a trunk turn the whole room reads"
            )
            .into());
        }
        Err(error) => error,
    };
    assert!(
        format!("{error:?}").contains("reply door"),
        "{case}: refused for another reason: {error:?}"
    );
    assert!(landed.is_none(), "{case}: a refused turn kept {landed:?}");
    Ok(())
}

/// A reply to the root of a private thread is refused, and lands nowhere.
#[test]
fn a_reply_to_a_private_threads_root_is_refused() -> TestResult {
    let fixture = open_fixture()?;
    let anchor = anchor(&fixture)?;
    let root = thread_reply(&fixture, anchor, Some(BTreeSet::from([fixture.owen])))?;
    let (turn, spoken) = speak(
        &fixture,
        serde_json::json!({"room_reply_to": root.to_hex()}),
    );
    assert_refused_and_unlanded(&fixture, turn, spoken, "private thread root")
}

/// A reply to a later TURN of a room-wide thread is refused too: the
/// witness never places a turn in an ordinary room's thread.
#[test]
fn a_reply_to_a_later_turn_of_a_room_wide_thread_is_refused() -> TestResult {
    let fixture = open_fixture()?;
    let anchor = anchor(&fixture)?;
    let root = thread_reply(&fixture, anchor, None)?;
    let later = thread_reply(&fixture, anchor, None)?;
    assert_ne!(root, later, "the second reply continues the thread");
    let (turn, spoken) = speak(
        &fixture,
        serde_json::json!({"room_reply_to": later.to_hex()}),
    );
    assert_refused_and_unlanded(&fixture, turn, spoken, "room-wide thread turn")
}

/// A turn naming a thread's TURN as its thread anchor is refused.
#[test]
fn a_turn_naming_a_thread_turn_as_its_anchor_is_refused() -> TestResult {
    let fixture = open_fixture()?;
    let anchor = anchor(&fixture)?;
    let root = thread_reply(&fixture, anchor, Some(BTreeSet::from([fixture.owen])))?;
    let (turn, spoken) = speak(
        &fixture,
        serde_json::json!({"room_thread_of": root.to_hex()}),
    );
    assert_refused_and_unlanded(&fixture, turn, spoken, "thread turn as anchor")
}

/// Control, green on main too: a reply to a trunk TURN, the anchor a thread
/// hangs from included, still lands on the trunk.
#[test]
fn a_reply_to_a_trunk_turn_still_lands_on_the_trunk() -> TestResult {
    let fixture = open_fixture()?;
    let anchor = anchor(&fixture)?;
    thread_reply(&fixture, anchor, Some(BTreeSet::from([fixture.owen])))?;
    let (turn, spoken) = speak(
        &fixture,
        serde_json::json!({"room_reply_to": anchor.to_hex()}),
    );
    spoken?;
    let landed = row(&fixture, turn)?.ok_or("the trunk reply keeps no room row")?;
    assert_eq!(landed.thread_of, None);
    assert_eq!(landed.actor, fixture.owen.to_hex());
    Ok(())
}
