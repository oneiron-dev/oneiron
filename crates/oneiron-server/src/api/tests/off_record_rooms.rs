//! ARCH-0052 D5, the notice model (owner ruling 2026-10-10, O1 = A): anyone
//! in a room may start an off-record stretch and keep their own copy. A member
//! saves into their own vault, a guest takes an export file, nothing writes
//! another person's vault, every save and export posts a notice to the room,
//! and an agent's save suggestion saves nothing by itself.
use super::owner_routes::{call, owner_recipe};
use super::*;
use oneiron::conversation::{ConversationBody, HistoryChoice};
use oneiron::{EdgeActorClass, EntityId, TimeRange, WriteActor};

const SECRET_WORDS: &str = "the lighthouse key is under the blue stone";

struct Room {
    id: EntityId,
    owner: EntityId,
    mina: EntityId,
    companion: EntityId,
}

fn person(server: &SyncServer, name: &str) -> EntityId {
    let id = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )
    .unwrap();
    server
        .vault()
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .unwrap();
    id
}

fn conversation(server: &SyncServer, by: EntityId, members: &[EntityId]) -> EntityId {
    let actor = WriteActor::new(by, EdgeActorClass::Human);
    let id = EntityId::now();
    server
        .vault()
        .create_conversation(id, &ConversationBody::default(), actor, 1)
        .unwrap();
    for (at, member) in (2..).zip(members) {
        server
            .vault()
            .join_member(id, *member, actor, at, HistoryChoice::Share)
            .unwrap();
    }
    id
}

/// A room holding the vault's owner, Mina (who has no vault here) and an
/// agent.
fn room(server: &SyncServer) -> Room {
    let owner = server.vault().ensure_embedded_owner_actor().unwrap();
    let mina = person(server, "Mina");
    let companion = person(server, "Companion");
    Room {
        id: conversation(server, owner, &[owner, mina, companion]),
        owner,
        mina,
        companion,
    }
}

fn slip(name: &str, who: EntityId, class: &str) -> String {
    test_bearer(&recipe(name, who, class))
}

/// The credential a slip is minted from, which also revokes it.
fn recipe(name: &str, who: EntityId, class: &str) -> String {
    format!(
        "jti={name};principal_ref={};actor_class={class};scope=core:read,core:write",
        who.to_hex()
    )
}

fn turn(room: EntityId, session_ref: &str, at: u64, text: &str) -> Value {
    json!({
        "room": room.to_hex(),
        "session_ref": session_ref,
        "turn": {
            "conversation_ref": "",
            "turn_ref": null,
            "messages": [{
                "id": null,
                "author": "user",
                "message_type": "utterance",
                "content": text,
                "metadata": null,
                "is_visible": true,
                "order": 0,
            }],
            "occurred_at": at,
        },
    })
}

fn witnessed(receipt: &Value) -> EntityId {
    let turn = receipt["receipt_ref"]
        .as_str()
        .and_then(|reference| reference.strip_prefix("witness:"))
        .unwrap_or_else(|| panic!("a witness receipt: {receipt}"));
    EntityId::from_hex(turn).unwrap()
}

/// The key the owner's own routes address a room's stretch by.
fn owner_key(room: EntityId, session_ref: &str) -> String {
    oneiron::off_record::room_session_key(room, session_ref)
}

async fn start(
    server: &Arc<SyncServer>,
    who: String,
    room: EntityId,
    session_ref: &str,
) -> (StatusCode, Value) {
    call(
        server,
        "POST",
        "/v1/core/off-record/start",
        who,
        Some(&json!({ "room": room.to_hex(), "session_ref": session_ref, "backend": "local" })),
    )
    .await
}

async fn say(
    server: &Arc<SyncServer>,
    who: String,
    room: EntityId,
    session_ref: &str,
    at: u64,
    text: &str,
) -> EntityId {
    let (status, receipt) = call(
        server,
        "POST",
        "/v1/core/off-record/witness",
        who,
        Some(&turn(room, session_ref, at, text)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    witnessed(&receipt)
}

async fn act(
    server: &Arc<SyncServer>,
    path: &str,
    who: String,
    room: EntityId,
    session_ref: &str,
) -> (StatusCode, Value) {
    call(
        server,
        "POST",
        &format!("/v1/core/off-record/{path}"),
        who,
        Some(&json!({ "room": room.to_hex(), "session_ref": session_ref })),
    )
    .await
}

async fn notices(
    server: &Arc<SyncServer>,
    who: String,
    room: EntityId,
    session_ref: &str,
) -> Vec<(String, String)> {
    let (status, view) = call(
        server,
        "GET",
        &format!(
            "/v1/core/off-record?room={}&session_ref={session_ref}",
            room.to_hex()
        ),
        who,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert!(
        !view.to_string().contains(SECRET_WORDS),
        "the room's record never quotes the talk: {view}"
    );
    view["notices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|notice| {
            (
                notice["act"].as_str().unwrap().to_owned(),
                notice["by"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn words(file: &Value) -> Vec<&str> {
    file["turns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|turn| turn["messages"][0]["content"].as_str().unwrap())
        .collect()
}

/// Whether any file of the vault holds `words`: nothing of an off-record talk
/// may reach the vault's storage until someone whose vault it is saves it.
fn stored(dir: &tempfile::TempDir, words: &str) -> bool {
    fn walk(path: &std::path::Path, needle: &[u8]) -> bool {
        if path.is_dir() {
            return std::fs::read_dir(path)
                .unwrap()
                .any(|entry| walk(&entry.unwrap().path(), needle));
        }
        std::fs::read(path)
            .is_ok_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
    }
    walk(dir.path(), words.as_bytes())
}

/// A guest keeps a copy as an export file. Their save is refused, since this
/// vault is not theirs, and neither the save nor the export writes any vault.
#[tokio::test]
async fn a_guests_save_writes_no_vault_and_their_export_is_a_file() {
    let (dir, server) = auth_test_server();
    let room = room(&server);
    let mina = slip("mina", room.mina, "human");
    let owner = slip("owner", room.owner, "human");

    // Anyone in the room may start; Mina is a guest here.
    let (status, started) = start(&server, mina.clone(), room.id, "garden").await;
    assert_eq!(status, StatusCode::OK, "{started}");
    assert_eq!(started["started_by"], room.mina.to_hex());
    assert_eq!(started["room"], room.id.to_hex());
    assert_eq!(started["session_ref"], "garden");
    let said = [
        say(&server, mina.clone(), room.id, "garden", 100, SECRET_WORDS).await,
        say(
            &server,
            owner.clone(),
            room.id,
            "garden",
            101,
            "the boat leaves at six",
        )
        .await,
    ];

    let (status, refused) = act(&server, "save", mina.clone(), room.id, "garden").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    // A native host's proof shows Mina is a live person, not that this vault
    // is hers: the owner's doors refuse her too.
    {
        let vault = server.vault();
        let proof = vault
            .authenticate_owner(
                room.mina,
                &room.mina.to_hex(),
                true,
                oneiron::store::GateDecisionId::now(),
            )
            .unwrap();
        let session = vault
            .off_record_session_vault()
            .bind(&owner_key(room.id, "garden"))
            .unwrap();
        assert!(session.save_talk_as(&proof).is_err());
        assert!(session.promote_turn_as(&proof, &said[0]).is_err());
        assert!(session.flip_on_record_as(&proof).is_err());
        // Nor does the vault's own mode door put a room on record without
        // the owner's proof: later turns would land in the vault.
        assert!(
            vault
                .set_off_record_session_mode(
                    &owner_key(room.id, "garden"),
                    oneiron::off_record::OffRecordMode::OnRecord,
                )
                .is_err()
        );
    }
    for turn in said {
        assert!(server.vault().get(&turn).unwrap().is_none());
    }
    assert!(
        !stored(&dir, SECRET_WORDS),
        "a guest's save wrote the vault"
    );

    let request = core_request_with_authz(
        "POST",
        "/v1/core/off-record/export",
        mina.clone(),
        Some(&json!({ "room": room.id.to_hex(), "session_ref": "garden" })),
    );
    let request = slip_credentials::bind_request(&server, request);
    let response = api_routes(server.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[axum::http::header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment"),
    );
    let file: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(words(&file), [SECRET_WORDS, "the boat leaves at six"]);
    assert_eq!(file["turns"][0]["speaker"], room.mina.to_hex());
    assert_eq!(file["turns"][1]["speaker"], room.owner.to_hex());
    for turn in said {
        assert!(server.vault().get(&turn).unwrap().is_none());
    }
    assert!(
        !stored(&dir, SECRET_WORDS),
        "a guest's export wrote the vault"
    );
    assert_eq!(
        notices(&server, owner, room.id, "garden").await,
        [("exported".to_owned(), room.mina.to_hex())]
    );
}

/// A member saves the whole talk into their own vault, and into nobody
/// else's: another vault stays untouched. A copy taken after the save still
/// holds every turn, read back from the vault.
#[tokio::test]
async fn a_members_save_writes_only_their_own_vault() {
    let (dir, server) = auth_test_server();
    let (other_dir, _other_vault) = auth_test_server();
    let room = room(&server);
    let mina = slip("mina", room.mina, "human");
    let owner = slip("owner", room.owner, "human");

    start(&server, owner.clone(), room.id, "harbour").await;
    let said = [
        say(&server, mina.clone(), room.id, "harbour", 100, SECRET_WORDS).await,
        say(&server, owner.clone(), room.id, "harbour", 101, "noted").await,
    ];
    assert!(!stored(&dir, SECRET_WORDS));

    let (status, saved) = act(&server, "save", owner.clone(), room.id, "harbour").await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    let saved_turns: Vec<&str> = saved["saved"]
        .as_array()
        .unwrap()
        .iter()
        .map(|turn| turn["turn"].as_str().unwrap())
        .collect();
    assert_eq!(saved_turns, said.map(|turn| turn.to_hex()));
    for turn in said {
        assert!(server.vault().get(&turn).unwrap().is_some());
    }
    assert!(
        !stored(&other_dir, SECRET_WORDS),
        "a save wrote another vault"
    );

    // A second save has nothing left to save and tells nobody.
    let (status, again) = act(&server, "save", owner.clone(), room.id, "harbour").await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["saved"], json!([]));

    let (status, file) = act(&server, "export", mina.clone(), room.id, "harbour").await;
    assert_eq!(status, StatusCode::OK, "{file}");
    assert_eq!(words(&file), [SECRET_WORDS, "noted"]);
    assert_eq!(file["turns"][0]["saved"], true);
    assert_eq!(file["turns"][0]["speaker"], room.mina.to_hex());
    assert_eq!(
        notices(&server, mina, room.id, "harbour").await,
        [
            ("saved_talk".to_owned(), room.owner.to_hex()),
            ("exported".to_owned(), room.mina.to_hex()),
        ]
    );
}

/// Every save and every export posts a notice to the room, naming who and
/// what; the owner's own one-turn save and on-record flip count too. A copy
/// holds the turns said on record. A 1:1 the owner entered alone posts none.
#[tokio::test]
async fn every_save_and_export_leaves_a_room_notice() {
    let (_dir, server) = auth_test_server();
    let room = room(&server);
    let mina = slip("mina", room.mina, "human");
    let owner = slip("owner", room.owner, "human");
    let owner_door = owner_recipe(&server);
    let key = owner_key(room.id, "kitchen");

    start(&server, mina.clone(), room.id, "kitchen").await;
    say(&server, mina.clone(), room.id, "kitchen", 100, SECRET_WORDS).await;
    let (status, _) = act(&server, "export", mina.clone(), room.id, "kitchen").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = act(&server, "save", owner.clone(), room.id, "kitchen").await;
    assert_eq!(status, StatusCode::OK);
    let later = say(
        &server,
        mina.clone(),
        room.id,
        "kitchen",
        102,
        "one more thing",
    )
    .await;
    let (status, promoted) = call(
        &server,
        "POST",
        "/v1/owner/off-record/promote",
        owner_door.clone(),
        Some(&json!({ "session_ref": key, "turn": later.to_hex() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{promoted}");
    let (status, flipped) = call(
        &server,
        "POST",
        "/v1/owner/off-record/mode",
        owner_door.clone(),
        Some(&json!({ "session_ref": key, "mode": "on_record" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{flipped}");
    say(
        &server,
        mina.clone(),
        room.id,
        "kitchen",
        103,
        "said on record",
    )
    .await;
    let (status, file) = act(&server, "export", owner.clone(), room.id, "kitchen").await;
    assert_eq!(status, StatusCode::OK, "{file}");
    assert_eq!(
        words(&file),
        [SECRET_WORDS, "one more thing", "said on record"]
    );

    let (mina_hex, owner_hex) = (room.mina.to_hex(), room.owner.to_hex());
    assert_eq!(
        notices(&server, mina, room.id, "kitchen").await,
        [
            ("exported".to_owned(), mina_hex),
            ("saved_talk".to_owned(), owner_hex.clone()),
            ("saved_turn".to_owned(), owner_hex.clone()),
            ("saving_from_here".to_owned(), owner_hex.clone()),
            ("exported".to_owned(), owner_hex),
        ]
    );

    // The owner's 1:1 with their companion has nobody else to tell.
    let (status, _) = call(
        &server,
        "POST",
        "/v1/owner/off-record",
        owner_door.clone(),
        Some(&json!({ "session_ref": "alone", "mode": "off_record", "backend": "local" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mut alone_turn = turn(room.id, "alone", 100, "just us");
    alone_turn.as_object_mut().unwrap().remove("room");
    let (status, receipt) = call(
        &server,
        "POST",
        "/v1/owner/off-record/witness",
        owner_door.clone(),
        Some(&alone_turn),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    let (status, saved) = call(
        &server,
        "POST",
        "/v1/owner/off-record/save",
        owner_door,
        Some(&json!({ "session_ref": "alone" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["saved"][0]["turn"], witnessed(&receipt).to_hex());
    let alone = server.vault().off_record_session("alone").unwrap().unwrap();
    assert!(alone.notices.is_empty());
    assert!(alone.room.is_none());
}

/// The agent may suggest a save, and everyone in the room sees it. The
/// suggestion saves nothing, and the agent can neither save, export nor start;
/// only a person's own save keeps the talk.
#[tokio::test]
async fn an_ai_suggestion_alone_saves_nothing() {
    let (dir, server) = auth_test_server();
    let room = room(&server);
    let mina = slip("mina", room.mina, "human");
    let owner = slip("owner", room.owner, "human");
    let companion = slip("companion", room.companion, "agent");

    start(&server, owner.clone(), room.id, "porch").await;
    let said = say(&server, owner.clone(), room.id, "porch", 100, SECRET_WORDS).await;

    let (status, suggested) =
        act(&server, "suggest-save", companion.clone(), room.id, "porch").await;
    assert_eq!(status, StatusCode::OK, "{suggested}");
    assert_eq!(
        notices(&server, mina.clone(), room.id, "porch").await,
        [("save_suggested".to_owned(), room.companion.to_hex())]
    );
    assert!(server.vault().get(&said).unwrap().is_none());
    assert!(!stored(&dir, SECRET_WORDS), "a suggestion saved the talk");

    for path in ["save", "export"] {
        let (status, refused) = act(&server, path, companion.clone(), room.id, "porch").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {refused}");
    }
    let (status, refused) = start(&server, companion.clone(), room.id, "agent-room").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    // A person cannot pass off a suggestion as theirs.
    let (status, refused) = act(&server, "suggest-save", mina.clone(), room.id, "porch").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(server.vault().get(&said).unwrap().is_none());
    assert!(!stored(&dir, SECRET_WORDS));

    // The person's tap saves.
    let (status, saved) = act(&server, "save", owner, room.id, "porch").await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert!(server.vault().get(&said).unwrap().is_some());
}

/// Someone outside the room learns nothing of a stretch in it, not even from
/// a name it took: each room names its own stretches. The vault's owner,
/// outside the room, cannot reach it through their own routes either. A
/// person who joined late takes away and reads only what their membership
/// shows them.
#[tokio::test]
async fn outsiders_see_nothing_and_a_late_joiner_sees_only_their_part() {
    let (_dir, server) = auth_test_server();
    let owner_id = server.vault().ensure_embedded_owner_actor().unwrap();
    let mina = person(&server, "Mina");
    let ravi = person(&server, "Ravi");
    // A room the vault's owner is not in.
    let attic = conversation(&server, owner_id, &[mina]);
    let other = conversation(&server, owner_id, &[ravi]);
    let (mina_slip, ravi_slip) = (slip("mina", mina, "human"), slip("ravi", ravi, "human"));
    let owner_door = owner_recipe(&server);

    let (status, _) = start(&server, mina_slip.clone(), attic, "attic").await;
    assert_eq!(status, StatusCode::OK);
    say(
        &server,
        mina_slip.clone(),
        attic,
        "attic",
        100,
        SECRET_WORDS,
    )
    .await;
    let (status, _) = act(&server, "save", mina_slip.clone(), attic, "attic").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = act(&server, "export", mina_slip.clone(), attic, "attic").await;
    assert_eq!(status, StatusCode::OK);

    // Only an agent suggests, so the outsider suggesting is Ravi's agent.
    let ravi_agent = slip("ravi-agent", ravi, "agent");
    for (path, who) in [
        ("save", &ravi_slip),
        ("export", &ravi_slip),
        ("suggest-save", &ravi_agent),
    ] {
        let (status, refused) = act(&server, path, who.clone(), attic, "attic").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {refused}");
    }
    let (status, _) = call(
        &server,
        "GET",
        &format!(
            "/v1/core/off-record?room={}&session_ref=attic",
            attic.to_hex()
        ),
        ravi_slip.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, refused) = call(
        &server,
        "POST",
        "/v1/core/off-record/witness",
        ravi_slip.clone(),
        Some(&turn(attic, "attic", 101, "let me in")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");
    // The same name in Ravi's own room is free.
    let (status, started) = start(&server, ravi_slip.clone(), other, "attic").await;
    assert_eq!(status, StatusCode::OK, "{started}");
    // The owner is not in the attic: their own routes find nothing there.
    let attic_key = json!({ "session_ref": owner_key(attic, "attic") });
    for path in ["/v1/owner/off-record/save", "/v1/owner/off-record/close"] {
        let (status, refused) =
            call(&server, "POST", path, owner_door.clone(), Some(&attic_key)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {refused}");
    }
    let (status, _) = call(
        &server,
        "GET",
        &format!(
            "/v1/owner/off-record?session_ref={}",
            owner_key(attic, "attic")
        ),
        owner_door,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Ravi joins the attic just after Mina's export, without its history.
    let exported_at = server
        .vault()
        .off_record_session(&owner_key(attic, "attic"))
        .unwrap()
        .unwrap()
        .notices[0]
        .at;
    let joined = exported_at + 1;
    server
        .vault()
        .join_member(
            attic,
            ravi,
            WriteActor::new(owner_id, EdgeActorClass::Human),
            joined,
            HistoryChoice::None,
        )
        .unwrap();
    say(
        &server,
        mina_slip,
        attic,
        "attic",
        joined + 10,
        "welcome, Ravi",
    )
    .await;
    let (status, file) = act(&server, "export", ravi_slip.clone(), attic, "attic").await;
    assert_eq!(status, StatusCode::OK, "{file}");
    assert_eq!(words(&file), ["welcome, Ravi"]);
    // Mina's export came before Ravi's time in the room.
    let seen = notices(&server, ravi_slip, attic, "attic").await;
    assert!(
        !seen.contains(&("exported".to_owned(), mina.to_hex())),
        "{seen:?}"
    );
}

/// Astra #1373 P1: a save kept the hidden messages of a turn (an agent's own
/// reasoning) that no one in the room was shown. A saved copy holds what the
/// room showed its saver, as an export does: the visible messages, with no
/// hidden text in the vault or its text index. The owner's own whole-talk
/// save keeps the same.
#[tokio::test]
async fn a_save_keeps_only_what_the_room_showed() {
    const SHOWN: &str = "the tide turns at noon";
    let (dir, server) = auth_test_server();
    let room = room(&server);
    let owner = slip("owner", room.owner, "human");
    let companion = slip("companion", room.companion, "agent");
    let owner_door = owner_recipe(&server);

    for (session_ref, hidden) in [
        ("study", "pelican whispers seven"),
        ("den", "walrus murmurs eleven"),
    ] {
        start(&server, owner.clone(), room.id, session_ref).await;
        let mut said = turn(room.id, session_ref, 100, SHOWN);
        said["turn"]["messages"] = json!([
            {
                "id": null, "author": "companion", "message_type": "utterance",
                "content": SHOWN, "metadata": null, "is_visible": true, "order": 0,
            },
            {
                "id": null, "author": "companion", "message_type": "executor.think",
                "content": hidden, "metadata": null, "is_visible": false, "order": 1,
            },
        ]);
        let (status, receipt) = call(
            &server,
            "POST",
            "/v1/core/off-record/witness",
            companion.clone(),
            Some(&said),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        let (status, saved) = if session_ref == "study" {
            act(&server, "save", owner.clone(), room.id, session_ref).await
        } else {
            call(
                &server,
                "POST",
                "/v1/owner/off-record/save",
                owner_door.clone(),
                Some(&json!({ "session_ref": owner_key(room.id, session_ref) })),
            )
            .await
        };
        assert_eq!(status, StatusCode::OK, "{saved}");
        assert_eq!(saved["saved"][0]["turn"], witnessed(&receipt).to_hex());
        let (status, closed) = call(
            &server,
            "POST",
            "/v1/owner/off-record/close",
            owner_door.clone(),
            Some(&json!({ "session_ref": owner_key(room.id, session_ref) })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{closed}");

        assert!(
            stored(&dir, SHOWN),
            "{session_ref}: the shown message was saved"
        );
        assert!(
            !stored(&dir, hidden),
            "{session_ref}: a hidden message reached the vault"
        );
        assert!(
            server.vault().search_text(hidden, 10).unwrap().is_empty(),
            "{session_ref}: the text index holds hidden text"
        );
    }
    assert!(!server.vault().search_text(SHOWN, 10).unwrap().is_empty());
}

/// Astra #1373 P1: the owner put the room on record, left it, and the next
/// turn of someone still there landed in the owner's vault. Saving stays
/// bound to the owner who started it: once they leave, it stops, the room
/// hears so, and later turns stay off record.
#[tokio::test]
async fn saving_from_here_stops_when_its_saver_leaves() {
    let (dir, server) = auth_test_server();
    let room = room(&server);
    let mina = slip("mina", room.mina, "human");
    let owner = slip("owner", room.owner, "human");
    let key = owner_key(room.id, "deck");

    start(&server, owner, room.id, "deck").await;
    let (status, flipped) = call(
        &server,
        "POST",
        "/v1/owner/off-record/mode",
        owner_recipe(&server),
        Some(&json!({ "session_ref": key, "mode": "on_record" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{flipped}");
    let kept = say(
        &server,
        mina.clone(),
        room.id,
        "deck",
        100,
        "said on record",
    )
    .await;
    assert!(server.vault().get(&kept).unwrap().is_some());

    server
        .vault()
        .leave_member(
            room.id,
            room.owner,
            WriteActor::new(room.owner, EdgeActorClass::Human),
            50,
        )
        .unwrap();
    let said = [
        say(&server, mina.clone(), room.id, "deck", 101, SECRET_WORDS).await,
        say(&server, mina.clone(), room.id, "deck", 102, "and again").await,
    ];
    for turn in said {
        assert!(server.vault().get(&turn).unwrap().is_none());
    }
    assert!(
        !stored(&dir, SECRET_WORDS),
        "a turn said after the saver left landed in their vault"
    );
    assert_eq!(
        notices(&server, mina.clone(), room.id, "deck").await,
        [
            ("saving_from_here".to_owned(), room.owner.to_hex()),
            ("saving_stopped".to_owned(), room.owner.to_hex()),
        ]
    );
    let record = server.vault().off_record_session(&key).unwrap().unwrap();
    assert_eq!(record.mode, oneiron::off_record::OffRecordMode::OffRecord);
    let (status, file) = act(&server, "export", mina, room.id, "deck").await;
    assert_eq!(status, StatusCode::OK, "{file}");
    assert_eq!(words(&file), ["said on record", SECRET_WORDS, "and again"]);
}

/// Astra #1373 P1: an export whose slip was revoked after its headers were
/// checked, while its body was still on the way, released the talk, even
/// what was said after the revocation. The slip is checked again with the
/// talk gathered: the export is refused, nothing is released and nobody is
/// told.
#[tokio::test]
async fn an_export_whose_slip_was_revoked_meanwhile_releases_nothing() {
    let (_dir, server) = auth_test_server();
    let room = room(&server);
    let mina_recipe = recipe("mina", room.mina, "human");
    let owner = slip("owner", room.owner, "human");

    start(&server, owner.clone(), room.id, "loft").await;
    say(&server, owner.clone(), room.id, "loft", 100, "before").await;

    // The headers arrive; the body waits until the slip is revoked.
    let (polled, body_asked) = tokio::sync::oneshot::channel::<()>();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let body = json!({ "room": room.id.to_hex(), "session_ref": "loft" }).to_string();
    let stream = futures_util::stream::once(async move {
        let _ = polled.send(());
        let _ = released.await;
        Ok::<_, std::io::Error>(body)
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/core/off-record/export")
        .header(AUTHORIZATION, test_bearer(&mina_recipe))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .unwrap();
    let request = slip_credentials::bind_request(&server, request);
    let export = tokio::spawn(api_routes(server.clone()).oneshot(request));
    body_asked.await.unwrap();
    slip_credentials::revoke(&server, &mina_recipe);
    say(&server, owner.clone(), room.id, "loft", 101, SECRET_WORDS).await;
    release.send(()).unwrap();

    let response = export.await.unwrap().unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body:?}");
    assert!(
        !String::from_utf8_lossy(&body).contains(SECRET_WORDS),
        "the revoked slip took the talk"
    );
    assert!(
        notices(&server, owner, room.id, "loft").await.is_empty(),
        "the room heard of an export that released nothing"
    );
}

/// Astra #1373 P2: an owner's witness bound to the room before the owner was
/// removed from it still landed. The owner's place on the roster is checked
/// again in the transaction that lands the turn, as a participant's is.
#[tokio::test]
async fn an_owner_removed_from_the_room_cannot_speak_into_it() {
    let (_dir, server) = auth_test_server();
    let room = room(&server);
    let mina = slip("mina", room.mina, "human");
    let owner = slip("owner", room.owner, "human");
    start(&server, owner, room.id, "yard").await;

    let vault = server.vault();
    let proof = vault
        .authenticate_owner(
            room.owner,
            &room.owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    // Bound while the owner was in the room; the removal lands before the
    // turn does.
    let session = vault
        .off_record_session_vault()
        .bind_for(&owner_key(room.id, "yard"), room.owner)
        .unwrap();
    vault
        .leave_member(
            room.id,
            room.owner,
            WriteActor::new(room.owner, EdgeActorClass::Human),
            50,
        )
        .unwrap();
    let said: oneiron::memory::WitnessTurn =
        serde_json::from_value(turn(room.id, "yard", 100, SECRET_WORDS)["turn"].clone()).unwrap();
    let refused = vault
        .memory(room.owner, EdgeActorClass::Human)
        .witness_into_session_as(&proof, &session, &said, None)
        .unwrap_err();
    assert_eq!(
        refused.code,
        oneiron::memory::MEMORY_CODE_FORBIDDEN,
        "{refused:?}"
    );

    let (status, file) = act(&server, "export", mina, room.id, "yard").await;
    assert_eq!(status, StatusCode::OK, "{file}");
    assert!(words(&file).is_empty(), "the turn landed: {file}");
}

/// Sol #1373 r6 P2: the owner put the room on record, the credential they
/// did it with was revoked, and their fresh flip on a new credential kept the
/// revoked one as the saver, so the room went off record instead. A saver
/// who no longer holds is let go before the flip decides anything.
#[tokio::test]
async fn a_fresh_flip_restarts_saving_after_its_credential_lapsed() {
    let (_dir, server) = auth_test_server();
    let room = room(&server);
    let mina = slip("mina", room.mina, "human");
    let key = owner_key(room.id, "garage");
    let owner = room.owner.to_hex();
    let [first, second] = ["first", "second"]
        .map(|jti| format!("jti=owner-{jti};principal_ref={owner};actor_class=human"));
    let flip = json!({ "session_ref": key, "mode": "on_record" });

    start(&server, mina.clone(), room.id, "garage").await;
    let (status, flipped) = call(
        &server,
        "POST",
        "/v1/owner/off-record/mode",
        test_bearer(&first),
        Some(&flip),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{flipped}");
    slip_credentials::revoke(&server, &first);
    let (status, flipped) = call(
        &server,
        "POST",
        "/v1/owner/off-record/mode",
        test_bearer(&second),
        Some(&flip),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{flipped}");
    assert_eq!(flipped["mode"], "on_record", "{flipped}");
    let kept = say(&server, mina, room.id, "garage", 100, "kept on record").await;
    assert!(server.vault().get(&kept).unwrap().is_some());
}
