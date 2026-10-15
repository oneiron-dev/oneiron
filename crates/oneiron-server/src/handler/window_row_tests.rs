//! `max_windows_per_connection` is a row, never a refusal (rule 5, OF-520): a socket past it is
//! served, keeps a bounded set of window subscriptions, still receives every change of a window
//! it forgot, and keeps every document it subscribes. A frame that names no exchange, or is
//! refused, creates no window, and an update that adds nothing wakes no socket.

use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use futures_util::{SinkExt, StreamExt};
use loro::{ExportMode, VersionVector};
use oneiron::sync::schema::read_window_list;
use oneiron::sync::transport::{self, document_sub_tags, window_sub_tags};
use oneiron::sync::{SyncClient, SyncClientConfig, SyncResidenceMode, WindowKey, WindowManager};
use oneiron::{EntityId, Vault, VaultConfig};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const SECRET: &str = "window-row-fixture-root";

/// A home serving sockets, its row set to `row` windows per connection.
struct Home {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    task: tokio::task::JoinHandle<()>,
    url: String,
}

impl Drop for Home {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Home {
    async fn start(row: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
        let server = Arc::new(
            SyncServer::new(
                vault,
                SyncServerConfig {
                    auth_secret: Some(SECRET.into()),
                    max_windows_per_connection: row,
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        let task = tokio::spawn({
            let server = server.clone();
            async move {
                axum::serve(listener, crate::build_app(server))
                    .await
                    .unwrap();
            }
        });
        Self {
            _dir: dir,
            server,
            task,
            url,
        }
    }

    /// A socket that spoke `hello`.
    async fn socket(&self, jti: &str, hello: Vec<u8>) -> Socket {
        let mut request = self.url.as_str().into_client_request().unwrap();
        crate::test_credentials::bind_ws_request(&self.server, &mut request, &format!("jti={jti}"));
        let mut socket = tokio_tungstenite::connect_async(request).await.unwrap().0;
        send(&mut socket, hello).await;
        socket
    }

    fn lists(&self, key: &WindowKey) -> bool {
        read_window_list(&self.server.root_doc).contains(key)
    }

    /// An UPDATE for `key` that writes one new PERSON row dated inside it.
    async fn change(&self, key: &WindowKey, at: u64) -> Change {
        let doc = self.server.get_or_create_window(key).await.unwrap();
        let base = doc.oplog_vv();
        let edit = doc.fork();
        let id = EntityId::now();
        let mut row = vec![oneiron::registry::ENTITY_TYPE_PERSON];
        for _ in 0..3 {
            row.extend_from_slice(&at.to_be_bytes());
        }
        row.extend_from_slice(b"placeholder person");
        edit.get_map("entities")
            .insert(&id.to_hex(), row.as_slice())
            .unwrap();
        edit.commit();
        let update = edit.export(ExportMode::updates(&base)).unwrap();
        let frame = transport::encode_window_sync(key.as_str(), window_sub_tags::UPDATE, &update)
            .into_result()
            .unwrap();
        Change { frame, id, update }
    }
}

/// One row written into a window, as the frame that relays it.
struct Change {
    frame: Vec<u8>,
    id: EntityId,
    update: Vec<u8>,
}

async fn send(socket: &mut Socket, frame: Vec<u8>) {
    socket.send(Message::Binary(frame.into())).await.unwrap();
}

/// `count` window keys a month apart, each with a timestamp inside it.
fn months(count: u64) -> Vec<(WindowKey, u64)> {
    const DAY: u64 = 86_400;
    let windows: Vec<_> = (0..count)
        .map(|n| {
            let at = 1_577_836_800 + (n * 31 + 14) * DAY;
            (WindowKey::from_timestamp(at), at)
        })
        .collect();
    let distinct: std::collections::BTreeSet<_> =
        windows.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(distinct.len(), windows.len(), "fixture: one key per month");
    windows
}

/// Everything a socket received until it went quiet for `quiet`, by window, as raw frames, and
/// the close code if the server closed it.
#[derive(Default)]
struct Heard {
    frames: BTreeMap<String, Vec<Vec<u8>>>,
    close: Option<u16>,
}

impl Heard {
    fn tags(&self, key: &WindowKey) -> Vec<u8> {
        self.frames
            .get(key.as_str())
            .into_iter()
            .flatten()
            .map(|frame| transport::decode_window_sync(&frame[1..]).unwrap().1)
            .collect()
    }

    /// Whether an UPDATE for `key` brought `change`: its own bytes relayed, or a whole export
    /// holding its row.
    fn pushed(&self, key: &WindowKey, change: &Change) -> bool {
        self.frames
            .get(key.as_str())
            .into_iter()
            .flatten()
            .any(|frame| {
                let (_, tag, payload) = transport::decode_window_sync(&frame[1..]).unwrap();
                tag == window_sub_tags::UPDATE
                    && (payload == change.update.as_slice() || carries(payload, change.id))
            })
    }
}

/// Reads `socket` until it is quiet for `quiet`, it closes, or a frame tagged `until` arrives
/// for `key`.
async fn listen(socket: &mut Socket, quiet: Duration, until: Option<(&WindowKey, u8)>) -> Heard {
    let mut heard = Heard::default();
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let message = match tokio::time::timeout(quiet, socket.next()).await {
                Ok(Some(Ok(message))) => message,
                // The home ends a socket it refuses without a close frame (1006).
                Ok(None | Some(Err(_))) => {
                    heard.close = Some(1006);
                    return;
                }
                Err(_) => return,
            };
            match message {
                Message::Close(frame) => {
                    heard.close = Some(frame.map_or(0, |frame| u16::from(frame.code)));
                    return;
                }
                Message::Binary(frame) if frame.first() == Some(&transport::TAG_WINDOW_SYNC) => {
                    let (key, tag, _) = transport::decode_window_sync(&frame[1..]).unwrap();
                    let done =
                        until.is_some_and(|(want, last)| want.as_str() == key && last == tag);
                    heard
                        .frames
                        .entry(key.to_owned())
                        .or_default()
                        .push(frame.to_vec());
                    if done {
                        return;
                    }
                }
                _ => {}
            }
        }
    })
    .await;
    heard
}

/// Asks for `key` with an empty vector and reads until the home's own vector arrives.
async fn subscribe(socket: &mut Socket, key: &WindowKey) -> Heard {
    let request = transport::encode_window_sync(
        key.as_str(),
        window_sub_tags::VV_REQUEST,
        &VersionVector::new().encode(),
    )
    .into_result()
    .unwrap();
    send(socket, request).await;
    listen(
        socket,
        Duration::from_secs(5),
        Some((key, window_sub_tags::VV_RESPONSE)),
    )
    .await
}

/// Whether `bytes`, imported into an empty document, hold `id`'s row.
fn carries(bytes: &[u8], id: EntityId) -> bool {
    let doc = loro::LoroDoc::new();
    doc.import(bytes).is_ok() && doc.get_map("entities").get(&id.to_hex()).is_some()
}

/// Bug repro (rule 5, learning #98): a v13 socket asked for more windows than the row and the
/// home closed it. Done-means: a flood of windows one socket asks for, each a key the home never
/// held, is served whole, and the socket is pushed changes for only the `row` it asked for last.
#[tokio::test]
async fn a_window_flood_is_served_and_pushes_only_the_row_it_asked_for_last() {
    const ROW: usize = 2;
    let home = Home::start(ROW).await;
    let windows = months(6);
    let mut owner = home
        .socket(
            "window-row-flood",
            transport::encode_replacement_full_window_protocol_hello(),
        )
        .await;
    for (key, _) in &windows {
        let heard = subscribe(&mut owner, key).await;
        assert_eq!(heard.close, None, "{key}: the home closed the socket");
        assert!(
            heard.tags(key).contains(&window_sub_tags::VV_RESPONSE),
            "{key}: not served: {:?}",
            heard.tags(key)
        );
    }

    let mut writer = home
        .socket(
            "window-row-writer",
            transport::encode_replacement_full_window_protocol_hello(),
        )
        .await;
    let mut written = Vec::new();
    for (key, at) in &windows {
        let change = home.change(key, *at).await;
        send(&mut writer, change.frame.clone()).await;
        written.push((key, change));
    }
    let heard = listen(&mut owner, Duration::from_secs(3), None).await;
    assert_eq!(heard.close, None);
    let pushed: Vec<_> = written
        .iter()
        .filter(|(key, change)| heard.pushed(key, change))
        .map(|(key, _)| (*key).clone())
        .collect();
    let last: Vec<_> = windows[windows.len() - ROW..]
        .iter()
        .map(|(key, _)| key.clone())
        .collect();
    assert_eq!(
        pushed, last,
        "the socket keeps a subscription past the row, or lost one inside it"
    );
    for (key, _) in &windows[..windows.len() - ROW] {
        assert!(
            !heard.tags(key).is_empty(),
            "{key}: a forgotten window's change sent nothing"
        );
    }
}

/// Done-means (Engine ruling, 10-15): after the home forgets a socket's window, the peer still
/// receives that window's next change, through its own client, and every change after it.
#[tokio::test]
async fn a_forgotten_window_still_reaches_its_peer() {
    let home = Home::start(1).await;
    let windows = months(2);
    let ((forgotten, at), (kept, _)) = (windows[0].clone(), windows[1].clone());
    for (key, _) in &windows {
        home.server.get_or_create_window(key).await.unwrap();
    }
    let mut owner = home
        .socket(
            "window-row-peer",
            transport::encode_replacement_full_window_protocol_hello(),
        )
        .await;
    for key in [&forgotten, &kept] {
        let heard = subscribe(&mut owner, key).await;
        assert_eq!(heard.close, None, "{key}: the home closed the socket");
    }

    let mut writer = home
        .socket(
            "window-row-peer-writer",
            transport::encode_replacement_full_window_protocol_hello(),
        )
        .await;
    let missed = home.change(&forgotten, at).await;
    send(&mut writer, missed.frame.clone()).await;
    let heard = listen(&mut owner, Duration::from_secs(3), None).await;
    assert_eq!(heard.close, None);
    let notices = heard
        .frames
        .get(forgotten.as_str())
        .cloned()
        .unwrap_or_default();
    assert!(
        !notices.is_empty(),
        "the forgotten window's change sent nothing"
    );

    // The device's own client answers what the home sent.
    let device_dir = tempfile::tempdir().unwrap();
    let device = Arc::new(Vault::open(device_dir.path(), VaultConfig::device()).unwrap());
    let manager = Arc::new(WindowManager::new(
        device,
        Arc::new(oneiron::sync::bridge::Materializer::new()),
        "device",
    ));
    let (mut client, _events) = SyncClient::new(
        manager,
        SyncClientConfig {
            residence_mode: SyncResidenceMode::All,
            ..Default::default()
        },
    )
    .unwrap();
    let mut answers = Vec::new();
    for frame in &notices {
        answers.extend(client.handle_server_message(frame).unwrap());
    }
    assert!(!answers.is_empty(), "the client let the change go");
    for answer in answers {
        send(&mut owner, answer).await;
    }
    let caught_up = listen(
        &mut owner,
        Duration::from_secs(5),
        Some((&forgotten, window_sub_tags::VV_RESPONSE)),
    )
    .await;
    assert_eq!(caught_up.close, None);
    assert!(
        caught_up.pushed(&forgotten, &missed),
        "the peer never received the change: {:?}",
        caught_up.tags(&forgotten)
    );

    // Asked again, the window is pushed again.
    let next = home.change(&forgotten, at).await;
    send(&mut writer, next.frame.clone()).await;
    let heard = listen(&mut owner, Duration::from_secs(3), None).await;
    assert!(
        heard.pushed(&forgotten, &next),
        "the next change was not pushed"
    );
}

/// Bug repro (rule 5): an owner socket's NOTE subscription past the row was refused. Done-means:
/// the socket keeps every one.
#[tokio::test]
async fn an_owner_note_subscription_past_the_row_is_served() {
    let _ = subscribe_owner_notes(1);
}

/// An owner v13 socket subscribed to two NOTEs on a home whose row is `row`, each served.
fn subscribe_owner_notes(row: usize) -> (tempfile::TempDir, SyncServer) {
    use super::{conn_state::ConnState, documents::handle_document};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let notes = ["placeholder one", "placeholder two"].map(|text| {
        vault
            .create_note(
                "research",
                text,
                oneiron::WriteActor::new(owner, oneiron::EdgeActorClass::Human),
            )
            .unwrap()
    });
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(SECRET.into()),
            max_windows_per_connection: row,
            ..Default::default()
        },
    )
    .unwrap();
    let mut state = ConnState::new(transport::REPLACEMENT_FULL_WINDOW_PROTOCOL_VERSION);
    state.bound_auth = Some(crate::test_credentials::authenticate(
        &server,
        &format!(
            "scope=core:read,core:write;principal_ref={};actor_class=human;jti=window-row-notes",
            owner.to_hex()
        ),
    ));
    let (direct, mut replies) = tokio::sync::mpsc::unbounded_channel();
    let request = [
        0u32.to_be_bytes().as_slice(),
        &VersionVector::new().encode(),
    ]
    .concat();
    for note in notes {
        handle_document(
            &server,
            1,
            note,
            document_sub_tags::REQUEST,
            &request,
            &direct,
            &mut state,
        )
        .unwrap_or_else(|error| panic!("a NOTE subscription was refused: {error}"));
        assert!(replies.try_recv().is_ok(), "the NOTE was not served");
    }
    assert_eq!(state.owner_documents.len(), 2);
    (dir, server)
}

/// Bug repro (rule 5): the home refused a socket's selector document subscription past the row.
/// Done-means: every one is served.
#[tokio::test]
async fn a_selector_document_subscription_past_the_row_is_served() {
    let _ = subscribe_selector_documents(1);
}

/// A selector socket subscribed to two documents under one facet on a home whose row is `row`,
/// each served.
fn subscribe_selector_documents(row: usize) -> (tempfile::TempDir, SyncServer) {
    use super::{conn_state::ConnState, documents::handle_document};
    use oneiron::{TimeRange, registry};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let facet = EntityId::now();
    vault
        .put_entity(
            &facet,
            registry::ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"placeholder facet",
        )
        .unwrap();
    let ids = [b"placeholder one", b"placeholder two"].map(|body| {
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                registry::ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                body,
            )
            .unwrap();
        vault
            .put_edge(&id, oneiron::EdgeKind::FacetOf, &facet, 1.0)
            .unwrap();
        id
    });
    let member = EntityId::now();
    let grant_id = EntityId::now();
    let grant = oneiron::federation::FederationGrant::new(
        oneiron::FederationGrantScope::vault(7),
        member,
        oneiron::federation::FederationGrantRole::Member,
        oneiron::federation::FederationGrantPreset::Member,
    );
    oneiron::sync::put_selector_test_federation_grant(&vault, &grant_id, &grant, 1).unwrap();
    let selector = oneiron::sync::SyncSelector::new(
        grant_id,
        member,
        oneiron::sync::SyncSelectorWorld::All,
        vec![facet],
        vec![oneiron::federation::SelectorRange::Core],
    );
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(SECRET.into()),
            max_windows_per_connection: row,
            ..Default::default()
        },
    )
    .unwrap();
    let mut state = ConnState::new(transport::PROTOCOL_VERSION);
    state.bound_auth = Some(crate::test_credentials::authenticate(
        &server,
        &format!(
            "scope=core:read,core:write;principal_ref={}",
            member.to_hex()
        ),
    ));
    let (direct, mut replies) = tokio::sync::mpsc::unbounded_channel();
    let request =
        oneiron::sync::encode_selector_vv_request(&selector, &VersionVector::new().encode())
            .unwrap();
    for id in ids {
        handle_document(
            &server,
            1,
            id,
            document_sub_tags::REQUEST,
            &request,
            &direct,
            &mut state,
        )
        .unwrap_or_else(|error| panic!("a document subscription was refused: {error}"));
        assert!(replies.try_recv().is_ok(), "the document was not served");
    }
    assert_eq!(state.documents.len(), 2);
    (dir, server)
}

/// Bug repro: a frame naming no exchange, or a residence update for a window its socket never
/// promoted, created the window it named before it was answered. Done-means: neither creates
/// one, and an unknown sub-tag still closes nothing.
#[tokio::test]
async fn a_key_that_names_no_exchange_creates_no_window() {
    let home = Home::start(64).await;
    let windows = months(3);
    let mut owner = home
        .socket(
            "window-row-unknown",
            transport::encode_replacement_full_window_protocol_hello(),
        )
        .await;
    for (key, _) in &windows[..2] {
        let frame = transport::encode_window_sync(key.as_str(), 200, b"placeholder")
            .into_result()
            .unwrap();
        send(&mut owner, frame).await;
    }
    let real = &windows[2].0;
    let heard = subscribe(&mut owner, real).await;
    assert_eq!(heard.close, None, "an unknown sub-tag closed the socket");
    for (key, _) in &windows[..2] {
        assert!(
            !home.lists(key),
            "{key}: an unknown sub-tag created its window"
        );
    }

    let fabricated = WindowKey::from_timestamp(1_000_000_000);
    let mut device = home
        .socket(
            "window-row-residence",
            transport::encode_replacement_residence_protocol_hello(),
        )
        .await;
    let mut update = 1u64.to_be_bytes().to_vec();
    update.extend_from_slice(b"placeholder");
    let frame = transport::encode_window_sync(
        fabricated.as_str(),
        window_sub_tags::RESIDENCE_UPDATE,
        &update,
    )
    .into_result()
    .unwrap();
    send(&mut device, frame).await;
    let heard = listen(&mut device, Duration::from_secs(3), None).await;
    assert!(
        heard.close.is_some(),
        "an unpromoted residence update was taken"
    );
    assert!(
        !home.lists(&fabricated),
        "an unpromoted residence update created its window"
    );
}

/// Bug repro (SOL-S3-007, ASTRA-S3-005): an update that adds no operation, such as the catch-up
/// reply every exchange ends with, was kept and relayed like a change. Past the row, two sockets'
/// catch-ups then woke each other for ever. Done-means: an update that adds nothing wakes no
/// socket.
#[tokio::test]
async fn an_update_that_adds_nothing_wakes_no_socket() {
    let home = Home::start(64).await;
    let (key, at) = months(1).remove(0);
    let mut owner = home
        .socket(
            "window-row-quiet",
            transport::encode_replacement_full_window_protocol_hello(),
        )
        .await;
    assert_eq!(subscribe(&mut owner, &key).await.close, None);
    let mut writer = home
        .socket(
            "window-row-quiet-writer",
            transport::encode_replacement_full_window_protocol_hello(),
        )
        .await;
    let change = home.change(&key, at).await;
    send(&mut writer, change.frame.clone()).await;
    let heard = listen(&mut owner, Duration::from_secs(3), None).await;
    assert!(heard.pushed(&key, &change), "fixture: the change is pushed");

    send(&mut writer, change.frame.clone()).await;
    let heard = listen(&mut owner, Duration::from_secs(3), None).await;
    assert_eq!(heard.close, None);
    assert!(
        heard.tags(&key).is_empty(),
        "an update that adds nothing woke the socket: {:?}",
        heard.tags(&key)
    );
}

/// Bug repro (ASTRA-S3-008): a vector that does not decode was refused only after the window it
/// names was created. Done-means: the refused frame creates nothing.
#[tokio::test]
async fn a_vector_that_does_not_decode_creates_no_window() {
    let home = Home::start(64).await;
    let (key, _) = months(1).remove(0);
    let mut owner = home
        .socket(
            "window-row-bad-vector",
            transport::encode_replacement_full_window_protocol_hello(),
        )
        .await;
    let frame =
        transport::encode_window_sync(key.as_str(), window_sub_tags::VV_REQUEST, b"placeholder")
            .into_result()
            .unwrap();
    send(&mut owner, frame).await;
    let heard = listen(&mut owner, Duration::from_secs(3), None).await;
    assert!(
        heard.close.is_some(),
        "a vector that does not decode was taken"
    );
    assert!(!home.lists(&key), "the refused frame created its window");
}

// The row's question (OF-520) is new with the fix: the checks below have no counterpart on the
// tree before it.

/// Done-means (OF-520): a socket past the row asks the row's question once, with what it held
/// when it crossed, for windows and for documents alike, and the question is kept on the vault.
#[tokio::test]
async fn crossing_the_row_asks_its_question_once() {
    use super::conn_state::ConnState;
    use super::window_sync::handle_window_sync;
    use crate::wire_telemetry::{LimitRow, WireQuestionKind};
    let home = Home::start(1).await;
    let (direct, _replies) = tokio::sync::mpsc::unbounded_channel();
    let mut state = ConnState::new(transport::REPLACEMENT_FULL_WINDOW_PROTOCOL_VERSION);
    for (key, _) in months(3) {
        handle_window_sync(
            &home.server,
            1,
            key.as_str(),
            window_sub_tags::VV_REQUEST,
            &VersionVector::new().encode(),
            &direct,
            &mut state,
        )
        .await
        .unwrap();
    }
    let (_notes_dir, notes) = subscribe_owner_notes(1);
    let (_documents_dir, documents) = subscribe_selector_documents(1);
    for server in [home.server.as_ref(), &notes, &documents] {
        let questions = server.wire_telemetry.limit_questions();
        let question = questions
            .latest(LimitRow::WindowsPerConnection)
            .expect("crossing the row asked nothing");
        assert_eq!(question.kind, WireQuestionKind::InspectLimitCrossing);
        assert_eq!(question.row, "max_windows_per_connection");
        assert_eq!(
            (question.bound, question.observed),
            (1, 2),
            "the question names the first crossing"
        );
        server.wire_telemetry.flush().unwrap();
        let window = question.raised_at / 60 * 60;
        assert_eq!(
            server
                .wire_telemetry
                .limit_question(LimitRow::WindowsPerConnection, window)
                .unwrap(),
            Some(question),
            "the question is not kept"
        );
    }
}

/// The notice goes to every window a socket is not pushed once it forgot one, so a device that
/// does not follow a window must read the notice as nothing, never as an error that drops its
/// socket; one it follows it asks for again.
#[test]
fn a_device_asks_again_only_for_a_window_it_follows() {
    let dir = tempfile::tempdir().unwrap();
    let device = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let manager = Arc::new(WindowManager::new(
        device,
        Arc::new(oneiron::sync::bridge::Materializer::new()),
        "device",
    ));
    let (followed, other) = (EntityId::now(), EntityId::now());
    let (mut client, _events) = SyncClient::new(
        manager,
        SyncClientConfig {
            residence_mode: SyncResidenceMode::All,
            followed_worlds: Some(vec![followed]),
            ..Default::default()
        },
    )
    .unwrap();
    let at = 1_577_836_800;
    for (world, asks) in [(followed, true), (other, false)] {
        let key = WindowKey::for_world(at, world);
        let notice =
            transport::encode_window_sync(key.as_str(), window_sub_tags::WINDOW_INVALIDATE, &[])
                .into_result()
                .unwrap();
        let answers = client.handle_server_message(&notice).unwrap();
        let asked = answers.iter().any(|frame| {
            frame.first() == Some(&transport::TAG_WINDOW_SYNC)
                && transport::decode_window_sync(&frame[1..]).is_ok_and(|(asked, tag, _)| {
                    asked == key.as_str() && tag == window_sub_tags::VV_REQUEST
                })
        });
        assert_eq!(asked, asks, "{key}");
    }
}
