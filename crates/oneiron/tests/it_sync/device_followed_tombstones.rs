//! A device writes the delete marker of a followed world's item even for a
//! window it never held (FOLLOWED-WORLD-TIER1-TOMBSTONE-IDS; canon ARCH-0023b
//! :500: "Tier 1 ... also carries the tombstone id set for every followed
//! world. So a device writes the delete marker even for a window it never
//! held."; Engine ANSWER FOLLOWED-WORLD-TOMBSTONE-IDS-FIX-OR-PARK = A, Thu 19
//! Nov 12:44).
//!
//! The device runs its real `SyncConnection` against the fake home of
//! `device_world_follow_live.rs`, which serves `residence.tombstones` from a
//! planted set. Before the fix the device never asked for a followed world's
//! tombstones: an item it opened in a world whose window the home refused to
//! it stayed readable from its thin copy after the home hard-deleted it, and
//! no `dt:` marker was ever written for an id the device never held.
//!
//! `cargo test --locked -p oneiron --all-features --test it_sync -- device_followed_tombstones`.

use std::sync::Arc;

use loro::ExportMode;
use oneiron::EntityId;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::schema::create_root_doc;
use oneiron::sync::transport::{TAG_SYNC_UPDATE, window_sub_tags};
use oneiron::sync::{
    SyncClientConfig, SyncResidenceMode, SyncSelector, SyncSelectorWorld, WindowKey,
};
use tokio::sync::{mpsc, oneshot};

use super::device_world_follow::{Device, now_secs};
use super::device_world_follow_live::{
    FakeHome, HomeEvent, TombstoneHome, Watch, note_session, synced, world_asks,
};

/// Seconds in two years: the month of the old window a fresh device follows.
const TWO_YEARS_SECS: u64 = 2 * 365 * 24 * 3600;

/// A hard delete's tombstone value as the home's window holds it: reason
/// byte 2 (`user_hard_delete`), the delete time as a little-endian u64, and
/// the request id.
fn hard_tombstone(deleted_at: u64) -> Vec<u8> {
    let mut value = vec![2_u8];
    value.extend_from_slice(&deleted_at.to_le_bytes());
    value.extend_from_slice(EntityId::now().as_bytes());
    value
}

/// Whether the device holds the permanent local hard-delete marker of `id`.
fn marked(device: &Device, id: EntityId) -> bool {
    device
        .vault
        .sync_state_get(&format!("dt:{}", id.to_hex()))
        .expect("read the delete marker")
        .is_some()
}

/// The home's root update listing `windows`.
fn root_listing(windows: &[WindowKey]) -> Vec<u8> {
    let root = create_root_doc("server", "vault", windows);
    let mut frame = vec![TAG_SYNC_UPDATE];
    frame.extend_from_slice(&root.export(ExportMode::snapshot()).expect("root snapshot"));
    frame
}

/// Leaves `item` in the device's read cache as a touch in `window` leaves it:
/// the row, its document, and the window it was opened in.
fn cache_thin_item(device: &Device, item: EntityId, window: &WindowKey) {
    let at = window.start_timestamp().expect("the window's month");
    let mut row = vec![oneiron::registry::ENTITY_TYPE_PERSON];
    for field in [at, at, at, 0] {
        row.extend_from_slice(&field.to_be_bytes());
    }
    row.extend_from_slice(b"an opened item the home deletes");
    let id = item.to_hex();
    for (key, value) in [
        (format!("ri:b:{id}"), row),
        (format!("ri:d:{id}"), b"cached document".to_vec()),
        (format!("ro:e:{id}"), window.as_str().as_bytes().to_vec()),
    ] {
        device
            .vault
            .sync_state_put(&key, &value)
            .expect("FIXTURE: the thin read row");
    }
}

/// The device's opened-item connection to the fake home at `url`.
fn opened_connection(device: &Device, url: String) -> SyncConnection {
    SyncConnection::new(
        device.manager(),
        ConnectionConfig {
            client_config: SyncClientConfig {
                server_url: url,
                residence_mode: SyncResidenceMode::Opened,
                residence_selector: Some(SyncSelector::new(
                    EntityId::now(),
                    EntityId::now(),
                    SyncSelectorWorld::All,
                    Vec::new(),
                    Vec::new(),
                )),
                note_session: Some(note_session(device)),
                ..SyncClientConfig::default()
            },
            auto_reconnect: false,
        },
    )
    .expect("the device's connection")
}

/// Runs `connection` until its first negotiation reports `Synced`, then
/// shuts it down: what the home saw, in order.
async fn sync_once(connection: &SyncConnection, home: mpsc::UnboundedReceiver<HomeEvent>) -> Watch {
    let (shutdown, shutdown_rx) = oneshot::channel();
    let (sync_tx, sync) = mpsc::unbounded_channel();
    let run = connection.run_observed(shutdown_rx, move |event| {
        let _ = sync_tx.send(event);
    });
    let mut watch = Watch {
        home,
        sync,
        home_seen: Vec::new(),
        sync_seen: Vec::new(),
    };
    let script = async {
        watch
            .until("the first negotiation syncs", |_, sync| synced(sync) >= 1)
            .await;
        let _ = shutdown.send(());
    };
    let (_ran, ()) = tokio::join!(run, script);
    watch
}

/// Runs `test` on a thread with a large stack and its own runtime, as the
/// live socket tests do.
fn on_engine_stack<F>(name: &str, test: fn() -> F)
where
    F: std::future::Future<Output = ()> + 'static,
{
    let run = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(test());
        })
        .expect("test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

/// Case 1: the device opened item E of world P, whose window W the home
/// refuses to it (one other row of W is unreadable to it, so the follow
/// answers `FOLLOW_REFUSED`). The home hard-deleted E. After the device
/// connects, it holds `dt:E`, its thin copy of E is gone, and W is still not
/// held. Before, `thin_item(E)` kept serving the cached copy.
#[test]
fn a_refused_followed_window_still_marks_its_deleted_item() {
    on_engine_stack(
        "a_refused_followed_window_still_marks_its_deleted_item",
        refused_followed_window_still_marks_its_deleted_item,
    );
}

async fn refused_followed_window_still_marks_its_deleted_item() {
    let device = Device::open();
    let at = now_secs();
    let founder = WindowKey::for_world(at, device.founder);
    let item = EntityId::now();
    cache_thin_item(&device, item, &founder);
    let tombstones = Arc::new(TombstoneHome {
        refuse_follows: true,
        ..TombstoneHome::default()
    });
    tombstones
        .served
        .lock()
        .expect("the served tombstones")
        .insert(
            founder.as_str().to_owned(),
            vec![(item.to_hex(), hard_tombstone(at))],
        );
    let (url, home, release_index) = FakeHome::start_tombstones(
        root_listing(&[WindowKey::from_timestamp(at), founder.clone()]),
        Arc::clone(&tombstones),
    )
    .await;
    release_index.send(()).expect("the index read is not held");
    let connection = opened_connection(&device, url);
    assert!(
        connection
            .thin_item(item)
            .expect("read the thin copy")
            .is_some(),
        "FIXTURE: the device reads its thin copy of the item",
    );
    connection
        .set_followed_worlds([device.founder].into_iter().collect())
        .expect("the owner's pick");
    let watch = sync_once(&connection, home).await;

    assert!(
        world_asks(&watch.home_seen, 1)
            .contains(&(founder.as_str().to_owned(), window_sub_tags::FOLLOW_REQUEST)),
        "FIXTURE: the device asked the home to follow the window, which the home refused",
    );
    assert!(
        marked(&device, item),
        "the device holds the delete marker of the item the home deleted in its refused followed window",
    );
    assert!(
        connection
            .thin_item(item)
            .expect("read the thin copy")
            .is_none(),
        "the deleted item no longer reads from its thin copy",
    );
    for key in [format!("rp:w:{founder}"), format!("d:w:{founder}")] {
        assert!(
            device
                .vault
                .sync_state_get(&key)
                .expect("read the window row")
                .is_none(),
            "the refused window is still not held here ({key})",
        );
    }
}

/// Case 2: a fresh device follows world P, whose window of two years ago
/// holds the tombstone of an item E it never held. After it connects, it
/// holds `dt:E`: the window's age and the thin index's current months do not
/// bound the set, and an id with no local trace is still marked.
#[test]
fn a_fresh_device_marks_an_id_it_never_held() {
    on_engine_stack(
        "a_fresh_device_marks_an_id_it_never_held",
        fresh_device_marks_an_id_it_never_held,
    );
}

async fn fresh_device_marks_an_id_it_never_held() {
    let device = Device::open();
    let at = now_secs();
    let old = WindowKey::for_world(at - TWO_YEARS_SECS, device.founder);
    let current = WindowKey::for_world(at, device.founder);
    let item = EntityId::now();
    assert!(
        device.vault.get_raw(&item).expect("read the row").is_none(),
        "FIXTURE: the device never held the item",
    );
    let tombstones = Arc::new(TombstoneHome::default());
    tombstones
        .served
        .lock()
        .expect("the served tombstones")
        .insert(
            old.as_str().to_owned(),
            vec![(item.to_hex(), hard_tombstone(at - TWO_YEARS_SECS))],
        );
    let (url, home, release_index) = FakeHome::start_tombstones(
        root_listing(&[WindowKey::from_timestamp(at), old.clone(), current]),
        Arc::clone(&tombstones),
    )
    .await;
    release_index.send(()).expect("the index read is not held");
    let connection = opened_connection(&device, url);
    connection
        .set_followed_worlds([device.founder].into_iter().collect())
        .expect("the owner's pick");
    let _watch = sync_once(&connection, home).await;

    assert!(
        tombstones
            .asks
            .lock()
            .expect("the recorded asks")
            .contains(&old.as_str().to_owned()),
        "the device asks for the tombstones of its followed world's old window",
    );
    assert!(
        marked(&device, item),
        "the device holds the delete marker of an id it never held",
    );
}

/// Case 4: the home's window keeps one tombstone value that is no binary,
/// which the home answers as empty, beside a hard delete of item E. An empty
/// value decodes hard, as the window's replay reads it, so it never refuses
/// the page: the device writes `dt:E`, and the marker of the empty value's
/// id too (blind review 1 of #9593). Before, one empty value refused the
/// whole answer, and no delete of any followed window landed.
#[test]
fn an_empty_tombstone_value_lands_hard_beside_the_others() {
    on_engine_stack(
        "an_empty_tombstone_value_lands_hard_beside_the_others",
        empty_tombstone_value_lands_hard_beside_the_others,
    );
}

async fn empty_tombstone_value_lands_hard_beside_the_others() {
    let device = Device::open();
    let at = now_secs();
    let founder = WindowKey::for_world(at, device.founder);
    let mut items = [EntityId::now(), EntityId::now()];
    items.sort_unstable_by_key(EntityId::to_hex);
    let [empty_item, hard_item] = items;
    let tombstones = Arc::new(TombstoneHome::default());
    tombstones
        .served
        .lock()
        .expect("the served tombstones")
        .insert(
            founder.as_str().to_owned(),
            vec![
                (empty_item.to_hex(), Vec::new()),
                (hard_item.to_hex(), hard_tombstone(at)),
            ],
        );
    let (url, home, release_index) = FakeHome::start_tombstones(
        root_listing(&[WindowKey::from_timestamp(at), founder.clone()]),
        Arc::clone(&tombstones),
    )
    .await;
    release_index.send(()).expect("the index read is not held");
    let connection = opened_connection(&device, url);
    connection
        .set_followed_worlds([device.founder].into_iter().collect())
        .expect("the owner's pick");
    let _watch = sync_once(&connection, home).await;

    assert!(
        tombstones
            .asks
            .lock()
            .expect("the recorded asks")
            .contains(&founder.as_str().to_owned()),
        "FIXTURE: the device asks for its followed window's tombstones",
    );
    assert!(
        marked(&device, hard_item),
        "the window's hard delete lands beside a value that reads as empty",
    );
    assert!(
        marked(&device, empty_item),
        "a value that reads as empty decodes hard, as the window's replay reads it",
    );
}

/// Case 3: the owner picked worlds P and K, but K's read setting keeps it on
/// the owner's machines, which this device is not. The device asks for P's
/// tombstones and never for K's, and takes no marker from K's window, even
/// one the home would serve.
#[test]
fn a_withheld_world_is_never_asked_for_tombstones() {
    on_engine_stack(
        "a_withheld_world_is_never_asked_for_tombstones",
        withheld_world_is_never_asked_for_tombstones,
    );
}

async fn withheld_world_is_never_asked_for_tombstones() {
    let device = Device::open();
    let at = now_secs();
    let founder = WindowKey::for_world(at, device.founder);
    let kept = WindowKey::for_world(at, device.kept_home);
    let readable_item = EntityId::now();
    let kept_item = EntityId::now();
    let tombstones = Arc::new(TombstoneHome::default());
    {
        let mut served = tombstones.served.lock().expect("the served tombstones");
        served.insert(
            founder.as_str().to_owned(),
            vec![(readable_item.to_hex(), hard_tombstone(at))],
        );
        served.insert(
            kept.as_str().to_owned(),
            vec![(kept_item.to_hex(), hard_tombstone(at))],
        );
    }
    let (url, home, release_index) = FakeHome::start_tombstones(
        root_listing(&[WindowKey::from_timestamp(at), founder.clone(), kept.clone()]),
        Arc::clone(&tombstones),
    )
    .await;
    release_index.send(()).expect("the index read is not held");
    let connection = opened_connection(&device, url);
    connection
        .set_followed_worlds([device.founder, device.kept_home].into_iter().collect())
        .expect("the owner's pick");
    let _watch = sync_once(&connection, home).await;

    let asks = tombstones.asks.lock().expect("the recorded asks").clone();
    assert!(
        asks.contains(&founder.as_str().to_owned()) && marked(&device, readable_item),
        "precondition: the device asks for its readable followed world's tombstones and marks them ({asks:?})",
    );
    assert!(
        !asks.contains(&kept.as_str().to_owned()),
        "the device never asks for a withheld world's tombstones ({asks:?})",
    );
    assert!(
        !marked(&device, kept_item),
        "the device takes no marker from a withheld world's window",
    );
}
