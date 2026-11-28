//! The by-item twin of the thin residence index: one `ri:i:{item}:{window}` row per
//! `ri:w:` listing, device-local and never synced.
//!
//! `cargo test --locked -p oneiron --all-features --test it_sync -- device_index_by_item`.

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::ExportMode;
use oneiron::EntityId;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::schema::create_root_doc;
use oneiron::sync::transport::TAG_SYNC_UPDATE;
use oneiron::sync::{
    SyncClientConfig, SyncResidenceMode, SyncSelector, SyncSelectorWorld, WindowKey,
};
use tokio::sync::{mpsc, oneshot};

use super::device_world_follow::{Device, now_secs};
use super::device_world_follow_live::{
    FakeHome, HomeEvent, IndexHome, TombstoneHome, Watch, note_session, synced,
};

/// A soft delete's tombstone value as the home's window holds it: reason
/// byte 1 (`user_delete`), the delete time as a little-endian u64, and
/// the request id.
fn soft_tombstone(deleted_at: u64) -> Vec<u8> {
    let mut value = vec![1_u8];
    value.extend_from_slice(&deleted_at.to_le_bytes());
    value.extend_from_slice(EntityId::now().as_bytes());
    value
}

/// The (window, item) pairs of every thin index listing (`ri:w:`) and of
/// every by-item twin row (`ri:i:`) the device holds: the two sets match
/// while each listing keeps its twin.
fn listings_and_twins(device: &Device) -> (BTreeSet<(String, String)>, BTreeSet<(String, String)>) {
    let listings: BTreeSet<(String, String)> = device
        .vault
        .sync_state_keys_with_prefix("ri:w:")
        .expect("read the thin index rows")
        .into_iter()
        .filter_map(|key| {
            key.strip_prefix("ri:w:")
                .and_then(|rest| rest.rsplit_once(':'))
                .map(|(window, item)| (window.to_owned(), item.to_owned()))
        })
        .collect();
    let twins: BTreeSet<(String, String)> = device
        .vault
        .sync_state_keys_with_prefix("ri:i:")
        .expect("read the by-item rows")
        .into_iter()
        .filter_map(|key| {
            key.strip_prefix("ri:i:")
                .and_then(|rest| rest.split_once(':'))
                .map(|(item, window)| (window.to_owned(), item.to_owned()))
        })
        .collect();
    (listings, twins)
}

/// The home's root update listing `windows`.
fn root_listing(windows: &[WindowKey]) -> Vec<u8> {
    let root = create_root_doc("server", "vault", windows);
    let mut frame = vec![TAG_SYNC_UPDATE];
    frame.extend_from_slice(&root.export(ExportMode::snapshot()).expect("root snapshot"));
    frame
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

/// The home's index lists two items in one window and one in another: after
/// one sync the device holds a by-item twin row for each listing, and the
/// (window, item) pair sets of the listings and the twins match.
#[test]
fn an_index_fetch_writes_a_by_item_row_for_each_listing() {
    on_engine_stack(
        "an_index_fetch_writes_a_by_item_row_for_each_listing",
        index_fetch_writes_a_by_item_row_for_each_listing,
    );
}

async fn index_fetch_writes_a_by_item_row_for_each_listing() {
    let device = Device::open();
    let at = now_secs();
    let base = WindowKey::from_timestamp(at);
    let founder = WindowKey::for_world(at, device.founder);
    let mut ids = [EntityId::now(), EntityId::now(), EntityId::now()];
    ids.sort_unstable_by_key(EntityId::to_hex);
    let [first, second, third] = ids;
    let index = Arc::new(IndexHome::default());
    index.served.lock().expect("the served index rows").insert(
        base.as_str().to_owned(),
        vec![
            (first.to_hex(), Some("First".to_owned()), at),
            (second.to_hex(), Some("Second".to_owned()), at),
        ],
    );
    index.served.lock().expect("the served index rows").insert(
        founder.as_str().to_owned(),
        vec![(third.to_hex(), Some("Third".to_owned()), at)],
    );
    let (url, home, release_index) = FakeHome::start_index(
        root_listing(&[base.clone(), founder.clone()]),
        Arc::clone(&index),
    )
    .await;
    release_index.send(()).expect("the index read is not held");
    let connection = opened_connection(&device, url);
    let _watch = sync_once(&connection, home).await;

    let (listings, twins) = listings_and_twins(&device);
    let expected = BTreeSet::from([
        (base.as_str().to_owned(), first.to_hex()),
        (base.as_str().to_owned(), second.to_hex()),
        (founder.as_str().to_owned(), third.to_hex()),
    ]);
    assert_eq!(listings, expected, "the fetch wrote all three listings");
    assert_eq!(twins, expected, "each listing got its by-item twin");
}

/// A window that leaves the home's root takes its listings with it on the
/// next sync: its by-item rows go too, the staying window's stay, and the
/// pair sets still match.
#[test]
fn a_window_that_leaves_the_index_takes_its_by_item_rows() {
    on_engine_stack(
        "a_window_that_leaves_the_index_takes_its_by_item_rows",
        window_that_leaves_the_index_takes_its_by_item_rows,
    );
}

async fn window_that_leaves_the_index_takes_its_by_item_rows() {
    let device = Device::open();
    let at = now_secs();
    let base = WindowKey::from_timestamp(at);
    let founder = WindowKey::for_world(at, device.founder);
    let mut ids = [EntityId::now(), EntityId::now(), EntityId::now()];
    ids.sort_unstable_by_key(EntityId::to_hex);
    let [first, second, third] = ids;
    let index = Arc::new(IndexHome::default());
    index.served.lock().expect("the served index rows").insert(
        base.as_str().to_owned(),
        vec![
            (first.to_hex(), Some("First".to_owned()), at),
            (second.to_hex(), Some("Second".to_owned()), at),
        ],
    );
    index.served.lock().expect("the served index rows").insert(
        founder.as_str().to_owned(),
        vec![(third.to_hex(), Some("Third".to_owned()), at)],
    );
    // First sync: the root lists both windows.
    let (url, home, release_index) = FakeHome::start_index(
        root_listing(&[base.clone(), founder.clone()]),
        Arc::clone(&index),
    )
    .await;
    release_index.send(()).expect("the index read is not held");
    let connection = opened_connection(&device, url);
    let _watch = sync_once(&connection, home).await;
    let (listings, twins) = listings_and_twins(&device);
    assert_eq!(listings.len(), 3, "FIXTURE: the first sync lists three");
    assert_eq!(
        listings, twins,
        "FIXTURE: the first sync twins every listing"
    );

    // Second sync: the home's root no longer lists the founder window.
    let (url, home, release_index) =
        FakeHome::start_index(root_listing(&[base.clone()]), Arc::clone(&index)).await;
    release_index.send(()).expect("the index read is not held");
    let connection = opened_connection(&device, url);
    let _watch = sync_once(&connection, home).await;

    let (listings, twins) = listings_and_twins(&device);
    let expected = BTreeSet::from([
        (base.as_str().to_owned(), first.to_hex()),
        (base.as_str().to_owned(), second.to_hex()),
    ]);
    assert_eq!(
        listings, expected,
        "the leaving window's listings are gone, the staying window's stay"
    );
    assert_eq!(
        twins, expected,
        "the leaving window's by-item rows went with its listings"
    );
}

/// An index-listed item the device never opened gets a soft tombstone from
/// the home: after the sync its listing and its by-item row are gone, the
/// other listing's pair stays, the pair sets match, and no delete marker
/// was written.
#[test]
fn a_soft_tombstone_drops_the_listing_and_its_by_item_row() {
    on_engine_stack(
        "a_soft_tombstone_drops_the_listing_and_its_by_item_row",
        soft_tombstone_drops_the_listing_and_its_by_item_row,
    );
}

async fn soft_tombstone_drops_the_listing_and_its_by_item_row() {
    let device = Device::open();
    let at = now_secs();
    let base = WindowKey::from_timestamp(at);
    let founder = WindowKey::for_world(at, device.founder);
    let mut ids = [EntityId::now(), EntityId::now()];
    ids.sort_unstable_by_key(EntityId::to_hex);
    let [victim, survivor] = ids;
    let index = Arc::new(IndexHome::default());
    index.served.lock().expect("the served index rows").insert(
        founder.as_str().to_owned(),
        vec![
            (victim.to_hex(), Some("Victim".to_owned()), at),
            (survivor.to_hex(), Some("Survivor".to_owned()), at),
        ],
    );
    let tombstones = Arc::new(TombstoneHome::default());
    tombstones
        .served
        .lock()
        .expect("the served tombstones")
        .insert(
            founder.as_str().to_owned(),
            vec![(victim.to_hex(), soft_tombstone(at))],
        );
    let (url, home, release_index) = FakeHome::start_index_tombstones(
        root_listing(&[base, founder.clone()]),
        Arc::clone(&index),
        Arc::clone(&tombstones),
    )
    .await;
    release_index.send(()).expect("the index read is not held");
    let connection = opened_connection(&device, url);
    connection
        .set_followed_worlds([device.founder].into_iter().collect())
        .expect("the owner's pick");
    let _watch = sync_once(&connection, home).await;

    let (listings, twins) = listings_and_twins(&device);
    let expected = BTreeSet::from([(founder.as_str().to_owned(), survivor.to_hex())]);
    assert_eq!(
        listings, expected,
        "the soft-deleted listing is gone, the other stays"
    );
    assert_eq!(
        twins, expected,
        "the soft-deleted twin went with its listing"
    );
    assert!(
        device
            .vault
            .sync_state_get(&format!("dt:{}", victim.to_hex()))
            .expect("read the delete marker")
            .is_none(),
        "a soft tombstone writes no delete marker",
    );
}
