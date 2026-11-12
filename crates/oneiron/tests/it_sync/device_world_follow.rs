//! A device follows its worlds by itself (census L7-42; ARCH-0023b
//! #partial-sync; Engine ruling WORLDSET-1, Fri 13 Nov 03:02). It follows
//! only the worlds the owner picked for it, and under sync all every world
//! readable on this machine. A world whose read setting turns away from this
//! machine is unfollowed at once, in both residence modes (DEC-0005). The
//! thin index lists every readable world, followed or not.
//!
//! The device vault is never marked "yours" (`MachineRole::Unanswered`), so
//! a world kept on "my machines" is withheld from it and a world readable
//! everywhere is not.

use std::sync::Arc;

use loro::{ExportMode, LoroDoc};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, ReadLocation, WorldPrivacy};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::schema::create_root_doc;
use oneiron::sync::transport::{self, TAG_SYNC_UPDATE, TAG_WINDOW_SYNC, window_sub_tags};
use oneiron::sync::{
    SyncClient, SyncClientConfig, SyncResidenceMode, SyncSelector, SyncSelectorWorld, WindowKey,
    WindowManager,
};
use oneiron::{EntityId, Vault, VaultConfig};

use crate::sync_harness::window_update_frame;

/// The secret of the fixture host's slip issuer.
pub(super) const FIXTURE_HOST_SECRET: &[u8] = b"device-world-follow";

/// A device vault holding three worlds: `founder` and `granted` readable
/// everywhere, and `kept_home` kept on the owner's machines, which this
/// device is not.
pub(super) struct Device {
    _dir: tempfile::TempDir,
    pub(super) vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    pub(super) founder: EntityId,
    pub(super) granted: EntityId,
    kept_home: EntityId,
}

impl Device {
    pub(super) fn open() -> Self {
        let dir = tempfile::tempdir().expect("device vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh device vault");
        let person = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST_SECRET).expect("fixture host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("a live install profile, never marked yours");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("authenticated owner");
        let founder = vault
            .create_world(&owner, "Founder world", vault.now_recorded_at())
            .expect("founder world");
        let granted = vault
            .create_world(&owner, "Granted world", vault.now_recorded_at())
            .expect("granted world");
        let kept_home = vault
            .create_world(&owner, "Kept on my machines", vault.now_recorded_at())
            .expect("kept world");
        let device = Self {
            _dir: dir,
            vault: Arc::new(vault),
            owner,
            founder,
            granted,
            kept_home,
        };
        device.keep_on_my_machines(kept_home);
        device
    }

    /// The owner keeps `world` on the machines marked "yours": this device
    /// may no longer read it.
    fn keep_on_my_machines(&self, world: EntityId) {
        self.vault
            .set_world_privacy_as(
                &self.owner,
                ActSurface::ThisInstall,
                world,
                WorldPrivacy {
                    read: ReadLocation::MyMachines,
                    ..WorldPrivacy::default()
                },
                None,
            )
            .expect("the owner keeps the world on their machines");
    }

    pub(super) fn manager(&self) -> Arc<WindowManager> {
        Arc::new(WindowManager::new(
            Arc::clone(&self.vault),
            Arc::new(Materializer::new()),
            "device-world-follow",
        ))
    }

    fn client(
        &self,
        residence_mode: SyncResidenceMode,
        followed: Option<Vec<EntityId>>,
    ) -> SyncClient {
        let manager = self.manager();
        let mut config = SyncClientConfig {
            residence_mode,
            ..SyncClientConfig::default()
        };
        if let Some(followed) = followed {
            config.followed_worlds = Some(followed);
        }
        SyncClient::new(manager, config)
            .expect("device sync client")
            .0
    }
}

pub(super) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

/// The home's root update listing this month's base window and each world's
/// window of this month.
pub(super) fn root_frame(at: u64, worlds: &[EntityId]) -> Vec<u8> {
    let mut windows = vec![WindowKey::from_timestamp(at)];
    windows.extend(worlds.iter().map(|world| WindowKey::for_world(at, *world)));
    let root = create_root_doc("server", "vault", &windows);
    let mut frame = vec![TAG_SYNC_UPDATE];
    frame.extend_from_slice(&root.export(ExportMode::snapshot()).expect("root snapshot"));
    frame
}

/// The world windows one negotiation asks of the home: the initial frames,
/// then the requests the home's root update brings.
fn negotiated_world_windows(client: &mut SyncClient, root: &[u8]) -> Vec<WindowKey> {
    let mut frames = client.generate_initial_sync();
    frames.extend(client.handle_server_message(root).expect("root update"));
    let mut worlds: Vec<WindowKey> = frames
        .iter()
        .filter(|frame| frame.first() == Some(&TAG_WINDOW_SYNC))
        .map(|frame| {
            WindowKey::new(
                transport::decode_window_sync(&frame[1..])
                    .expect("decode requested window")
                    .0,
            )
        })
        .filter(|key| key.world().is_some())
        .collect();
    worlds.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    worlds.dedup();
    worlds
}

/// The windows `frames` ask the home to promote.
fn promotion_requests(frames: &[Vec<u8>]) -> Vec<WindowKey> {
    let mut keys: Vec<WindowKey> = frames
        .iter()
        .filter(|frame| frame.first() == Some(&TAG_WINDOW_SYNC))
        .filter_map(|frame| {
            let (key, sub_tag, _) =
                transport::decode_window_sync(&frame[1..]).expect("decode window frame");
            (sub_tag == window_sub_tags::PROMOTION_REQUEST).then(|| WindowKey::new(key))
        })
        .collect();
    keys.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    keys.dedup();
    keys
}

/// A window update of `world`'s window this month, as the home relays one.
fn world_update(at: u64, world: EntityId) -> Vec<u8> {
    let doc = LoroDoc::new();
    doc.get_map("probe").insert("k", 1).expect("probe write");
    let update = doc.export(ExportMode::all_updates()).expect("probe update");
    window_update_frame(WindowKey::for_world(at, world).as_str(), &update)
}

fn sorted(mut keys: Vec<WindowKey>) -> Vec<WindowKey> {
    keys.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    keys
}

#[test]
fn a_device_follows_only_its_picked_world() {
    let device = Device::open();
    let at = now_secs();
    // The owner picks the founder world for this machine; its connection
    // records the pick.
    let connection = SyncConnection::new(device.manager(), ConnectionConfig::default())
        .expect("the device's connection");
    connection
        .set_followed_worlds([device.founder].into_iter().collect())
        .expect("the owner's pick");
    let mut client = device.client(SyncResidenceMode::Opened, None);

    let picked = client
        .handle_server_message(&world_update(at, device.founder))
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(
        !picked.contains("unfollowed world window"),
        "the picked world is followed: {picked}",
    );
    let unpicked = client
        .handle_server_message(&world_update(at, device.granted))
        .expect_err("a readable world the owner did not pick is not followed");
    assert!(
        unpicked.to_string().contains("unfollowed world window"),
        "refused as unfollowed: {unpicked}",
    );

    // A pick never reaches past the world's read setting.
    connection
        .set_followed_worlds([device.founder, device.kept_home].into_iter().collect())
        .expect("the owner's wider pick");
    let kept = client
        .handle_server_message(&world_update(at, device.kept_home))
        .expect_err("a picked world this machine may not read is not followed");
    assert!(
        kept.to_string().contains("unfollowed world window"),
        "refused as unfollowed: {kept}",
    );
}

#[test]
fn a_picked_world_syncs_its_full_windows_when_opened() {
    let device = Device::open();
    let at = now_secs();
    let root = root_frame(at, &[device.founder, device.granted, device.kept_home]);
    let connection = SyncConnection::new(device.manager(), ConnectionConfig::default())
        .expect("the device's connection");
    connection
        .set_followed_worlds([device.founder].into_iter().collect())
        .expect("the owner's pick");
    let selected = |device: &Device| {
        let manager = device.manager();
        SyncClient::new(
            manager,
            SyncClientConfig {
                residence_mode: SyncResidenceMode::Opened,
                residence_selector: Some(SyncSelector::new(
                    EntityId::now(),
                    EntityId::now(),
                    SyncSelectorWorld::All,
                    Vec::new(),
                    Vec::new(),
                )),
                ..SyncClientConfig::default()
            },
        )
        .expect("opened device client")
        .0
    };

    // The home's root arrives after the first frames: the picked world's
    // window is asked to be promoted, then for its vector.
    let mut client = selected(&device);
    let mut frames = client.generate_initial_sync();
    frames.extend(client.handle_server_message(&root).expect("root update"));
    let founder = WindowKey::for_world(at, device.founder);
    assert_eq!(
        promotion_requests(&frames),
        vec![founder.clone()],
        "only the picked world's window is asked in full, not the readable \
         world nobody picked nor the world kept on the owner's machines",
    );

    // The home grants it on this socket with no promotion marker here.
    let grant =
        transport::encode_window_sync(founder.as_str(), window_sub_tags::PROMOTION_GRANTED, &[])
            .into_result()
            .expect("grant frame");
    client
        .handle_server_message(&grant)
        .expect("the device takes the home's grant for its followed window");

    // The next connect asks for it in its first frames, the root now held.
    let reconnected = selected(&device);
    assert_eq!(
        promotion_requests(&reconnected.generate_initial_sync()),
        vec![founder],
        "a reconnect asks again for the followed window's promotion",
    );
}

#[test]
fn sync_all_follows_every_world_readable_here() {
    let device = Device::open();
    let at = now_secs();
    let root = root_frame(at, &[device.founder, device.granted, device.kept_home]);
    let mut client = device.client(SyncResidenceMode::All, None);

    assert_eq!(
        negotiated_world_windows(&mut client, &root),
        sorted(vec![
            WindowKey::for_world(at, device.founder),
            WindowKey::for_world(at, device.granted),
        ]),
        "under sync all the device asks for every world readable here and \
         not the world kept on the owner's machines",
    );
}

#[test]
fn a_revoke_drops_a_world_in_both_modes() {
    // Sync all: the next negotiation names only the founder world, and the
    // home's update of the granted world is refused.
    let device = Device::open();
    let at = now_secs();
    let root = root_frame(at, &[device.founder, device.granted, device.kept_home]);
    let mut client = device.client(SyncResidenceMode::All, None);
    assert_eq!(
        negotiated_world_windows(&mut client, &root),
        sorted(vec![
            WindowKey::for_world(at, device.founder),
            WindowKey::for_world(at, device.granted),
        ]),
        "precondition: both readable worlds are followed",
    );
    device.keep_on_my_machines(device.granted);
    let mut renegotiated = device.client(SyncResidenceMode::All, None);
    assert_eq!(
        negotiated_world_windows(&mut renegotiated, &root),
        vec![WindowKey::for_world(at, device.founder)],
        "a world whose read setting turned away from this machine is no longer asked for",
    );
    let refused = client
        .handle_server_message(&world_update(at, device.granted))
        .expect_err("the revoked world's update is refused on the live client");
    assert!(
        refused.to_string().contains("unfollowed world window"),
        "refused as unfollowed: {refused}",
    );

    // Opened: a picked world whose read setting turns away is unfollowed
    // at once; the picked world still readable stays followed.
    let device = Device::open();
    let mut client = device.client(
        SyncResidenceMode::Opened,
        Some(vec![device.founder, device.granted]),
    );
    device.keep_on_my_machines(device.granted);
    let refused = client
        .handle_server_message(&world_update(at, device.granted))
        .expect_err("the revoked picked world's update is refused");
    assert!(
        refused.to_string().contains("unfollowed world window"),
        "refused as unfollowed, not at a later gate: {refused}",
    );
    let founder = client
        .handle_server_message(&world_update(at, device.founder))
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(
        !founder.contains("unfollowed world window"),
        "the picked world still readable stays followed: {founder}",
    );
}

#[cfg(oneiron_test_support)]
#[test]
fn the_thin_index_lists_unpicked_readable_worlds() {
    let device = Device::open();
    let at = now_secs();
    let root = root_frame(at, &[device.founder, device.granted, device.kept_home]);
    // Opened, nothing picked: the device follows no world.
    let mut client = device.client(SyncResidenceMode::Opened, None);
    client.handle_server_message(&root).expect("root update");

    let indexed = oneiron::test_doors::world_follow::thin_index_windows(&client, at, 1)
        .expect("thin index windows");
    assert_eq!(
        sorted(indexed),
        sorted(vec![
            WindowKey::from_timestamp(at),
            WindowKey::for_world(at, device.founder),
            WindowKey::for_world(at, device.granted),
        ]),
        "the thin index lists every world readable here, followed or not, \
         and not the world kept on the owner's machines",
    );
}
