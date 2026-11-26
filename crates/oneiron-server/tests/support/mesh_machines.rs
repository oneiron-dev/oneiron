//! The owner's machines, each serving over the real mesh, for tests of the
//! protocols between two (or more) of his servers (pass 33 row R0; the form
//! of `organ_mesh_two_server_e2e.rs` and `mesh_two_machine_peer_e2e.rs`).
//!
//! The fixture is the owner's home H and N devices of H. Each device is a
//! replica of H's vault in its own directory with its own install identity,
//! enrolled as `oneiron device enrol` enrols a device. Each device's server
//! runs with its real mesh listener (`handler::mesh::start`, serve's full
//! route set: iroh on a loopback port the system assigns, no relay), so a
//! call between two of them crosses the real handshake and the listener's
//! admission (the MACHINE row and its grant for the protocol, read live).
//! Every replica binds every other device's endpoint at the address its
//! listener took. Enrolment grants sync alone: a test grants each other
//! protocol per holder and peer ([`Machines::grant`]).
//!
//! Test-only: shared by the crate's integration tests through
//! `#[path = "support/mesh_machines.rs"]`, with `support/engine_stack.rs`.
// Each including test binary uses part of it.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, MachineOwnership, MachineRole, MeshBindingIdentity, MeshEnrolment,
    MeshEnrolmentAsk, MeshMachineAddress, PairingPrincipal, pairing_binding_transcript_pinned,
};
use oneiron::federation::Scope;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::sync::mesh_path::{
    MESH_PATH_RECEIPTS_READ_MAX, MeshPathDirection, MeshPathReceipt, SYNC_ALPN,
};
use oneiron::test_doors::steward;
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_mesh_transport::MeshTransport;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::embedded_peer_path::{MeshListener, start_mesh_listener};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
pub(crate) fn at<E: std::fmt::Debug>(
    step: &'static str,
) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// The owner's home H: a rooted carrier install the owner answered as his
/// own machine, as `oneiron serve` leaves a self-hosted home. It never runs.
pub(crate) struct Home {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: oneiron::consent::AuthenticatedOwner,
}

pub(crate) fn home() -> TestResult<Home> {
    let dir = tempfile::tempdir()?;
    let vault =
        steward::open_owner_carrier_vault(dir.path()).map_err(at("open the home's vault"))?;
    let owner = steward::owner(&vault).map_err(at("the home's owner proof"))?;
    let machine = vault
        .local_machine()
        .map_err(at("read the home's install"))?
        .ok_or("FIXTURE: the home's install has no machine")?
        .id;
    vault
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .map_err(at("the owner answers the home is his"))?;
    Ok(Home {
        _dir: dir,
        vault,
        owner,
    })
}

/// One device of H: a replica of H's vault with its own install identity,
/// enrolled on H.
pub(crate) struct Device {
    _dir: tempfile::TempDir,
    pub(crate) vault: Arc<Vault>,
    pub(crate) machine: EntityId,
    identity: MeshBindingIdentity,
    /// The pairing slip H minted for the device's mesh binding.
    mesh_pairing: [u8; 32],
    /// The device's keystore, installed again when its vault opens again.
    keystore: Arc<oneiron_keystore::MemoryKeystore>,
}

impl Home {
    /// H's vault: the owner's home, where his changes are his signed acts.
    pub(crate) fn vault(&self) -> &Vault {
        &self.vault
    }

    /// The owner's proof on H.
    pub(crate) fn owner(&self) -> &oneiron::consent::AuthenticatedOwner {
        &self.owner
    }

    /// A device that copies H's vault and enrols on H as the owner's own
    /// machine, as `oneiron device enrol` does: H's owner makes the machine
    /// pairing link; the device redeems it with a holder key of its own
    /// (seeded by `holder_seed`), its enrolment request, its machine key's
    /// possession proof and its mesh identity; H enrols it, and binds and
    /// grants its endpoint on sync in the same redemption.
    pub(crate) fn enrol(&self, holder_seed: u8) -> TestResult<Device> {
        self.enrol_with(holder_seed, &oneiron_server::SERVED_MESH_ALPNS)
    }

    /// As [`Self::enrol`], the binding's pairing covering the protocols of
    /// `ceiling` alone.
    pub(crate) fn enrol_with(&self, holder_seed: u8, ceiling: &[&[u8]]) -> TestResult<Device> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::device())
            .map_err(at("open the device's vault"))?;
        vault
            .import_signed_authority_history(
                &self
                    .vault
                    .export_signed_authority_history()
                    .map_err(at("the home's authority history"))?,
            )
            .map_err(at("the device takes the home's authority history"))?;
        let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
        vault.install_device_keystore(keystore.clone());
        // The install's identity is minted with its machine encryption key,
        // as its enrolment request mints it; its mesh identity is read from
        // that identity.
        let vault_id = vault
            .authority_vault_id()
            .map_err(at("the device's vault id"))?
            .ok_or("FIXTURE: the device's copy has no vault id")?;
        vault
            .machine_encryption_key(vault_id)
            .map_err(at("the device's encryption key"))?;
        let device_owner = steward::owner(&vault).map_err(at("the device's owner proof"))?;
        let identity = vault
            .mesh_binding_identity_as_owner(&device_owner)
            .map_err(at("the device's mesh identity"))?;
        let (machine, mesh) = self.redeem_enrolment(&vault, &identity, holder_seed, ceiling)?;
        let pairing_slip_id = match mesh {
            Some(MeshEnrolment::Bound {
                pairing_slip_id, ..
            }) => pairing_slip_id,
            other => {
                return Err(format!("FIXTURE: the home did not bind the device: {other:?}").into());
            }
        };
        Ok(Device {
            _dir: dir,
            vault: Arc::new(vault),
            machine,
            identity,
            mesh_pairing: pairing_slip_id,
            keystore,
        })
    }

    /// `device` enrols on H again with a new machine link, its binding's
    /// pairing covering `ceiling`: what H's redemption made of its mesh
    /// binding.
    pub(crate) fn re_enrol(
        &self,
        device: &Device,
        holder_seed: u8,
        ceiling: &[&[u8]],
    ) -> TestResult<Option<MeshEnrolment>> {
        let (_, mesh) =
            self.redeem_enrolment(&device.vault, &device.identity, holder_seed, ceiling)?;
        Ok(mesh)
    }

    /// H grants `device` the protocol `alpn`, as the owner does with
    /// `vault.mesh.set_alpn_grant` on the home.
    pub(crate) fn grant(&self, device: &Device, alpn: &[u8]) -> TestResult {
        self.vault
            .set_mesh_alpn_grant(
                &test_host_issuer(),
                device.machine,
                device.identity.endpoint_key,
                alpn,
                true,
            )
            .map_err(at("the home grants the device a protocol"))?;
        Ok(())
    }

    /// H's owner lowers the mesh pairing lifetime (`mesh.grant.max_ttl_secs`)
    /// to `secs`: each later enrolment pairs its machine for that long.
    pub(crate) fn limit_pairings(&self, secs: u64) -> TestResult {
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&self.owner),
                SetSetting::vault_value("mesh.grant.max_ttl_secs", serde_json::json!(secs)),
            )
            .map_err(at("the owner lowers the mesh pairing lifetime"))?;
        if !matches!(outcome, SetSettingOutcome::Applied { .. }) {
            return Err(
                format!("FIXTURE: the pairing lifetime did not change: {outcome:?}").into(),
            );
        }
        Ok(())
    }

    /// When the pairing H minted for `device`'s binding expires, in H's fold.
    pub(crate) fn pairing_expiry(&self, device: &Device) -> TestResult<u64> {
        let fold = self
            .vault
            .authority_fold()
            .map_err(at("the home's authority fold"))?;
        let pairing = fold
            .slips
            .mints
            .get(&device.mesh_pairing)
            .ok_or("FIXTURE: the home's fold holds the device's pairing")?;
        Ok(pairing.action.claims.expires_at)
    }

    /// H signs one more act into its authority log once its own clock reads
    /// `not_before` or later: it revokes a slip it never minted, which
    /// touches no machine of the test.
    pub(crate) fn sign_act_from(&self, not_before: u64) -> TestResult {
        while self
            .vault
            .capability_slip_now()
            .map_err(at("read the home's clock"))?
            < not_before
        {
            // testkit-lint: allow(sleep) H's clock must reach `not_before`: the condition the caller's test sets up
            std::thread::sleep(Duration::from_millis(200));
        }
        let appended = self
            .vault
            .revoke_capability_slip_once(&test_host_issuer(), [0x5a; 32])
            .map_err(at("the home signs a later act"))?;
        if !appended {
            return Err("FIXTURE: the home's later act appended no row".into());
        }
        Ok(())
    }

    /// The device of `vault` redeems a new machine pairing link of H's with a
    /// holder key of its own (seeded by `holder_seed`), its enrolment
    /// request, its machine key's possession proof and its mesh `identity`;
    /// H enrols it, and binds and grants its endpoint on sync in the same
    /// redemption under `ceiling`. The enrolled MACHINE and the mesh
    /// binding's outcome.
    fn redeem_enrolment(
        &self,
        vault: &Vault,
        identity: &MeshBindingIdentity,
        holder_seed: u8,
        ceiling: &[&[u8]],
    ) -> TestResult<(EntityId, Option<MeshEnrolment>)> {
        let vault_id = vault
            .authority_vault_id()
            .map_err(at("the device's vault id"))?
            .ok_or("FIXTURE: the device's copy has no vault id")?;
        let request = vault
            .machine_enrolment_request(
                vault_id,
                vault
                    .machine_encryption_key(vault_id)
                    .map_err(at("the device's encryption key"))?,
            )
            .map_err(at("the device's enrolment request"))?;
        let issuer = test_host_issuer();
        let link = self
            .vault
            .issue_machine_pairing_link(
                &issuer,
                &self.owner,
                ActSurface::ThisInstall,
                Scope::top(),
                3600,
                PairingPrincipal::default(),
                MachineOwnership::Yours,
            )
            .map_err(at("the owner's machine pairing link"))?;
        let holder = SigningKey::from_bytes(&[holder_seed; 32]);
        let binding_key = holder.verifying_key().to_bytes();
        let holder_ref = request.machine.to_hex();
        let transcript = pairing_binding_transcript_pinned(
            &link.code,
            &binding_key,
            &holder_ref,
            link.pin.as_ref(),
        )
        .map_err(at("the pairing transcript"))?;
        let possession = vault
            .machine_possession_proof(&request, &transcript)
            .map_err(at("the machine key's possession proof"))?;
        let redeemed = self
            .vault
            .redeem_pairing_link_with_mesh(
                &issuer,
                &link.code,
                &holder_ref,
                binding_key,
                &holder.sign(&transcript).to_bytes(),
                &request,
                Some(&possession),
                // The binding's pairing covers `ceiling`
                // (MESH-PAIRING-CEILING = A); each grant stays the owner's.
                MeshEnrolmentAsk {
                    identity,
                    granted: SYNC_ALPN,
                    ceiling,
                },
            )
            .map_err(at("the home redeems the device's enrolment"))?;
        Ok((request.machine, redeemed.mesh))
    }

    /// Every device takes H's authority history once all have enrolled, so
    /// each replica folds every machine and every slip H minted.
    pub(crate) fn share_history(&self, devices: &[&Device]) -> TestResult {
        let history = self
            .vault
            .export_signed_authority_history()
            .map_err(at("the home's authority history"))?;
        for device in devices {
            device
                .vault
                .import_signed_authority_history(&history)
                .map_err(at("a device takes the home's authority history"))?;
        }
        Ok(())
    }
}

impl Device {
    /// This device after its vault was closed for `closed` and opened again
    /// on the same directory with the same keystore, as a device that was
    /// shut down. Its authority clock stops while the vault is closed and
    /// resumes from its floor, so it reads about `closed` behind H's
    /// afterwards.
    pub(crate) fn reopened_after(self, closed: Duration) -> TestResult<Device> {
        let Device {
            _dir: dir,
            vault,
            machine,
            identity,
            mesh_pairing,
            keystore,
        } = self;
        let open = Arc::try_unwrap(vault)
            .map_err(|_| "FIXTURE: another handle holds the device's vault open")?;
        drop(open);
        // The vault stays closed for `closed` of real time: its authority clock stops meanwhile.
        // testkit-lint: allow(sleep) the closed time is the condition the caller's test sets up
        std::thread::sleep(closed);
        let vault = Vault::open(dir.path(), VaultConfig::device())
            .map_err(at("open the device's vault again"))?;
        vault.install_device_keystore(keystore.clone());
        Ok(Device {
            _dir: dir,
            vault: Arc::new(vault),
            machine,
            identity,
            mesh_pairing,
            keystore,
        })
    }

    /// This vault binds `peer`'s endpoint at the loopback addresses its
    /// running listener bound (`listening`), on the pairing H minted for it.
    /// The listeners and dialers read the roster and the grants live, so a
    /// bind after the listener started counts.
    pub(crate) fn bind(&self, peer: &Device, listening: &Served) -> TestResult {
        self.bind_at(peer, listening.addresses.clone())
    }

    /// This vault binds `peer`'s endpoint at `direct_addrs` (none for a peer
    /// no test dials), on the pairing H minted for it.
    pub(crate) fn bind_at(&self, peer: &Device, direct_addrs: Vec<SocketAddr>) -> TestResult {
        self.bind_on(peer, direct_addrs, peer.mesh_pairing)
    }

    /// This vault binds `peer`'s endpoint at `direct_addrs` on the pairing
    /// slip `pairing` (one a re-enrolment of `peer` named), as the owner
    /// does with `vault.mesh.bind_machine`.
    pub(crate) fn bind_on(
        &self,
        peer: &Device,
        direct_addrs: Vec<SocketAddr>,
        pairing: [u8; 32],
    ) -> TestResult {
        self.vault
            .bind_mesh_machine(
                &test_host_issuer(),
                peer.machine,
                MeshMachineAddress {
                    endpoint_key: peer.identity.endpoint_key,
                    direct_addrs,
                    relay_url: None,
                },
                peer.identity.device_key,
                pairing,
                [
                    peer.identity.device_proof.as_slice(),
                    peer.identity.transport_proof.as_slice(),
                ],
            )
            .map_err(at("bind the peer's endpoint"))?;
        Ok(())
    }

    /// This vault grants `peer` the protocol `alpn`, as the owner does with
    /// `vault.mesh.set_alpn_grant`: this machine then admits `peer` on it,
    /// and dials `peer` on it.
    pub(crate) fn grant(&self, peer: &Device, alpn: &[u8]) -> TestResult {
        self.vault
            .set_mesh_alpn_grant(
                &test_host_issuer(),
                peer.machine,
                peer.identity.endpoint_key,
                alpn,
                true,
            )
            .map_err(at("grant the peer a protocol"))?;
        Ok(())
    }

    /// This vault withdraws `peer`'s grant of `alpn`, as the owner does with
    /// `vault.mesh.set_alpn_grant` and `allow = false`.
    pub(crate) fn revoke(&self, peer: &Device, alpn: &[u8]) -> TestResult {
        self.vault
            .set_mesh_alpn_grant(
                &test_host_issuer(),
                peer.machine,
                peer.identity.endpoint_key,
                alpn,
                false,
            )
            .map_err(at("withdraw the peer's grant of a protocol"))?;
        Ok(())
    }

    /// Whether this vault's grants admit `peer` on `alpn` now, as its mesh
    /// listener's admission reads them.
    pub(crate) fn admits(&self, peer: &Device, alpn: &[u8]) -> TestResult<bool> {
        self.vault
            .mesh_grant_permits(peer.machine, peer.identity.endpoint_key, alpn)
            .map_err(at("read the peer's grant"))
    }

    /// Starts this device's server as a device of H, with no models, and its
    /// mesh listener on a loopback port the system assigns as it binds: no
    /// other test of the binary (they run in parallel) can take that port
    /// between the choice and the bind.
    pub(crate) async fn serve(&self) -> TestResult<Served> {
        self.serve_with(SyncServerConfig::default()).await
    }

    /// As [`Self::serve`], with the server's configuration `config` (e.g.
    /// an `[execution_node]` file).
    pub(crate) async fn serve_with(&self, config: SyncServerConfig) -> TestResult<Served> {
        let server =
            SyncServer::new(Arc::clone(&self.vault), config).map_err(at("the device's server"))?;
        let (server, host) = AiHost::attach_device(server, None, true).await;
        let server = Arc::new(server);
        let app = oneiron_server::build_app(Arc::clone(&server));
        let listener = start_mesh_listener(
            Arc::clone(&server),
            SocketAddr::from(([127, 0, 0, 1], 0)),
            &app,
        )
        .await
        .map_err(at("the device's mesh listener"))?;
        let addresses = listener.direct_addrs();
        if addresses.is_empty() {
            return Err("FIXTURE: the device's mesh listener bound no direct address".into());
        }
        Ok(Served {
            server,
            _host: host,
            listener: Some(listener),
            addresses,
        })
    }
}

/// A device's running server and mesh listener.
pub(crate) struct Served {
    pub(crate) server: Arc<SyncServer>,
    _host: AiHost,
    /// `None` once a test stopped it.
    listener: Option<MeshListener>,
    /// The loopback addresses the listener bound.
    pub(crate) addresses: Vec<SocketAddr>,
}

impl Served {
    /// The listener's endpoint, which this machine's own dials ride.
    pub(crate) fn transport(&self) -> TestResult<Arc<dyn MeshTransport>> {
        self.listener
            .as_ref()
            .map(MeshListener::transport)
            .ok_or_else(|| "the machine's mesh listener is stopped".into())
    }

    /// Stops the listener, if it still runs: its stop's drain and cancel.
    pub(crate) async fn stop(&mut self) {
        if let Some(listener) = self.listener.take() {
            listener.stop().await;
        }
    }
}

/// One machine of the owner's: its replica and its running server.
pub(crate) struct Machine {
    pub(crate) device: Device,
    pub(crate) served: Served,
}

/// H and its running devices.
pub(crate) struct Machines {
    _home: Home,
    machines: Vec<Machine>,
}

impl Machines {
    /// Enrols `count` devices of one home (holder seeds 0x0a, 0x0b, ...),
    /// starts each one's server and listener, and binds each device's
    /// endpoint, at the address its listener took, in every other replica.
    /// It grants nothing past enrolment's sync.
    pub(crate) async fn start(count: u8) -> TestResult<Self> {
        Self::start_with(count, |_, _| SyncServerConfig::default()).await
    }

    /// As [`Self::start`], each device's server configured by
    /// `configure(index, machines)`, where `machines` are every device's
    /// MACHINE ids in enrolment order (e.g. a node's file naming its
    /// issuer).
    pub(crate) async fn start_with(
        count: u8,
        configure: impl Fn(usize, &[EntityId]) -> SyncServerConfig,
    ) -> TestResult<Self> {
        let home = home()?;
        let devices = (0..count)
            .map(|index| home.enrol(0x0a + index))
            .collect::<TestResult<Vec<_>>>()?;
        home.share_history(&devices.iter().collect::<Vec<_>>())?;
        let ids: Vec<EntityId> = devices.iter().map(|device| device.machine).collect();
        let mut machines = Vec::with_capacity(devices.len());
        for (index, device) in devices.into_iter().enumerate() {
            machines.push(Machine {
                served: device.serve_with(configure(index, &ids)).await?,
                device,
            });
        }
        for holder in &machines {
            for peer in &machines {
                if peer.device.machine != holder.device.machine {
                    holder.device.bind(&peer.device, &peer.served)?;
                }
            }
        }
        Ok(Self {
            _home: home,
            machines,
        })
    }

    /// As [`Self::start`], then every replica grants every other machine
    /// each of `alpns`: for a test that needs machines already holding a
    /// protocol's grant (e.g. the job grant before an approval).
    pub(crate) async fn start_granted(count: u8, alpns: &[&[u8]]) -> TestResult<Self> {
        let machines = Self::start(count).await?;
        let indices = 0..machines.machines.len();
        for holder in indices.clone() {
            for peer in indices.clone().filter(|peer| *peer != holder) {
                machines.grant(holder, peer, alpns)?;
            }
        }
        Ok(machines)
    }

    /// The machine at `index`, in enrolment order.
    pub(crate) fn machine(&self, index: usize) -> &Machine {
        &self.machines[index]
    }

    /// `holder`'s vault grants `peer` each of `alpns`.
    pub(crate) fn grant(&self, holder: usize, peer: usize, alpns: &[&[u8]]) -> TestResult {
        for alpn in alpns {
            self.machines[holder]
                .device
                .grant(&self.machines[peer].device, alpn)?;
        }
        Ok(())
    }

    /// `holder`'s vault withdraws `peer`'s grant of each of `alpns`.
    pub(crate) fn revoke(&self, holder: usize, peer: usize, alpns: &[&[u8]]) -> TestResult {
        for alpn in alpns {
            self.machines[holder]
                .device
                .revoke(&self.machines[peer].device, alpn)?;
        }
        Ok(())
    }

    /// The machine at `index` binds its own endpoint in its own vault and
    /// grants itself each of `alpns`, as a replica holds its own grant once
    /// the owner's grant of it syncs there (e.g. a node's own job grant).
    pub(crate) fn grant_own(&self, index: usize, alpns: &[&[u8]]) -> TestResult {
        let machine = &self.machines[index];
        // A vault binds each machine's endpoint once.
        let bound = machine
            .device
            .vault
            .mesh_machine(machine.device.machine)
            .map_err(at("read the machine's own endpoint"))?
            .is_some();
        if !bound {
            machine.device.bind(&machine.device, &machine.served)?;
        }
        for alpn in alpns {
            machine.device.grant(&machine.device, alpn)?;
        }
        Ok(())
    }

    pub(crate) async fn stop(mut self) {
        for machine in &mut self.machines {
            machine.served.stop().await;
        }
    }
}

/// The inbound path receipts `vault` holds for `machine` on `alpn`.
pub(crate) fn inbound_path_receipts(
    vault: &Vault,
    machine: EntityId,
    alpn: &[u8],
) -> Vec<MeshPathReceipt> {
    let alpn = String::from_utf8_lossy(alpn);
    let machine = machine.to_hex();
    vault
        .mesh_path_receipts(MESH_PATH_RECEIPTS_READ_MAX)
        .unwrap_or_default()
        .into_iter()
        .filter(|receipt| {
            receipt.direction == MeshPathDirection::Inbound
                && receipt.alpn == alpn
                && receipt.machine.as_deref() == Some(machine.as_str())
        })
        .collect()
}

/// Polls `probe` every 250 ms until it holds or `within` passes. A probe
/// reads what another serving process wrote after a call over a real
/// transport: that process signals nothing to await, and it does not run on
/// a fake clock.
pub(crate) async fn eventually(within: Duration, mut probe: impl FnMut() -> bool) -> bool {
    // testkit-lint: allow(wall-clock) bounds a wait on another serving process
    let deadline = Instant::now() + within;
    loop {
        if probe() {
            return true;
        }
        // testkit-lint: allow(wall-clock) the same bound
        if Instant::now() >= deadline {
            return false;
        }
        // testkit-lint: allow(sleep) the poll interval; the other process signals nothing
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
