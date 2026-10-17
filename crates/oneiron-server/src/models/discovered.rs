//! The models the owner's other nodes offer (OF-575, FIX 3229). Each
//! own-server row a mesh catalog refresh wrote becomes a route of its own on
//! the host's router: one rung, sent once to the node that offered it. A raw
//! call or a manifest's role route that names the model reaches it through
//! that ladder and a run, like a configured model; its own-server row, not
//! the host, vouches for where it runs. Nothing re-advertises it: the chat
//! catalog, the aliases, the quota fallbacks and what this node serves the
//! owner's other nodes stay the configured ones.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::SingleRouteBackend;
use oneiron::llm::registry::{ModelRegistryRow, ModelWireFormat};
use oneiron::llm::run_admission::{KeyCustody, OfferBinding, OfferRoute, Payer};
use oneiron::{LlmCatalogEntry, ModelLocality, Vault};
use oneiron_llm_own_server::{MESH_PEER, MeshLlmTransport, OwnServerBackend, VaultLlmNodes};
use oneiron_mesh_transport::{MachineId, MeshTransport};

use super::ladder::{LadderRung, SeatScope, Wire};
use super::router::Routes;
use super::{ModelRouter, OfferCooldowns, OfferLadder, ServedOffer};

/// The adapter a discovered model's offer names: the own-server wire, over
/// the owner's mesh.
const MESH_ADAPTER: &str = "own-server-mesh";

/// Who pays for a call to a model on another of the owner's nodes: nobody
/// per call, as for the vault's own node. The node that runs it meters it
/// under its own admission.
const MESH_PAYER: Payer = Payer::Local;

/// Serves the models the owner's other nodes offer on the host's router,
/// as each mesh catalog refresh leaves the vault's rows.
pub(crate) struct MeshRoutes {
    /// `None` on a host with no configured model: it has no raw route to
    /// serve them on.
    router: Option<Arc<ModelRouter>>,
    /// Shared with every configured ladder, so an offer's rest outlives the
    /// refresh that rebuilt its route.
    rests: Arc<OfferCooldowns>,
    transport: MeshLlmTransport,
}

impl MeshRoutes {
    /// Serves the rows earlier refreshes wrote at once, before this run's
    /// first refresh. Calls go out on the current runtime.
    pub(super) fn new(
        router: Option<Arc<ModelRouter>>,
        rests: Arc<OfferCooldowns>,
        vault: &Arc<Vault>,
        mesh: Arc<dyn MeshTransport>,
    ) -> Self {
        let routes = Self {
            router,
            rests,
            transport: MeshLlmTransport::new(
                mesh,
                Arc::new(VaultLlmNodes(Arc::clone(vault))),
                tokio::runtime::Handle::current(),
            ),
        };
        routes.publish(vault);
        routes
    }

    /// Serves each model the vault's discovery rows hold now, in place of
    /// the last set. When the rows cannot be read, the last set stays.
    pub(crate) fn publish(&self, vault: &Vault) {
        let Some(router) = &self.router else {
            return;
        };
        let rows = match vault.model_registry_rows() {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "mesh model routes kept as they were");
                return;
            }
        };
        let mut peers: BTreeMap<MachineId, Vec<LlmCatalogEntry>> = BTreeMap::new();
        for row in rows {
            if let Some(peer) = mesh_peer(&row) {
                peers.entry(peer).or_default().push(row.catalog);
            }
        }
        let mut routes = Routes::new();
        for (peer, entries) in peers {
            let backend: Arc<dyn SingleRouteBackend> = Arc::new(OwnServerBackend::serving(
                self.transport.peer(peer),
                entries.iter().cloned(),
            ));
            for entry in entries {
                let Some(binding) = mesh_offer(peer, &entry) else {
                    continue;
                };
                let rung = LadderRung {
                    provider: binding.route.origin().to_owned(),
                    position: 0,
                    model: entry.model.clone(),
                    // The full engine id crosses the own-server wire; the
                    // node that runs it names it to its provider.
                    wire_model: entry.model.as_str().to_owned(),
                    prompt: None,
                    offer: ServedOffer {
                        binding,
                        backend: Arc::clone(&backend),
                    },
                    media: None,
                };
                let ladder = OfferLadder::bare(rung, Arc::clone(&self.rests)).scoped(SeatScope {
                    wire: Wire::Chat,
                    ..SeatScope::default()
                });
                routes.insert(entry.model, (ModelLocality::OwnServer, Arc::new(ladder)));
            }
        }
        router.discover(routes);
    }
}

/// The node a row names, when the row is discovery's own: an own-server
/// route a mesh catalog refresh wrote for a model that node offers.
fn mesh_peer(row: &ModelRegistryRow) -> Option<MachineId> {
    if row.wire != ModelWireFormat::OwnServer || row.catalog.locality != ModelLocality::OwnServer {
        return None;
    }
    let peer = row.catalog.metadata.get(MESH_PEER)?.as_str()?;
    MachineId::from_hex(peer).ok()
}

/// The offer a call to `entry`'s model on `peer` is admitted under: the
/// own-server wire at that node, keyless and paid by nobody per call.
fn mesh_offer(peer: MachineId, entry: &LlmCatalogEntry) -> Option<OfferBinding> {
    let route = OfferRoute::new(MESH_ADAPTER, format!("mesh:{}", peer.to_hex())).ok()?;
    Some(OfferBinding {
        offer: entry.model.as_str().to_owned(),
        model: entry.model.clone(),
        route,
        locality: ModelLocality::OwnServer,
        payer: MESH_PAYER,
        credential_binding: None,
        catalog_revision: Some(entry.model.revision().to_owned()),
        custody: KeyCustody::Keyless,
        rates: Vec::new(),
        payer_person: None,
    })
}
