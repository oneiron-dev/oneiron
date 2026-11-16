//! Where each world's text vectors are made, as this install makes them (DEC-0005
//! #private-world-vectors; FIX [WORLD-VECTORS-FACT]): the read behind `vault.worlds.vectors`.
//!
//! The verdict is this install's own, from the predicate its pending-text lease loop embeds by
//! (Engine RULING WORLD-VECTORS-MECHANISM = B, 16 Nov 11:03). `world_space`: the world's order
//! names its own text space ([`WorldTextSpaces`]), which takes every row the world carries.
//! `vault_space`: the text embedder this install's host runs is the vault's pinned model, and a
//! row of the world may go to it, on this device or toward an endpoint the world is not withheld
//! from ([`super::PendingEmbeddingReconciler`]'s lease loop). `none`: neither, so no vector of
//! the world's text is made here. No stored row says which machines run the vault's model, so
//! the verdict is never one for another machine, and the answer names the install that gave it.
//!
//! Who reads it (lead RULING WORLD-VECTORS-INTENT = B, 16 Nov 11:04): the owner under its proof,
//! or a holder of a Steward grant naming `read` that reaches the whole vault, checked at each
//! read. The answer names no content: world ids, the verdict, a space id and the install.

use std::collections::BTreeSet;
use std::sync::Mutex;
#[cfg(feature = "sync")]
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::world_space::WorldTextSpaces;
use crate::authority::WorldPrivacyView;
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_WORLD;
use crate::settings::ReadDestination;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Result, Vault, WriteActor};

const VERB: &str = "vault.worlds.vectors";

/// Which worlds to answer for.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorldVectorsRequest {
    /// World ids (hex). Empty: every world of the vault, base reality first.
    #[serde(default)]
    pub worlds: Vec<String>,
}

/// Where a world's text vectors are made on the install that answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorldVectorsVerdict {
    /// Into the vault's own text index, by the vault's pinned model.
    VaultSpace,
    /// Into the world's own text space, which its model order names.
    WorldSpace,
    /// Nowhere on this install: its text model does not run here for the world.
    None,
}

/// One world's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorldVectorsEntry {
    /// The world id (hex).
    pub world: String,
    pub vectors: WorldVectorsVerdict,
    /// The world's text space (`model@revision@device`), for `world_space` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space: Option<String>,
}

/// The verdicts of the install that answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorldVectorsAnswer {
    /// This install's machine id (hex), or none before it joined a vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// One entry per world asked for that is a live world of the vault, in
    /// id order with base reality first. A world that is unknown, not live,
    /// or not an id is left out, and nothing says which. A vault root in
    /// conflict answers none.
    pub worlds: Vec<WorldVectorsEntry>,
}

/// The host text embedder a live reconciler runs: what its lease loop judges a world's rows by.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(crate) struct HostTextEmbedder {
    model_id: String,
    dimensions: usize,
    on_device: bool,
    endpoint: ReadDestination,
}

impl HostTextEmbedder {
    /// Whether the lease loop embeds `world`'s rows into the vault's text index with this
    /// embedder: the vault's pinned model at the vault's dimensions, and a world whose rows
    /// may go to it (`withheld` = the worlds kept from its endpoint).
    fn embeds_world(&self, vault: &Vault, withheld: &BTreeSet<EntityId>, world: EntityId) -> bool {
        self.dimensions == vault.config.dimensions
            && vault.config.embedding_model.as_deref() == Some(self.model_id.as_str())
            && (self.on_device || !withheld.contains(&world))
    }
}

/// The host text embedder registered on a vault: the one its newest live reconciler runs. In
/// memory only; a reopened vault has none until its host builds a reconciler again.
#[derive(Debug, Default)]
pub(crate) struct HostTextEmbedderSlot {
    current: Mutex<Option<(u64, HostTextEmbedder)>>,
    #[cfg(feature = "sync")]
    next_token: AtomicU64,
}

impl HostTextEmbedderSlot {
    fn current(&self) -> Option<HostTextEmbedder> {
        self.current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|(_, embedder)| embedder.clone())
    }
}

/// Holds a reconciler's embedder on its vault while the reconciler lives; dropping it withdraws
/// the embedder unless a newer reconciler registered its own.
#[cfg(feature = "sync")]
pub(crate) struct HostTextEmbedderRegistration {
    vault: std::sync::Weak<Vault>,
    token: u64,
}

#[cfg(feature = "sync")]
impl HostTextEmbedderRegistration {
    pub(crate) fn register(vault: &std::sync::Arc<Vault>, embedder: &dyn super::Embedder) -> Self {
        let slot = &vault.host_text_embedder;
        let token = slot.next_token.fetch_add(1, Ordering::Relaxed);
        *slot
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((
            token,
            HostTextEmbedder {
                model_id: embedder.model_id().to_owned(),
                dimensions: embedder.dimensions(),
                on_device: embedder.locality() == super::EmbedderLocality::OnDevice,
                endpoint: embedder.endpoint(),
            },
        ));
        Self {
            vault: std::sync::Arc::downgrade(vault),
            token,
        }
    }
}

#[cfg(feature = "sync")]
impl Drop for HostTextEmbedderRegistration {
    fn drop(&mut self) {
        let Some(vault) = self.vault.upgrade() else {
            return;
        };
        let mut current = vault
            .host_text_embedder
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current
            .as_ref()
            .is_some_and(|(token, _)| *token == self.token)
        {
            *current = None;
        }
    }
}

/// `vault.worlds.vectors` for the vault's owner under its proof.
///
/// # Errors
///
/// An owner proof that no longer stands; storage errors.
pub fn read_world_vectors_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &WorldVectorsRequest,
) -> Result<WorldVectorsAnswer> {
    owner.revalidate(vault)?;
    read_world_vectors(vault, input)
}

/// [`read_world_vectors_as_owner`] for an agent or person holding a live Steward grant that
/// names `read` and reaches the whole vault, checked at this read.
///
/// # Errors
///
/// A caller who holds no such grant; storage errors.
pub fn read_world_vectors_as_reader(
    vault: &Vault,
    reader: WriteActor,
    input: &WorldVectorsRequest,
) -> MemoryResult<WorldVectorsAnswer> {
    crate::federation::admit_substrate_read_by(
        vault,
        reader,
        VERB,
        crate::federation::SubstrateRead::Evidence,
    )?;
    Ok(read_world_vectors(vault, input)?)
}

/// `vault.worlds.vectors` on a bound handle: the embedded owner reads under its own proof, any
/// other caller as a reader.
///
/// # Errors
///
/// As [`read_world_vectors_as_owner`] and [`read_world_vectors_as_reader`].
pub fn read_world_vectors_embedded(
    memory: &Memory<'_>,
    input: &WorldVectorsRequest,
) -> MemoryResult<WorldVectorsAnswer> {
    match memory.embedded_owner(VERB) {
        Ok(owner) => Ok(read_world_vectors_as_owner(memory.vault(), &owner, input)?),
        Err(_) => read_world_vectors_as_reader(
            memory.vault(),
            WriteActor::new(memory.actor(), memory.actor_class()),
            input,
        ),
    }
}

fn read_world_vectors(vault: &Vault, input: &WorldVectorsRequest) -> Result<WorldVectorsAnswer> {
    let host = vault.host_text_embedder.current();
    let txn = vault.store.env.read_txn()?;
    let machine =
        crate::store::install_identity::read_machine_id_in_txn(vault, &txn)?.map(|id| id.to_hex());
    if WorldPrivacyView::load_unless_conflicted_in(vault, &txn)?.is_none() {
        return Ok(WorldVectorsAnswer {
            machine,
            worlds: Vec::new(),
        });
    }
    let worlds = asked_worlds_in(vault, &txn, input)?;
    let spaces = WorldTextSpaces::read_in(vault, &txn)?;
    let withheld = match &host {
        Some(host) if !host.on_device => {
            crate::settings::device_local_worlds_for(vault, &txn, &host.endpoint)?
        }
        _ => BTreeSet::new(),
    };
    let worlds = worlds
        .into_iter()
        .map(|world| {
            let (vectors, space) = match spaces.of_world(&world) {
                Some(space) => (WorldVectorsVerdict::WorldSpace, Some(space.id.clone())),
                None if host
                    .as_ref()
                    .is_some_and(|host| host.embeds_world(vault, &withheld, world)) =>
                {
                    (WorldVectorsVerdict::VaultSpace, None)
                }
                None => (WorldVectorsVerdict::None, None),
            };
            WorldVectorsEntry {
                world: world.to_hex(),
                vectors,
                space,
            }
        })
        .collect();
    Ok(WorldVectorsAnswer { machine, worlds })
}

/// The worlds `input` asks for that are worlds of the vault, base reality first, then the live
/// WORLD rows in id order; none an off-record session holds.
fn asked_worlds_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &WorldVectorsRequest,
) -> Result<Vec<EntityId>> {
    let base = crate::claim::base_world_id();
    let is_world = |id: &EntityId| -> Result<bool> {
        if vault.store.off_record_sessions.contains_entity(id)? {
            return Ok(false);
        }
        Ok(matches!(
            live_entity_row_in_txn(&vault.store, txn, id)?,
            LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_WORLD
        ))
    };
    let mut rows = BTreeSet::new();
    if input.worlds.is_empty() {
        for id in vault
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_WORLD, None)?
        {
            let id = id?;
            if id != base && is_world(&id)? {
                rows.insert(id);
            }
        }
        return Ok(std::iter::once(base).chain(rows).collect());
    }
    let mut with_base = false;
    for id in input
        .worlds
        .iter()
        .filter_map(|hex| EntityId::from_hex(hex).ok())
    {
        if id == base {
            with_base = true;
        } else if is_world(&id)? {
            rows.insert(id);
        }
    }
    Ok(with_base.then_some(base).into_iter().chain(rows).collect())
}
