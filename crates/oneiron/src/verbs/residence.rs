//! The owner's residence controls (OF-534, FIX 531): a machine's residence
//! mode, opening one item there, its thin index and pruning its opened-item
//! caches, as owner-vault rows that name the machine they act on. The named
//! machine's own `SyncConnection` applies each one; a host reaches it
//! through the connection it registered for that machine id, and an
//! embedded handle reaches none. A machine the host reaches no connection
//! for gets the row as the owner's residence directive, and each answer
//! then says so (`state: "queued"`, FIX 3570) instead of what the machine
//! did. The owner reads those directives back, with each machine's result as
//! this replica received it (`vault.residence.directives`, FIX 4346). The
//! engine types have no wire form, so the inputs and answers are spelled
//! here.

use serde::{Deserialize, Serialize};

use crate::EntityId;
#[cfg(feature = "sync")]
use crate::Vault;
#[cfg(feature = "sync")]
use crate::consent::AuthenticatedOwner;
#[cfg(feature = "sync")]
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};
#[cfg(feature = "sync")]
use crate::sync::residence::ResidenceDirectiveState;
#[cfg(feature = "sync")]
use crate::sync::{OpenedItem, ResidenceIndexWindow, ResidenceModeChange, SyncResidenceMode};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::residence::{
    ResidenceActView, ResidenceDirectiveView, ResidenceDirectivesRequest, ResidenceMachineRequest,
    ResidenceModeName, ResidenceModeRequest, ResidenceOpenRequest, ResidencePruneRequest,
    ResidenceResultStatusName, ResidenceResultView,
};

#[cfg(feature = "sync")]
impl From<ResidenceModeName> for SyncResidenceMode {
    fn from(mode: ResidenceModeName) -> Self {
        match mode {
            ResidenceModeName::Opened => Self::Opened,
            ResidenceModeName::All => Self::All,
        }
    }
}

#[cfg(feature = "sync")]
impl From<SyncResidenceMode> for ResidenceModeName {
    fn from(mode: SyncResidenceMode) -> Self {
        match mode {
            SyncResidenceMode::Opened => Self::Opened,
            SyncResidenceMode::All => Self::All,
        }
    }
}

/// `vault.residence.worlds`'s input: the worlds the named machine follows,
/// the owner's pick of its projects (ARCH-0023b #partial-sync). It replaces
/// the machine's earlier pick; an empty list follows none. A world the
/// machine may not read is never followed, and under sync all the machine
/// follows every world it may read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidenceWorldsRequest {
    /// The owner's machine, by its machine id (32 hex).
    pub machine: EntityId,
    /// The worlds it follows, 32 hex each.
    pub worlds: Vec<EntityId>,
}

/// A residence row the host relayed as the owner's residence directive,
/// because the named machine runs no sync connection it reaches (FIX 3570):
/// accepted, not executed. The machine applies it once when it next syncs
/// and records the directive's result; the same row again, while this one
/// is pending, answers this same directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceQueued {
    /// The queued residence directive, 32 hex.
    pub directive: EntityId,
    /// The machine it waits for, 32 hex.
    pub machine: EntityId,
}

/// `vault.residence.mode`'s answer: what the switch did on the machine, or
/// the directive queued for it. `state` says which; an applied answer
/// carries [`ResidenceModeChanged`]'s fields beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResidenceModeAnswer {
    Applied(ResidenceModeChanged),
    Queued(ResidenceQueued),
}

/// `vault.residence.worlds`'s answer: the pick the machine follows now, or
/// the directive queued for it. `state` says which; an applied answer
/// carries [`ResidenceWorldsPicked`]'s fields beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResidenceWorldsAnswer {
    Applied(ResidenceWorldsPicked),
    Queued(ResidenceQueued),
}

/// The pick a machine follows now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceWorldsPicked {
    /// The picked worlds, ascending, 32 hex each.
    pub worlds: Vec<EntityId>,
}

/// `vault.residence.open`'s answer: the item the machine opened, or the
/// directive queued for it. `state` says which; an applied answer carries
/// [`ResidenceOpened`]'s fields beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResidenceOpenAnswer {
    Applied(Box<ResidenceOpened>),
    Queued(ResidenceQueued),
}

/// `vault.residence.index`'s answer: the machine's thin index, or the
/// directive queued for it. `state` says which; an applied answer carries
/// [`ResidenceIndex`]'s fields beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResidenceIndexAnswer {
    Applied(ResidenceIndex),
    Queued(ResidenceQueued),
}

/// `vault.residence.prune`'s answer: what the prune dropped on the
/// machine, or the directive queued for it. `state` says which; an applied
/// answer carries [`ResidencePruned`]'s fields beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResidencePruneAnswer {
    Applied(ResidencePruned),
    Queued(ResidenceQueued),
}

/// What switching the machine's residence mode did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceModeChanged {
    /// The mode the machine runs now; the elected home always runs `all`.
    pub mode: ResidenceModeName,
    /// Held windows the home granted again, kept as promoted windows.
    pub retained: Vec<String>,
    /// Held windows the home did not grant again: still on disk, unsynced.
    pub unsynced: Vec<String>,
    /// Opened-item caches dropped on the way to `all`.
    pub pruned_items: usize,
}

#[cfg(feature = "sync")]
impl From<ResidenceModeChange> for ResidenceModeChanged {
    fn from(change: ResidenceModeChange) -> Self {
        let keys = |keys: Vec<crate::sync::WindowKey>| {
            keys.iter().map(|key| key.as_str().to_owned()).collect()
        };
        Self {
            mode: change.mode.into(),
            retained: keys(change.retained),
            unsynced: keys(change.unsynced),
            pruned_items: change.pruned_items,
        }
    }
}

/// Where the opened item came from on the machine: its canonical row, or a
/// grant-checked read cache. NOTE bodies use the same typed editor view as
/// `vault.notes.read`; no raw document bytes are exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceOpened {
    pub item: EntityId,
    pub window: String,
    /// `resident` (a canonical local row) or `thin` (a read cache).
    pub residence: String,
    /// The bytes the machine holds for it.
    pub bytes: usize,
    pub source: crate::note::NoteReadSource,
    pub note: Option<crate::note::NoteReadView>,
}

impl ResidenceOpened {
    #[cfg(feature = "sync")]
    pub fn from_opened(
        opened: OpenedItem,
        source: crate::note::NoteReadSource,
        note: Option<crate::note::NoteReadView>,
    ) -> Self {
        match opened {
            OpenedItem::Resident {
                entity_id,
                window,
                raw,
            } => Self {
                item: entity_id,
                window: window.as_str().to_owned(),
                residence: "resident".to_owned(),
                bytes: raw.len(),
                source,
                note,
            },
            OpenedItem::Thin(thin) => Self {
                item: thin.entity_id,
                window: thin.window.as_str().to_owned(),
                residence: "thin".to_owned(),
                bytes: thin.raw.len() + thin.document.len(),
                source,
                note,
            },
        }
    }
}

/// One entry of a window's thin index: what exists, never a body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceIndexEntry {
    pub entity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub learned_at: u64,
}

/// One current window's thin index on the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceIndexWindowView {
    pub window: String,
    pub items: Vec<ResidenceIndexEntry>,
}

/// The machine's thin index, window by window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceIndex {
    pub windows: Vec<ResidenceIndexWindowView>,
}

#[cfg(feature = "sync")]
impl From<Vec<ResidenceIndexWindow>> for ResidenceIndex {
    fn from(windows: Vec<ResidenceIndexWindow>) -> Self {
        Self {
            windows: windows
                .into_iter()
                .map(|window| ResidenceIndexWindowView {
                    window: window.window.as_str().to_owned(),
                    items: window
                        .items
                        .into_iter()
                        .map(|entry| ResidenceIndexEntry {
                            entity_id: entry.entity_id,
                            title: entry.title,
                            learned_at: entry.learned_at,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

/// What a prune dropped on the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidencePruned {
    /// Opened-item caches dropped.
    pub dropped: usize,
}

#[cfg(feature = "sync")]
impl From<&ResidenceDirectiveState> for ResidenceDirectiveView {
    fn from(state: &ResidenceDirectiveState) -> Self {
        Self {
            directive: state.directive.id,
            machine: state.directive.machine,
            issued_at: state.directive.issued_at,
            act: (&state.directive.act).into(),
            entry: bytes_to_hex_lower(&state.entry),
            result: state.result.as_ref().map(ResidenceResultView::from),
        }
    }
}

/// `vault.residence.directives` as the vault owner: the residence directives
/// this replica holds and each machine's result as received here. The read
/// revalidates the owner in its own read transaction; it reaches no machine
/// and queues nothing. A directive id this replica does not hold answers an
/// empty list. A `null` result means not received here, never that the
/// machine is idle.
///
/// # Errors
///
/// Neither or both of `machine` and `directive`; an owner who no longer
/// stands; storage errors.
#[cfg(feature = "sync")]
pub fn residence_directives_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ResidenceDirectivesRequest,
) -> MemoryResult<Vec<ResidenceDirectiveView>> {
    input.validate()?;
    let states = match input.directive {
        Some(directive) => vault
            .residence_directive_as(owner, directive)?
            .into_iter()
            .collect(),
        None => vault.residence_directives_as(owner, input.machine)?,
    };
    Ok(states.iter().map(ResidenceDirectiveView::from).collect())
}

/// `vault.residence.directives` on an embedded handle, as the vault's own
/// owner ([`Memory::embedded_owner`]): the same read as
/// [`residence_directives_as_owner`], which needs no machine's connection.
///
/// # Errors
///
/// A caller who is not the vault's owner; as [`residence_directives_as_owner`].
#[cfg(feature = "sync")]
pub fn residence_directives(
    memory: &Memory<'_>,
    input: &ResidenceDirectivesRequest,
) -> MemoryResult<Vec<ResidenceDirectiveView>> {
    let owner = memory.embedded_owner("vault.residence.directives")?;
    residence_directives_as_owner(memory.vault(), &owner, input)
}

/// A residence row on an embedded handle: refused, as no machine's sync
/// connection is reachable beneath an embedded vault. A server's host door
/// applies it through the named machine's connection.
///
/// # Errors
///
/// Always.
pub fn residence_host_only<I, T>(_memory: &Memory<'_>, verb: &str, _input: &I) -> MemoryResult<T> {
    Err(MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        format!("{verb} acts on a machine's own sync connection; an embedded vault reaches none"),
        &[super::host::SERVED_CLIENT_HINT],
    ))
}
