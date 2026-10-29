//! FIX 8875 stage 2: the erasable keys a handoff's actor content is sealed
//! under (`super::actor_content`), in transit to its target and retired at
//! every holder.
//!
//! Before it stages its parts, the source asks its target for a key session
//! for the handoff: the target draws a fresh hybrid key pair and nonce, keeps
//! the secret in this process's memory only, and offers the public half
//! ([`open_key_session`]). The source exports each key of the handoff to that
//! session (`home_handoff_custody::export`, which records the target as a
//! holder before it seals) and sends the seals; the target installs each one
//! in a writer of its own and forgets the secret ([`receive_keys`]). Keys go
//! before parts, so a target holding every part holds the keys too, and its
//! own arrival can adopt without a session. A key whose actor is erased there
//! is refused there; a key that does not travel leaves its content unreadable
//! there, and the facts land alone. Seals are never stored.
//!
//! An actor's erase retires its keys on each node (the custody's catalog
//! scrub) and owes every other holder's copy. Each delivery round a node asks
//! every holder it owes to retire its copies ([`retire_held`] at the holder),
//! then reads which of them the holder keeps no live copy of
//! ([`retired_here`]) and clears those debts ([`note_retired`]). A holder out
//! of reach keeps its debt; the erase never waits on it.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use getrandom::SysRng;
use oneiron_crypto::{HybridPublicKey, HybridSecretKey};
use rand_core::{OsRng, RngCore};

use super::delivery::FrozenHandoff;
use super::store::{self, HandoffHead, HandoffRole, HandoffTransfer};
use super::{HandoffId, refused, routes};
use crate::Vault;
use crate::authority::AuthorityFold;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::home_handoff_custody::{
    Content, Installed, KeyRef, LiveTarget, ReceiveWriter, SessionBinding, TransitSeal,
    VerifiedHolder, export, holder_retired, holder_retirements, install_received, open_content,
    retire,
};

/// The context a key session's binding derives under.
const SESSION_CONTEXT: &str = "oneiron/home-handoff/key-session/v1";

/// What a target offers for one handoff's keys: its session-ephemeral
/// public key and the nonce it drew for the session.
pub(crate) struct KeySessionOffer {
    pub(crate) ephemeral: Vec<u8>,
    pub(crate) nonce: [u8; 32],
}

/// One key on its way to a target: its ref and its seal to the target's
/// session. Transit only: never stored.
pub(crate) struct SentKey {
    pub(crate) key: String,
    pub(crate) sealed: TransitSeal,
}

/// The retired keys whose copies one holder still keeps, as far as this
/// node knows, and the endpoint it answers at, when one is known.
pub(crate) struct OwedRetirement {
    pub(crate) holder: EntityId,
    pub(crate) endpoint: Option<String>,
    pub(crate) keys: Vec<String>,
}

/// A key session this node offered as a target, until its keys arrive.
struct HeldSession {
    id: HandoffId,
    digest: [u8; 32],
    source: EntityId,
    session: SessionBinding,
    secret: HybridSecretKey,
}

/// The key sessions this process offered: at most one per source machine,
/// in memory only.
static SESSIONS: Mutex<Vec<HeldSession>> = Mutex::new(Vec::new());

fn sessions() -> MutexGuard<'static, Vec<HeldSession>> {
    SESSIONS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The binding both ends derive for the key session of handoff `id`, sealed
/// to the bytes `digest` names, from `source` to `target` in vault
/// `vault_id`.
fn session_binding(
    vault_id: &[u8; 32],
    id: &HandoffId,
    digest: &[u8; 32],
    source: &EntityId,
    target: &EntityId,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SESSION_CONTEXT);
    hasher.update(vault_id);
    hasher.update(id);
    hasher.update(digest);
    hasher.update(source.as_bytes());
    hasher.update(target.as_bytes());
    *hasher.finalize().as_bytes()
}

/// This vault's id and this install's machine.
fn here(vault: &Vault) -> Result<([u8; 32], EntityId)> {
    let txn = vault.store.env.read_txn()?;
    let vault_id = vault
        .authority_view_readonly_in_txn(&txn)?
        .vault_id
        .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
    let machine = crate::identity::read_machine_id_in_txn(vault, &txn)?
        .ok_or_else(|| refused("this install has no machine yet"))?;
    Ok((vault_id, machine))
}

/// The target's half: a fresh key session for handoff `id`, sealed to the
/// bytes `digest` names, from `source`, the machine its socket proved. The
/// session's secret stays in this process's memory until the keys arrive; a
/// later session from the same source replaces it.
///
/// # Errors
///
/// A vault with no genesis or an install with no machine yet; the random
/// source failed; storage errors.
pub(crate) fn open_key_session(
    vault: &Vault,
    id: HandoffId,
    digest: [u8; 32],
    source: EntityId,
) -> Result<KeySessionOffer> {
    let (vault_id, machine) = here(vault)?;
    let secret =
        HybridSecretKey::generate(&mut SysRng).map_err(|_| refused("os randomness unavailable"))?;
    let mut nonce = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| refused("os randomness unavailable"))?;
    let session = SessionBinding {
        binding: session_binding(&vault_id, &id, &digest, &source, &machine),
        nonce,
    };
    let offer = KeySessionOffer {
        ephemeral: secret.public_key().to_bytes(),
        nonce,
    };
    let mut held = sessions();
    held.retain(|entry| entry.source != source);
    held.push(HeldSession {
        id,
        digest,
        source,
        session,
        secret,
    });
    Ok(offer)
}

/// The target's half: installs `keys`, each a key ref and its seal to the
/// session this node offered `source` for handoff `id`, each in a writer of
/// its own, and forgets the session. Returns how many this node holds now.
/// A key whose actor is erased here, or that this custody retired, is
/// refused and not counted; one that does not open or install is logged and
/// not counted.
///
/// # Errors
///
/// No session open here for this handoff from `source`; storage errors.
pub(crate) fn receive_keys(
    vault: &Vault,
    id: HandoffId,
    digest: [u8; 32],
    source: EntityId,
    keys: Vec<(String, Vec<u8>)>,
) -> Result<u32> {
    let held = {
        let mut sessions = sessions();
        let at = sessions
            .iter()
            .position(|entry| entry.id == id && entry.digest == digest && entry.source == source)
            .ok_or_else(|| refused("no key session is open here for this handoff"))?;
        sessions.swap_remove(at)
    };
    let (_, machine) = here(vault)?;
    let holder = VerifiedHolder {
        source,
        target: machine,
        lineage: id,
        session: held.session,
    };
    let mut installed = 0u32;
    for (key, sealed) in keys {
        let Ok(key_ref) = KeyRef::from_hex(&key) else {
            continue;
        };
        let sealed = TransitSeal::from_bytes(sealed);
        let outcome = vault.with_write_txn(|txn| {
            let mut writer = ReceiveWriter {
                store: &vault.store,
                wtxn: txn,
                session: &held.secret,
            };
            install_received(&mut writer, key_ref, &sealed, &holder)
        });
        match outcome {
            Ok(Installed::Installed | Installed::AlreadyInstalled) => {
                installed = installed.saturating_add(1);
            }
            Ok(Installed::Refused { .. }) => {}
            Err(error) => {
                tracing::debug!(kind = ?error.kind(), "a home handoff key was not installed");
            }
        }
    }
    Ok(installed)
}

/// The source's half: each key of `frozen`, sealed to the session its
/// target offered, `offer`. The target is recorded as a holder of each key
/// before it is sealed. A key this node no longer holds live (its actor
/// erased since the freeze) does not travel.
///
/// # Errors
///
/// A session key that does not import; a malformed key ref.
pub(crate) fn transit_keys(
    vault: &Vault,
    frozen: &FrozenHandoff,
    offer: &KeySessionOffer,
) -> Result<Vec<SentKey>> {
    let movement = &frozen.movement;
    let target = LiveTarget {
        machine: movement.target.machine,
        session: SessionBinding {
            binding: session_binding(
                &movement.vault_id,
                &frozen.id,
                &frozen.digest,
                &movement.source.machine,
                &movement.target.machine,
            ),
            nonce: offer.nonce,
        },
        ephemeral: HybridPublicKey::from_bytes(&offer.ephemeral)
            .map_err(|_| refused("the target's session key does not import"))?,
    };
    let mut sent = Vec::with_capacity(frozen.keys.len());
    for key in &frozen.keys {
        match export(&vault.store, KeyRef::from_hex(key)?, &target) {
            Ok(sealed) => sent.push(SentKey {
                key: key.clone(),
                sealed,
            }),
            Err(error) => {
                tracing::debug!(kind = ?error.kind(), "a home handoff key was not sent");
            }
        }
    }
    Ok(sent)
}

/// The holder's half: stages the retirement of each of `keys` this custody
/// holds, at `requester`'s word, carries it out at once, and clears this
/// node's debt for `requester`'s own copy of each: it asks only for keys it
/// retired itself. Returns how many keys it named.
///
/// # Errors
///
/// Storage and custody faults.
pub(crate) fn retire_held(vault: &Vault, requester: EntityId, keys: &[String]) -> Result<u32> {
    let refs: Vec<KeyRef> = keys
        .iter()
        .filter_map(|key| KeyRef::from_hex(key).ok())
        .collect();
    vault.with_write_txn(|txn| {
        for key in &refs {
            retire(&vault.store, txn, *key)?;
        }
        Ok(())
    })?;
    // A finisher that fails here runs again on the next housekeeping pass.
    vault.finish_erasable_retirements_after_commit();
    for key in &refs {
        holder_retired(&vault.store, *key, requester)?;
    }
    Ok(u32::try_from(refs.len()).unwrap_or(u32::MAX))
}

/// Whether this node keeps no live copy of key `key`: retired here, or
/// never held. Probed by opening nothing under it: a retired key reads as
/// erased and a missing one as unavailable, while a live one refuses the
/// empty bytes.
fn no_live_copy(vault: &Vault, key: KeyRef) -> bool {
    matches!(
        open_content(&vault.store, key, &[], &[]),
        Ok(Content::Erased | Content::Unavailable(_))
    )
}

/// The holder's half: those of `keys` this node keeps no live copy of.
pub(crate) fn retired_here(vault: &Vault, keys: &[String]) -> Vec<String> {
    keys.iter()
        .filter(|key| KeyRef::from_hex(key).is_ok_and(|key| no_live_copy(vault, key)))
        .cloned()
        .collect()
}

/// The endpoint `holder` answers at: its home candidacy's node in the routes
/// the host fed, else the route a handoff this node froze for it captured.
fn holder_endpoint(
    fold: &AuthorityFold,
    head: &HandoffHead,
    transfers: &[(HandoffId, HandoffTransfer)],
    holder: EntityId,
) -> Option<String> {
    fold.home_candidacy
        .get(&holder)
        .and_then(|declared| routes::route_for(head, declared.node_id))
        .and_then(|route| route.endpoint)
        .or_else(|| {
            transfers
                .iter()
                .filter(|(_, transfer)| {
                    transfer.role == HandoffRole::Source
                        && transfer.movement.target.machine == holder
                })
                .find_map(|(_, transfer)| transfer.route.as_ref()?.endpoint.clone())
        })
}

/// Every holder this node owes a retired key's copy to, with the keys and
/// the endpoint it answers at.
///
/// # Errors
///
/// Storage and custody faults.
pub(crate) fn owed_retirements(vault: &Vault) -> Result<Vec<OwedRetirement>> {
    let owed = holder_retirements(&vault.store)?;
    if owed.is_empty() {
        return Ok(Vec::new());
    }
    let txn = vault.store.env.read_txn()?;
    let machine = crate::identity::read_machine_id_in_txn(vault, &txn)?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    let head = store::head_in_txn(vault, &txn)?;
    let transfers = store::transfers_in_txn(vault, &txn)?;
    let mut by_holder: BTreeMap<EntityId, Vec<String>> = BTreeMap::new();
    for debt in owed {
        if Some(debt.holder) != machine {
            by_holder
                .entry(debt.holder)
                .or_default()
                .push(debt.key_ref.to_hex());
        }
    }
    Ok(by_holder
        .into_iter()
        .map(|(holder, keys)| OwedRetirement {
            holder,
            endpoint: holder_endpoint(&fold, &head, &transfers, holder),
            keys,
        })
        .collect())
}

/// Clears `holder`'s debt for each of `keys`: its answer on a socket that
/// proved it said it keeps no live copy.
///
/// # Errors
///
/// A malformed key ref; custody faults.
pub(crate) fn note_retired(vault: &Vault, holder: EntityId, keys: &[String]) -> Result<()> {
    for key in keys {
        holder_retired(&vault.store, KeyRef::from_hex(key)?, holder)?;
    }
    Ok(())
}
