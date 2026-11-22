//! The authority overlay's erasable keys, carried live between the vault's
//! own machines (census L5-22 1a-iii commit 7).
//!
//! A sealed AUTHORITY_LOG row opens only where its subject's overlay key is
//! held and ready (`store::authority_overlay_custody`). Each machine runs one
//! round per upkeep pass with its residence home
//! (`crate::sync::client::residence::authority_overlay_custody`), page by
//! page:
//!
//! - the machine offers its page of [`OverlayInventory`] and a fresh
//!   session-ephemeral key whose secret stays in its memory for the page
//!   ([`offer_overlay_page`]);
//! - the home ([`answer_offer`]) first retires each subject the machine
//!   erased, then answers its own erased subjects, the keys it holds that
//!   the machine lacks (each sealed to the machine's session, the machine
//!   recorded as a holder first), the keys it wants, and a session of its
//!   own for them;
//! - the machine ([`apply_overlay_answer`]) retires the home's erased subjects,
//!   installs the home's keys and seals each wanted key to the home's
//!   session, which the home installs ([`receive_keys`]).
//!
//! Keys move through the home: a key minted on one machine reaches another
//! on that one's first round after the home has it. Every install and
//! retirement is the authority's key event
//! (`crate::authority::install_authority_overlay_key_in_txn`,
//! `crate::authority::retire_authority_overlay_subject_in_txn`), so a row
//! opens or closes from that writer's commit on. Retirements go before keys,
//! and an erased subject refuses a key on every install. A page's inputs
//! (its peer's session key and erased subjects) are checked before its first
//! write, and a machine's new offer closes the session its home held for the
//! machine's last page. Seals are never stored. A holder's debt clears only
//! when its inventory names the key destroyed there.
//!
//! Nothing here does network I/O or judges who the peer is: the residence
//! doors admit only a machine of the owner's that its socket proved
//! (`sync::residence::authority_overlay_custody`), and a machine judges its
//! home the same way before it offers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use getrandom::SysRng;
use oneiron_crypto::{HybridPublicKey, HybridSecretKey};
use rand_core::{OsRng, RngCore};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
pub use crate::store::authority_overlay_custody::ErasedSubject;
use crate::store::authority_overlay_custody::{
    OverlayInventory, awaits_retirement_by, clear_destroyed_holder_debts, export_key,
    open_received_key, overlay_inventory, record_sender,
};
use crate::store::home_handoff_custody::{LiveTarget, SessionBinding, TransitSeal};

/// The context a key session's binding derives under.
const SESSION_CONTEXT: &str = "oneiron/authority-overlay/key-session/v1";

/// The context an inventory's digest derives under.
const INVENTORY_CONTEXT: &str = "oneiron/authority-overlay/inventory/v1";

/// The most subjects one page of a round compares (CALLS:
/// OVERLAY_PAGE_SUBJECTS): a larger inventory goes on from the last subject
/// a page covered. A subject's row is about 50 bytes a key.
pub const OVERLAY_PAGE_SUBJECTS: usize = 1024;

/// One key session's public half: the receiver's ephemeral hybrid public
/// key and the nonce it drew. Its secret never leaves the receiver's
/// memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayKeySession {
    pub ephemeral: Vec<u8>,
    pub nonce: [u8; 32],
}

/// One key on its way: its subject, its ref and its seal to the receiver's
/// session. Transit only: never stored.
pub struct OverlaySentKey {
    pub subject: EntityId,
    pub key_ref: [u8; 32],
    pub sealed: Vec<u8>,
}

/// One page of what a machine offers its home.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayOffer {
    /// The digest of the machine's whole inventory.
    pub digest: [u8; 32],
    /// Whether the machine waits on the home's proof that it destroyed a
    /// key of a subject erased on the machine.
    pub owed: bool,
    /// The page covers subjects after this one; none on the first page.
    pub after: Option<EntityId>,
    /// The last subject the machine's side of the page holds, when more of
    /// its inventory follows.
    pub through: Option<EntityId>,
    /// The machine's keys held ready in the page, by subject and ref.
    pub ready: BTreeSet<(EntityId, [u8; 32])>,
    /// The machine's erased subjects in the page.
    pub erased: BTreeMap<EntityId, ErasedSubject>,
    /// The machine's session for the keys the home sends it.
    pub session: OverlayKeySession,
}

/// The home's answer to one page.
pub struct OverlayAnswer {
    /// The two inventories agree and neither side waits on the other's
    /// proof: the round ends with nothing to carry.
    pub same: bool,
    /// The last subject this page covered, when the round goes on.
    pub through: Option<EntityId>,
    /// The home's erased subjects in the page.
    pub erased: BTreeMap<EntityId, ErasedSubject>,
    /// The home's keys the machine lacks, sealed to the machine's session.
    pub keys: Vec<OverlaySentKey>,
    /// The machine's keys the home wants, by subject and ref.
    pub wanted: BTreeSet<(EntityId, [u8; 32])>,
    /// The home's session for the wanted keys; none when it wants none.
    pub session: Option<OverlayKeySession>,
}

impl OverlayAnswer {
    fn same() -> Self {
        Self {
            same: true,
            through: None,
            erased: BTreeMap::new(),
            keys: Vec::new(),
            wanted: BTreeSet::new(),
            session: None,
        }
    }
}

/// The secret half of a machine's session for one page, held for that
/// page's answer only.
pub struct OverlayPageSession {
    secret: HybridSecretKey,
    binding: SessionBinding,
}

/// A key session a home offered a machine, until its keys arrive.
struct HeldSession {
    binding: SessionBinding,
    secret: HybridSecretKey,
}

/// The key sessions this process offered as a home: at most one per vault,
/// machine and home (one binding), in memory only.
static SESSIONS: Mutex<Vec<HeldSession>> = Mutex::new(Vec::new());

fn sessions() -> MutexGuard<'static, Vec<HeldSession>> {
    SESSIONS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("authority overlay custody refused: {reason}"))
}

/// The binding both ends derive for keys `sender` seals to `receiver` in
/// vault `vault_id`.
fn session_binding(vault_id: &[u8; 32], sender: &EntityId, receiver: &EntityId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SESSION_CONTEXT);
    hasher.update(vault_id);
    hasher.update(sender.as_bytes());
    hasher.update(receiver.as_bytes());
    *hasher.finalize().as_bytes()
}

/// This vault's authority id.
fn vault_id(vault: &Vault) -> Result<[u8; 32]> {
    let txn = vault.store.env.read_txn()?;
    vault
        .authority_view_readonly_in_txn(&txn)?
        .vault_id
        .ok_or_else(|| refused("the vault has no authority genesis yet"))
}

/// A fresh session for keys `sender` seals to `receiver`: its secret and
/// binding stay with the caller, its public half travels.
fn new_session(
    vault_id: &[u8; 32],
    sender: &EntityId,
    receiver: &EntityId,
) -> Result<(OverlayPageSession, OverlayKeySession)> {
    let secret =
        HybridSecretKey::generate(&mut SysRng).map_err(|_| refused("os randomness unavailable"))?;
    let mut nonce = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| refused("os randomness unavailable"))?;
    let public = OverlayKeySession {
        ephemeral: secret.public_key().to_bytes(),
        nonce,
    };
    let binding = SessionBinding {
        binding: session_binding(vault_id, sender, receiver),
        nonce,
    };
    Ok((OverlayPageSession { secret, binding }, public))
}

/// The digest of `inventory`, every row in order.
fn digest(inventory: &OverlayInventory) -> [u8; 32] {
    let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX).to_be_bytes();
    let mut hasher = blake3::Hasher::new_derive_key(INVENTORY_CONTEXT);
    hasher.update(&count(inventory.ready.len()));
    for (subject, key_ref) in &inventory.ready {
        hasher.update(subject.as_bytes());
        hasher.update(key_ref);
    }
    hasher.update(&count(inventory.erased.len()));
    for (subject, erased) in &inventory.erased {
        hasher.update(subject.as_bytes());
        hasher.update(&count(erased.refs.len()));
        for key_ref in &erased.refs {
            hasher.update(key_ref);
        }
        hasher.update(&count(erased.destroyed.len()));
        for key_ref in &erased.destroyed {
            hasher.update(key_ref);
        }
    }
    *hasher.finalize().as_bytes()
}

/// Whether `subject` lies in the page after `after` through `through`.
fn in_page(subject: &EntityId, after: Option<&EntityId>, through: Option<&EntityId>) -> bool {
    after.is_none_or(|after| subject > after) && through.is_none_or(|through| subject <= through)
}

/// The last subject of `inventory`'s page after `after`, when more of its
/// subjects follow that page.
fn page_end(inventory: &OverlayInventory, after: Option<&EntityId>) -> Option<EntityId> {
    let subjects: BTreeSet<&EntityId> = inventory
        .ready
        .iter()
        .map(|(subject, _)| subject)
        .chain(inventory.erased.keys())
        .filter(|subject| in_page(subject, after, None))
        .collect();
    (subjects.len() > OVERLAY_PAGE_SUBJECTS)
        .then(|| subjects.into_iter().nth(OVERLAY_PAGE_SUBJECTS - 1).copied())
        .flatten()
}

/// The earlier of two page ends; none is past every subject.
fn earlier(left: Option<EntityId>, right: Option<EntityId>) -> Option<EntityId> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (end, None) | (None, end) => end,
    }
}

/// `inventory`'s rows in the page after `after` through `through`.
fn page_of(
    inventory: &OverlayInventory,
    after: Option<&EntityId>,
    through: Option<&EntityId>,
) -> OverlayInventory {
    OverlayInventory {
        ready: inventory
            .ready
            .iter()
            .filter(|(subject, _)| in_page(subject, after, through))
            .copied()
            .collect(),
        erased: inventory
            .erased
            .iter()
            .filter(|(subject, _)| in_page(subject, after, through))
            .map(|(subject, erased)| (*subject, erased.clone()))
            .collect(),
    }
}

/// The target for keys `sender` seals to `receiver`'s session `session` in
/// vault `vault_id`.
///
/// # Errors
/// A session key that does not import.
fn live_target(
    vault_id: &[u8; 32],
    sender: &EntityId,
    receiver: &EntityId,
    session: &OverlayKeySession,
) -> Result<LiveTarget> {
    Ok(LiveTarget {
        machine: *receiver,
        session: SessionBinding {
            binding: session_binding(vault_id, sender, receiver),
            nonce: session.nonce,
        },
        ephemeral: HybridPublicKey::from_bytes(&session.ephemeral)
            .map_err(|_| refused("the receiver's session key does not import"))?,
    })
}

/// Refuses `erased`, a peer's erased subjects, when one names no ref: an
/// install learns of an erase only through a key of the subject, so its own
/// inventory names at least one, and a subject named with none is a
/// malformed page.
fn check_erased(erased: &BTreeMap<EntityId, ErasedSubject>) -> Result<()> {
    if erased.values().any(|erased| erased.refs.is_empty()) {
        return Err(refused("an erased subject names no key"));
    }
    Ok(())
}

/// Retires here each subject of `erased`, which `peer` named erased, that
/// this install does not already name erased under every one of those refs:
/// the authority's key event, one grouped writer per subject, then custody's
/// finisher after the commits. Then clears `peer`'s debts for each key it
/// names destroyed. The caller has refused a subject named with no ref
/// ([`check_erased`]).
fn retire_erased(
    vault: &Vault,
    local: &OverlayInventory,
    peer: &EntityId,
    erased: &BTreeMap<EntityId, ErasedSubject>,
) -> Result<()> {
    let mut staged = false;
    for (subject, theirs) in erased {
        if local
            .erased
            .get(subject)
            .is_some_and(|ours| ours.refs.is_superset(&theirs.refs))
        {
            continue;
        }
        let refs: Vec<[u8; 32]> = theirs.refs.iter().copied().collect();
        vault.with_write_txn_grouped(|txn| {
            crate::authority::retire_authority_overlay_subject_in_txn(
                &vault.store,
                txn,
                subject,
                &refs,
            )
        })?;
        staged = true;
    }
    if staged {
        vault.finish_erasable_retirements_after_commit();
    }
    let destroyed: BTreeSet<[u8; 32]> = erased
        .values()
        .flat_map(|erased| erased.destroyed.iter().copied())
        .collect();
    clear_destroyed_holder_debts(&vault.store, peer, &destroyed)
}

/// Opens `key`, which `sender` sealed to this install's session (`secret`
/// under `binding`, `receiver` this machine), records `sender` as a holder
/// of it, synced, and installs it in `txn` through the authority's key
/// event. The record's subject must be the one `key` names. The debt is
/// recorded before the key event, as an export records its receiver before
/// the seal: an erase of the subject here owes `sender`'s retirement
/// whatever happens to this writer.
///
/// # Errors
/// A seal that does not open for this session; a record of another purpose
/// or subject; custody faults; the key event's errors (an erased subject
/// among them).
pub(crate) fn install_received_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receiver: &EntityId,
    sender: &EntityId,
    secret: &HybridSecretKey,
    binding: &SessionBinding,
    key: &OverlaySentKey,
) -> Result<()> {
    let sealed = TransitSeal::from_bytes(key.sealed.clone());
    let (subject, custody_secret) =
        open_received_key(secret, receiver, binding, &key.key_ref, &sealed)?;
    if subject != key.subject {
        return Err(refused("a key's record names another subject"));
    }
    record_sender(&vault.store, &key.key_ref, sender)?;
    crate::authority::install_authority_overlay_key_in_txn(
        &vault.store,
        txn,
        &subject,
        &key.key_ref,
        &custody_secret,
    )
}

/// Installs each of `keys`, which `sender` sealed to this install's session,
/// each in a grouped writer of its own that records `sender` as a holder of
/// it first. Returns how many writers committed; one that does not open or
/// install is logged and not counted.
fn install_keys(
    vault: &Vault,
    receiver: &EntityId,
    sender: &EntityId,
    session: &OverlayPageSession,
    keys: Vec<OverlaySentKey>,
) -> u32 {
    let mut installed = 0u32;
    for key in keys {
        let outcome = vault.with_write_txn_grouped(|txn| {
            install_received_in_txn(
                vault,
                txn,
                receiver,
                sender,
                &session.secret,
                &session.binding,
                &key,
            )
        });
        match outcome {
            Ok(()) => installed = installed.saturating_add(1),
            Err(error) => {
                tracing::debug!(kind = ?error.kind(), "an authority overlay key was not installed");
            }
        }
    }
    installed
}

/// Seals each of `keys`, held here, to `target`, each one's holder debt
/// recorded first. One that does not export (retired or erased since the
/// inventory) is logged and left out.
fn export_keys(
    vault: &Vault,
    target: &LiveTarget,
    keys: impl IntoIterator<Item = (EntityId, [u8; 32])>,
) -> Vec<OverlaySentKey> {
    let mut sent = Vec::new();
    for (subject, key_ref) in keys {
        match export_key(&vault.store, &subject, &key_ref, target) {
            Ok(sealed) => sent.push(OverlaySentKey {
                subject,
                key_ref,
                sealed: sealed.as_bytes().to_vec(),
            }),
            Err(error) => {
                tracing::debug!(kind = ?error.kind(), "an authority overlay key was not sent");
            }
        }
    }
    sent
}

/// The machine's half: the page of this install's inventory after `after`
/// that `machine` (this install) offers `home`, with a fresh session for
/// the home's keys whose secret the caller keeps for this page's answer.
///
/// # Errors
/// A vault with no authority genesis; the random source failed; storage
/// and custody faults.
pub fn offer_overlay_page(
    vault: &Vault,
    machine: &EntityId,
    home: &EntityId,
    after: Option<EntityId>,
) -> Result<(OverlayOffer, OverlayPageSession)> {
    let vault_id = vault_id(vault)?;
    let inventory = overlay_inventory(&vault.store)?;
    let through = page_end(&inventory, after.as_ref());
    let page = page_of(&inventory, after.as_ref(), through.as_ref());
    let (page_session, session) = new_session(&vault_id, home, machine)?;
    let offer = OverlayOffer {
        digest: digest(&inventory),
        owed: awaits_retirement_by(&vault.store, &inventory, home)?,
        after,
        through,
        ready: page.ready,
        erased: page.erased,
        session,
    };
    Ok((offer, page_session))
}

/// The home's half of one page: `machine`, a machine of the owner's its
/// socket proved, offered `offer` to `home`, this install's machine. First
/// closes the session it held for the machine's last page, and refuses a
/// session key that does not import or an erased subject named with no ref,
/// before any write. Then retires the machine's erased subjects, and
/// answers: the home's erased subjects in the page, its keys the machine
/// lacks (sealed to the machine's session), the machine's keys it wants,
/// and a session for them, which it holds in memory until [`receive_keys`].
/// On a first page whose digest matches and where neither side waits on the
/// other's proof, it answers `same` and carries nothing.
///
/// # Errors
/// A vault with no authority genesis; a session key that does not import;
/// an erased subject named with no ref; the random source failed; storage,
/// custody and key-event faults.
pub(crate) fn answer_offer(
    vault: &Vault,
    home: &EntityId,
    machine: &EntityId,
    offer: &OverlayOffer,
) -> Result<OverlayAnswer> {
    let vault_id = vault_id(vault)?;
    let binding = session_binding(&vault_id, machine, home);
    sessions().retain(|entry| entry.binding.binding != binding);
    let target = live_target(&vault_id, home, machine, &offer.session)?;
    check_erased(&offer.erased)?;
    let mut local = overlay_inventory(&vault.store)?;
    if offer.after.is_none()
        && offer.digest == digest(&local)
        && !offer.owed
        && !awaits_retirement_by(&vault.store, &local, machine)?
    {
        return Ok(OverlayAnswer::same());
    }
    let after = offer.after.as_ref();
    let through = earlier(offer.through, page_end(&local, after));
    let theirs = OverlayInventory {
        ready: offer.ready.clone(),
        erased: offer.erased.clone(),
    };
    let theirs = page_of(&theirs, after, through.as_ref());
    retire_erased(vault, &local, machine, &theirs.erased)?;
    if !theirs.erased.is_empty() {
        local = overlay_inventory(&vault.store)?;
    }
    let mine = page_of(&local, after, through.as_ref());
    let send = mine
        .ready
        .iter()
        .filter(|(subject, key_ref)| {
            !theirs.ready.contains(&(*subject, *key_ref)) && !theirs.erased.contains_key(subject)
        })
        .copied();
    let keys = export_keys(vault, &target, send);
    let wanted: BTreeSet<(EntityId, [u8; 32])> = theirs
        .ready
        .iter()
        .filter(|(subject, key_ref)| {
            !mine.ready.contains(&(*subject, *key_ref)) && !mine.erased.contains_key(subject)
        })
        .copied()
        .collect();
    let session = if wanted.is_empty() {
        None
    } else {
        let (held, public) = new_session(&vault_id, machine, home)?;
        let mut held_sessions = sessions();
        held_sessions.retain(|entry| entry.binding.binding != held.binding.binding);
        held_sessions.push(HeldSession {
            binding: held.binding,
            secret: held.secret,
        });
        Some(public)
    };
    Ok(OverlayAnswer {
        same: false,
        through,
        erased: mine.erased,
        keys,
        wanted,
        session,
    })
}

/// The home's half of the keys `machine` sends: each sealed to the session
/// this install (`home`) offered it, installed through the authority's key
/// event in a writer of its own; the session closes. Returns how many it
/// installed.
///
/// # Errors
/// A vault with no authority genesis; no session open here for this
/// machine.
pub(crate) fn receive_keys(
    vault: &Vault,
    home: &EntityId,
    machine: &EntityId,
    keys: Vec<OverlaySentKey>,
) -> Result<u32> {
    let binding = session_binding(&vault_id(vault)?, machine, home);
    let held = {
        let mut held_sessions = sessions();
        let at = held_sessions
            .iter()
            .position(|entry| entry.binding.binding == binding)
            .ok_or_else(|| refused("no overlay key session is open here for this machine"))?;
        held_sessions.swap_remove(at)
    };
    let session = OverlayPageSession {
        secret: held.secret,
        binding: held.binding,
    };
    Ok(install_keys(vault, home, machine, &session, keys))
}

/// The machine's half of the home's answer to `offer`: refuses a session
/// key that does not import or an erased subject named with no ref, before
/// any write; retires the home's erased subjects, installs the home's keys
/// (sealed to `session`), and seals each key the home wants, of those this
/// page offered and of a subject the answer does not name erased, to the
/// home's session. Returns the keys to send the home; none when it wants
/// none.
///
/// # Errors
/// A vault with no authority genesis; a session key that does not import;
/// an erased subject named with no ref; storage, custody and key-event
/// faults.
pub fn apply_overlay_answer(
    vault: &Vault,
    machine: &EntityId,
    home: &EntityId,
    offer: &OverlayOffer,
    session: &OverlayPageSession,
    answer: OverlayAnswer,
) -> Result<Vec<OverlaySentKey>> {
    if answer.same {
        return Ok(Vec::new());
    }
    let vault_id = vault_id(vault)?;
    let target = answer
        .session
        .as_ref()
        .map(|theirs| live_target(&vault_id, machine, home, theirs))
        .transpose()?;
    check_erased(&answer.erased)?;
    let local = overlay_inventory(&vault.store)?;
    retire_erased(vault, &local, home, &answer.erased)?;
    install_keys(vault, machine, home, session, answer.keys);
    let Some(target) = target else {
        return Ok(Vec::new());
    };
    let wanted = answer.wanted.into_iter().filter(|(subject, key_ref)| {
        offer.ready.contains(&(*subject, *key_ref)) && !answer.erased.contains_key(subject)
    });
    Ok(export_keys(vault, &target, wanted))
}

/// One whole round between two installs of one vault, in this process and
/// with no socket (census L5-22 1a-iii): `machine` on `source` offers,
/// `home` on `destination` answers, each page in turn, as the residence
/// round runs them. Keys and erased subjects go both ways.
#[cfg(test)]
pub(crate) fn run_round_for_test(
    source: &Vault,
    machine: &EntityId,
    destination: &Vault,
    home: &EntityId,
) -> Result<()> {
    let mut after = None;
    loop {
        let (offer, session) = offer_overlay_page(source, machine, home, after)?;
        let answer = answer_offer(destination, home, machine, &offer)?;
        let through = answer.through;
        let sent = apply_overlay_answer(source, machine, home, &offer, &session, answer)?;
        if !sent.is_empty() {
            receive_keys(destination, home, machine, sent)?;
        }
        match through {
            Some(through) if after.is_none_or(|after| through > after) => after = Some(through),
            _ => return Ok(()),
        }
    }
}

/// [`run_round_for_test`]'s first page, with each key the home wants
/// installed in a writer that aborts after the key event ran: custody keeps
/// the key file it synced, and nothing the writer staged commits.
#[cfg(test)]
pub(crate) fn run_round_then_abort_for_test(
    source: &Vault,
    machine: &EntityId,
    destination: &Vault,
    home: &EntityId,
) -> Result<()> {
    let (offer, session) = offer_overlay_page(source, machine, home, None)?;
    let answer = answer_offer(destination, home, machine, &offer)?;
    let sent = apply_overlay_answer(source, machine, home, &offer, &session, answer)?;
    let binding = session_binding(&vault_id(destination)?, machine, home);
    let held = {
        let mut held_sessions = sessions();
        let at = held_sessions
            .iter()
            .position(|entry| entry.binding.binding == binding)
            .ok_or_else(|| refused("no overlay key session is open here for this machine"))?;
        held_sessions.swap_remove(at)
    };
    for key in &sent {
        let aborted = destination.with_write_txn_grouped(|txn| {
            install_received_in_txn(
                destination,
                txn,
                home,
                machine,
                &held.secret,
                &held.binding,
                key,
            )?;
            Err::<(), _>(Error::InvariantViolation(
                "the writer aborts after the install",
            ))
        });
        match aborted {
            Err(Error::InvariantViolation("the writer aborts after the install")) => {}
            Err(error) => return Err(error),
            Ok(()) => return Err(refused("the aborting writer committed")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod carrier_tests {
    //! The carrier's own tests (census L5-22 1a-iii commit 7, tasks E/F/H):
    //! the residence doors refuse strangers, the page arithmetic, and the
    //! wire codec round trips. Every test mints its own vaults and ids, so
    //! tests running in parallel never share a session. There is no positive
    //! control for E: no cheap fixture mints a trusted proven machine (the
    //! enrolment needs an owner answer), so refusal only.

    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use crate::authority::{HostSlipIssuer, PeerMachine};
    use crate::entity_id::EntityId;
    use crate::sync::residence::{
        authority_overlay_keys, authority_overlay_offer, overlay_answer_from_wire,
        overlay_answer_to_wire, overlay_keys_from_wire, overlay_keys_to_wire,
        overlay_offer_from_wire, overlay_offer_to_wire,
    };
    use crate::{Vault, VaultConfig};

    /// The host root every door-test vault in this mod is rooted under.
    const DOOR_TEST_SECRET: &[u8] = b"carrier door test host root words";

    /// A fresh vault with an authority genesis, kept alive with its dir.
    fn rooted_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        let issuer = HostSlipIssuer::from_secret(DOOR_TEST_SECRET).unwrap();
        vault.ensure_host_root_slip(&issuer).unwrap();
        (dir, vault)
    }

    /// The offer `machine` on `vault` builds for `home`.
    fn offer_for(vault: &Vault, machine: &EntityId, home: &EntityId) -> OverlayOffer {
        offer_overlay_page(vault, machine, home, None).unwrap().0
    }

    /// E: an unknown peer is refused at the overlay offer door.
    #[test]
    fn an_unknown_peer_is_refused_at_the_overlay_offer_door() {
        let (_dir, vault) = rooted_vault();
        let machine = EntityId::now();
        let home = EntityId::now();
        let offer = offer_for(&vault, &machine, &home);
        assert!(authority_overlay_offer(&vault, PeerMachine::Unknown, &offer).is_err());
    }

    /// E: a proven machine the fold does not trust is refused at the offer door.
    #[test]
    fn a_proven_but_untrusted_machine_is_refused_at_the_overlay_offer_door() {
        let (_dir, vault) = rooted_vault();
        let machine = EntityId::now();
        let home = EntityId::now();
        let offer = offer_for(&vault, &machine, &home);
        let stranger = EntityId::now();
        let peer = PeerMachine::Proven {
            machine: stranger,
            key: [0x5a; 32],
        };
        assert!(authority_overlay_offer(&vault, peer, &offer).is_err());
    }

    /// E: an unknown peer is refused at the overlay keys door before any key is read.
    #[test]
    fn an_unknown_peer_is_refused_at_the_overlay_keys_door() {
        let (_dir, vault) = rooted_vault();
        assert!(authority_overlay_keys(&vault, PeerMachine::Unknown, Vec::new()).is_err());
    }

    /// E: a proven machine the fold does not trust is refused at the keys door.
    #[test]
    fn a_proven_but_untrusted_machine_is_refused_at_the_overlay_keys_door() {
        let (_dir, vault) = rooted_vault();
        let stranger = EntityId::now();
        let peer = PeerMachine::Proven {
            machine: stranger,
            key: [0x5a; 32],
        };
        assert!(authority_overlay_keys(&vault, peer, Vec::new()).is_err());
    }

    /// F: fewer than a page of subjects has no page end.
    #[test]
    fn page_end_is_none_when_the_inventory_holds_less_than_a_page() {
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();
        let inventory = OverlayInventory {
            ready: BTreeSet::from([(a, [0x01; 32]), (b, [0x02; 32])]),
            erased: BTreeMap::from([(
                c,
                ErasedSubject {
                    refs: BTreeSet::from([[0x03; 32]]),
                    destroyed: BTreeSet::new(),
                },
            )]),
        };
        assert!(inventory.ready.len() + inventory.erased.len() < OVERLAY_PAGE_SUBJECTS);
        assert!(page_end(&inventory, None).is_none());
    }

    /// F: a page past the limit ends at the 1024th distinct subject, ready
    /// and erased mixed, one subject holding two refs counting once.
    #[test]
    fn page_end_is_the_1024th_subject_when_the_inventory_overflows_a_page() {
        let mut subjects = Vec::new();
        for _ in 0..(OVERLAY_PAGE_SUBJECTS + 1) {
            subjects.push(EntityId::now());
        }
        subjects.sort();
        subjects.dedup();
        assert_eq!(subjects.len(), OVERLAY_PAGE_SUBJECTS + 1);
        let mut ready = BTreeSet::new();
        let mut erased = BTreeMap::new();
        for (i, subject) in subjects.iter().enumerate() {
            let key_ref = [((i % 250) + 1) as u8; 32];
            if i % 2 == 0 {
                ready.insert((*subject, key_ref));
            } else {
                erased.insert(
                    *subject,
                    ErasedSubject {
                        refs: BTreeSet::from([key_ref]),
                        destroyed: BTreeSet::new(),
                    },
                );
            }
        }
        let first = subjects[0];
        ready.insert((first, [0xfe; 32]));
        let inventory = OverlayInventory { ready, erased };
        assert_eq!(
            page_end(&inventory, None),
            Some(subjects[OVERLAY_PAGE_SUBJECTS - 1])
        );
    }

    /// F: a page after one subject through another holds only what lies between.
    #[test]
    fn a_page_after_one_subject_through_another_holds_only_what_lies_between() {
        let mut subjects = [EntityId::now(), EntityId::now(), EntityId::now()];
        subjects.sort();
        let inventory = OverlayInventory {
            ready: BTreeSet::from([(subjects[0], [0x11; 32]), (subjects[1], [0x22; 32])]),
            erased: BTreeMap::from([(
                subjects[2],
                ErasedSubject {
                    refs: BTreeSet::from([[0x33; 32]]),
                    destroyed: BTreeSet::new(),
                },
            )]),
        };
        let page = page_of(&inventory, Some(&subjects[0]), Some(&subjects[1]));
        assert_eq!(page.ready, BTreeSet::from([(subjects[1], [0x22; 32])]));
        assert!(page.erased.is_empty());
        let whole = page_of(&inventory, None, None);
        assert_eq!(whole.ready, inventory.ready);
        assert_eq!(whole.erased, inventory.erased);
    }

    /// F: a lone page end passes through, and two ends keep the minimum.
    #[test]
    fn earlier_passes_a_lone_end_through_and_keeps_the_minimum_of_two() {
        let a = EntityId::now();
        let b = EntityId::now();
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        assert_eq!(earlier(Some(a), None), Some(a));
        assert_eq!(earlier(None, Some(b)), Some(b));
        assert_eq!(earlier(Some(a), Some(b)), Some(lo));
        assert_eq!(earlier(Some(hi), Some(lo)), Some(lo));
        assert_eq!(earlier(None, None), None);
    }

    /// A public key session for wire fixtures: opaque bytes and a nonce.
    fn wire_session() -> OverlayKeySession {
        OverlayKeySession {
            ephemeral: vec![0x09; 48],
            nonce: [0x07; 32],
        }
    }

    /// An offer with ready keys, an erased subject with refs and destroyed,
    /// and both bounds set.
    fn sample_offer() -> OverlayOffer {
        OverlayOffer {
            digest: [0xab; 32],
            owed: true,
            after: Some(EntityId::now()),
            through: Some(EntityId::now()),
            ready: BTreeSet::from([(EntityId::now(), [0xab; 32]), (EntityId::now(), [0xcd; 32])]),
            erased: BTreeMap::from([(
                EntityId::now(),
                ErasedSubject {
                    refs: BTreeSet::from([[0xef; 32], [0x12; 32]]),
                    destroyed: BTreeSet::from([[0xef; 32]]),
                },
            )]),
            session: wire_session(),
        }
    }

    /// An answer with a carried key, a wanted key, an erased subject and a session.
    fn sample_answer() -> OverlayAnswer {
        OverlayAnswer {
            same: false,
            through: Some(EntityId::now()),
            erased: BTreeMap::from([(
                EntityId::now(),
                ErasedSubject {
                    refs: BTreeSet::from([[0x55; 32]]),
                    destroyed: BTreeSet::new(),
                },
            )]),
            keys: vec![OverlaySentKey {
                subject: EntityId::now(),
                key_ref: [0x66; 32],
                sealed: vec![0x77; 64],
            }],
            wanted: BTreeSet::from([(EntityId::now(), [0x88; 32])]),
            session: Some(wire_session()),
        }
    }

    /// Two carried keys with distinct subjects, refs and seals.
    fn sample_keys() -> Vec<OverlaySentKey> {
        vec![
            OverlaySentKey {
                subject: EntityId::now(),
                key_ref: [0x99; 32],
                sealed: vec![0x01, 0x02, 0x03],
            },
            OverlaySentKey {
                subject: EntityId::now(),
                key_ref: [0xaa; 32],
                sealed: vec![0xff; 32],
            },
        ]
    }

    /// H: an offer with ready keys, an erased subject and bounds survives the wire.
    #[test]
    fn an_offer_with_ready_keys_an_erased_subject_and_bounds_survives_the_wire() {
        let offer = sample_offer();
        let wire = overlay_offer_to_wire(&offer);
        assert_eq!(overlay_offer_from_wire(wire), Some(offer));
    }

    /// H: an answer with keys, wanted and a session survives the wire
    /// (`OverlayAnswer` and `OverlaySentKey` have no `PartialEq`, so fields).
    #[test]
    fn an_answer_with_keys_wanted_and_a_session_survives_the_wire() {
        let answer = sample_answer();
        let wire = overlay_answer_to_wire(&answer);
        let decoded = overlay_answer_from_wire(wire).expect("a well-formed answer decodes");
        assert_eq!(decoded.same, answer.same);
        assert_eq!(decoded.through, answer.through);
        assert_eq!(decoded.erased, answer.erased);
        assert_eq!(decoded.wanted, answer.wanted);
        assert_eq!(decoded.session, answer.session);
        assert_eq!(decoded.keys.len(), answer.keys.len());
        for (got, want) in decoded.keys.iter().zip(answer.keys.iter()) {
            assert_eq!(got.subject, want.subject);
            assert_eq!(got.key_ref, want.key_ref);
            assert_eq!(got.sealed, want.sealed);
        }
    }

    /// H: carried keys survive the wire with subject, ref and seal.
    #[test]
    fn carried_keys_survive_the_wire_with_subject_ref_and_seal() {
        let keys = sample_keys();
        let wire = overlay_keys_to_wire(&keys);
        let decoded = overlay_keys_from_wire(wire).expect("well-formed keys decode");
        assert_eq!(decoded.len(), keys.len());
        for (got, want) in decoded.iter().zip(keys.iter()) {
            assert_eq!(got.subject, want.subject);
            assert_eq!(got.key_ref, want.key_ref);
            assert_eq!(got.sealed, want.sealed);
        }
    }

    /// H: a wire value with an unknown field is refused on every door.
    #[test]
    fn a_wire_value_with_an_unknown_field_is_refused() {
        let mut offer_wire = overlay_offer_to_wire(&sample_offer());
        offer_wire["unexpected"] = serde_json::json!(1);
        assert!(overlay_offer_from_wire(offer_wire).is_none());
        let mut answer_wire = overlay_answer_to_wire(&sample_answer());
        answer_wire["unexpected"] = serde_json::json!(1);
        assert!(overlay_answer_from_wire(answer_wire).is_none());
        let mut keys_wire = overlay_keys_to_wire(&sample_keys());
        keys_wire["unexpected"] = serde_json::json!(1);
        assert!(overlay_keys_from_wire(keys_wire).is_none());
    }

    /// H: an upper-case hex ref is refused from the wire.
    #[test]
    fn an_offer_with_an_upper_case_hex_ref_is_refused_from_the_wire() {
        let mut wire = overlay_offer_to_wire(&sample_offer());
        wire["ready"][0]["key"] = serde_json::json!("AB".repeat(32));
        assert!(overlay_offer_from_wire(wire).is_none());
    }

    /// H: a 31-byte ref is refused from the wire.
    #[test]
    fn carried_keys_with_a_short_ref_are_refused_from_the_wire() {
        let keys = sample_keys();
        let mut wire = overlay_keys_to_wire(&keys);
        wire["keys"][0]["key"] = serde_json::json!("ab".repeat(31));
        assert!(overlay_keys_from_wire(wire).is_none());
    }

    /// H: bad base64 is refused from the wire, in a session and in a seal.
    #[test]
    fn a_wire_value_with_bad_base64_is_refused() {
        let mut offer_wire = overlay_offer_to_wire(&sample_offer());
        offer_wire["session"]["ephemeral"] = serde_json::json!("!!!");
        assert!(overlay_offer_from_wire(offer_wire).is_none());
        let keys = sample_keys();
        let mut keys_wire = overlay_keys_to_wire(&keys);
        keys_wire["keys"][0]["sealed"] = serde_json::json!("***");
        assert!(overlay_keys_from_wire(keys_wire).is_none());
    }
}
