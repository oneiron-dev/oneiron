//! Identity asks as one reader may read them (FIX 8711).
//!
//! An ask quotes a saved mention, and its candidates name people from other
//! conversations, so every door that lists, renders, decides or answers one
//! reads it through the caller's own lane, as a runtime argument: the
//! Dreamer's relationship-granted lane for the host's decisions
//! ([`maintenance_reader`]), the owner request's own lane for the owner
//! routes, and the Memory handle's bound lane for the agent verbs. Each
//! judgement uses the lane's live policy in the door's own snapshot.
//!
//! An ask is read when its mention's turn and message are, and, when it
//! names a provisional entity of its own, every span naming that entity is
//! (a settle on another candidate reaches them all). Each candidate is read
//! on its own: a stored entity by its row, a cold provisional one through a
//! live span naming it in its origin turn. A hint counts only the
//! contributions whose mention the lane reads. An ask the lane does not
//! read looks absent; a candidate it does not read is no option. The stored
//! ask stays whole: a settle compares against it and acts on it.
use std::collections::BTreeMap;

use super::{ASKS, IdentityAsk, IdentityHint, hints};
use crate::claim::{ScopedRead, ScopedReadActorKey};
use crate::gate::PolicyManifestResolution;
use crate::{EntityId, Error, Result, Vault};

/// The Dreamer's own lane for the host's identity decisions: its
/// relationship-granted read, as the Coach's room upkeep reads. None while
/// no identity ask is open, which a read alone tells, so an idle round
/// opens no write.
///
/// # Errors
///
/// When the vault cannot resolve the Dreamer's principal.
pub fn maintenance_reader(vault: &Vault) -> Result<Option<ScopedRead<'_>>> {
    let txn = vault.store.env.read_txn()?;
    let open = ASKS.iter_from(&vault.store, &txn, &[])?.next().is_some();
    drop(txn);
    if !open {
        return Ok(None);
    }
    dreamer_reader(vault).map(Some)
}

/// The Dreamer's relationship-granted lane, whether or not an ask is open:
/// the nightly re-check settles a mention only as it reads it (FIX 10374).
///
/// # Errors
///
/// When the vault cannot resolve the Dreamer's principal.
pub(super) fn dreamer_reader(vault: &Vault) -> Result<ScopedRead<'_>> {
    let dreamer = vault.dreamer_authority()?;
    let key = ScopedReadActorKey::with_actor_class(
        dreamer.entity_ref().to_hex(),
        dreamer.actor_class().gate_actor_class(),
    )
    .ok_or_else(|| Error::InvalidConfig("invalid Dreamer read key".into()))?
    .require_relationship_grants(Some(dreamer.entity_ref()));
    Ok(vault.scoped_read(key))
}

/// One lane's judgement in one snapshot: the lane, and the live policy it
/// resolved there with an owner lane's standing rechecked.
pub(super) struct Admit<'r, 'v> {
    read: &'r ScopedRead<'v>,
    policy: PolicyManifestResolution,
}

impl<'r, 'v> Admit<'r, 'v> {
    /// `read`'s live policy in `txn`.
    pub(super) fn in_txn(read: &'r ScopedRead<'v>, txn: &heed::RoTxn<'_>) -> Result<Self> {
        Ok(Self {
            read,
            policy: read.live_policy_manifest_in(txn)?,
        })
    }

    /// Whether the lane reads `id` in `txn`.
    fn reads(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        self.read
            .is_ref_readable_with_policy_in(txn, &self.policy, id)
    }

    /// Whether the lane reads a mention: its turn and its message.
    pub(super) fn reads_source(
        &self,
        txn: &heed::RoTxn<'_>,
        turn: &EntityId,
        message: &EntityId,
    ) -> Result<bool> {
        Ok(self.reads(txn, turn)? && self.reads(txn, message)?)
    }
}

/// An open ask as one lane reads it.
pub(super) struct AdmittedIdentityAsk {
    /// The ask as stored: a settle compares against it and acts on it.
    pub(super) stored: IdentityAsk,
    /// The ask with only the candidates the lane reads, in stored order;
    /// its own provisional entity none when that is not one of them.
    pub(super) ask: IdentityAsk,
    /// Each candidate's hint, summed over the contributions the lane reads.
    pub(super) hints: BTreeMap<EntityId, IdentityHint>,
    /// What this read rests on: the mention's turn and message, each
    /// candidate read, and the turn and message of each hint contribution
    /// summed.
    pub(super) evidence: Vec<EntityId>,
}

impl AdmittedIdentityAsk {
    /// Whether the lane reads every stored candidate. The Dreamer decides
    /// only such an ask; any other waits for the owner.
    pub(super) fn whole(&self) -> bool {
        self.ask.candidates.len() == self.stored.candidates.len()
    }
}

/// Whether `admit` reads candidate `id`: a stored entity by its own row, a
/// cold provisional one, which has none, through a span naming it in its
/// origin turn.
pub(super) fn candidate_in_txn(
    vault: &Vault,
    admit: &Admit<'_, '_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(entity) = crate::tagging::provisional_in_txn(&vault.store, txn, id)? else {
        return admit.reads(txn, id);
    };
    for (turn, mention) in vault.mentions_naming_in_txn(txn, id)? {
        if turn == entity.origin && admit.reads_source(txn, &turn, &mention.message)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `admit` reads every span naming `own`, which a settle on another
/// candidate absorbs.
fn spans_in_txn(
    vault: &Vault,
    admit: &Admit<'_, '_>,
    txn: &heed::RoTxn<'_>,
    own: &EntityId,
) -> Result<bool> {
    for (turn, mention) in vault.mentions_naming_in_txn(txn, own)? {
        if !admit.reads_source(txn, &turn, &mention.message)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `stored` as `admit` reads it in `txn`: none when it does not read the
/// mention, or a span naming the ask's own provisional entity; else the
/// candidates and hint words it reads.
pub(super) fn admitted_in_txn(
    vault: &Vault,
    admit: &Admit<'_, '_>,
    txn: &heed::RoTxn<'_>,
    stored: IdentityAsk,
) -> Result<Option<AdmittedIdentityAsk>> {
    if !admit.reads_source(txn, &stored.turn, &stored.message)? {
        return Ok(None);
    }
    if let Some(own) = stored.provisional
        && !spans_in_txn(vault, admit, txn, &own)?
    {
        return Ok(None);
    }
    let mut candidates = Vec::with_capacity(stored.candidates.len());
    for id in &stored.candidates {
        if candidate_in_txn(vault, admit, txn, id)? {
            candidates.push(*id);
        }
    }
    let mut evidence = vec![stored.turn, stored.message];
    evidence.extend(candidates.iter().copied());
    let mut hints = BTreeMap::new();
    let summed = hints::hints_in_txn(&vault.store, txn, (stored.kind, &stored.name), Some(admit))?;
    for (entity, hint, sources) in summed {
        if !candidates.contains(&entity) {
            continue;
        }
        for source in sources {
            for id in [source.turn, source.message] {
                if !evidence.contains(&id) {
                    evidence.push(id);
                }
            }
        }
        hints.insert(entity, hint);
    }
    let provisional = stored.provisional.filter(|own| candidates.contains(own));
    let ask = IdentityAsk {
        candidates,
        provisional,
        ..stored.clone()
    };
    Ok(Some(AdmittedIdentityAsk {
        stored,
        ask,
        hints,
        evidence,
    }))
}

/// The open ask `key` as `read` reads it in `txn`, under its live policy
/// there: none when no such ask is open or the lane does not read it, and,
/// with `whole`, when it does not read every candidate.
pub(super) fn open_ask_in_txn(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
    whole: bool,
) -> Result<Option<AdmittedIdentityAsk>> {
    let Some(stored) = ASKS.get(&vault.store, txn, key)? else {
        return Ok(None);
    };
    let admit = Admit::in_txn(read, txn)?;
    Ok(admitted_in_txn(vault, &admit, txn, stored)?.filter(|seen| !whole || seen.whole()))
}
