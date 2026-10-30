//! Channel-identity consume door: usage accounting, and the fair wait of an
//! action that meets a full envelope window.

use super::bound::invalid_grant;
use super::verb_class::verb_in_class;
use crate::Vault;
use crate::channel_identity_autonomy::{
    ChannelIdentityActionEnvelope, ChannelIdentityEffectCandidate,
};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;

/// One usage row per immutable envelope, shared by all grants naming it.
pub const CHANNEL_IDENTITY_GRANT_USAGE_PREFIX: &[u8] = b"outbound_grant:channel_identity_usage:v1:";

/// The reason a send its sender's envelope covers names while it waits in
/// that envelope's line for a full window to open.
pub const CHANNEL_IDENTITY_WINDOW_WAIT_REASON: &str = "gate.pending.channel_identity_window_wait";

/// One envelope's usage window: the window start, the spent
/// `(effect_key, fingerprint)` pairs, and the line of actions retained for a
/// later window. Keyed by the envelope id.
const USAGE: SideTable<EntityId, ChannelIdentityGrantUsage, Raw> =
    SideTable::new(&side_table::OUTBOUND_GRANT_CHANNEL_IDENTITY_USAGE);

/// How long a retained action keeps its place once the window its turn falls
/// in opens, if it does not come back; a shorter window bounds it to the
/// window itself.
const WINDOW_WAIT_HOLD_SECS: u64 = 15 * 60;

#[derive(Clone, PartialEq, Eq)]
struct ChannelIdentityGrantUsage {
    started: u64,
    effects: Vec<([u8; 32], [u8; 32])>,
    /// Actions that met a full window, in arrival order.
    retained: Vec<RetainedAction>,
}

/// One action's place in its envelope's line.
#[derive(Clone, Copy, PartialEq, Eq)]
struct RetainedAction {
    effect_key: [u8; 32],
    fingerprint: [u8; 32],
    /// The engine second its place lapses unless it comes back first.
    deadline: u64,
}

impl RawValue for ChannelIdentityGrantUsage {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut bytes = self.started.to_be_bytes().to_vec();
        bytes.extend_from_slice(&row_count(self.effects.len())?);
        for (effect, fingerprint) in &self.effects {
            bytes.extend_from_slice(effect);
            bytes.extend_from_slice(fingerprint);
        }
        bytes.extend_from_slice(&row_count(self.retained.len())?);
        for action in &self.retained {
            bytes.extend_from_slice(&action.effect_key);
            bytes.extend_from_slice(&action.fingerprint);
            bytes.extend_from_slice(&action.deadline.to_be_bytes());
        }
        Ok(bytes)
    }

    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        let mut rest = raw;
        let started = u64::from_be_bytes(take(&mut rest)?);
        let spent = u32::from_be_bytes(take(&mut rest)?);
        let mut effects: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for _ in 0..spent {
            effects.push((take(&mut rest)?, take(&mut rest)?));
        }
        let held = u32::from_be_bytes(take(&mut rest)?);
        let mut retained = Vec::new();
        for _ in 0..held {
            retained.push(RetainedAction {
                effect_key: take(&mut rest)?,
                fingerprint: take(&mut rest)?,
                deadline: u64::from_be_bytes(take(&mut rest)?),
            });
        }
        if !rest.is_empty() {
            return Err(invalid_grant().into());
        }
        Ok(Self {
            started,
            effects,
            retained,
        })
    }
}

/// The next `N` bytes of a usage row.
fn take<const N: usize>(rest: &mut &[u8]) -> std::result::Result<[u8; N], CodecError> {
    let bytes = *rest;
    let Some((head, tail)) = bytes.split_first_chunk::<N>() else {
        return Err(invalid_grant().into());
    };
    *rest = tail;
    Ok(*head)
}

/// A list length, as the usage row stores it.
fn row_count(len: usize) -> std::result::Result<[u8; 4], CodecError> {
    Ok(u32::try_from(len)
        .map_err(|_| invalid_grant())?
        .to_be_bytes())
}

/// What [`Vault::admit_channel_identity_grant`] decided for one action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelIdentityGrantOutcome {
    /// The action holds a slot in its envelope's window: a new one, or on a
    /// true retry the one it was first given.
    Admitted,
    /// The window is full. The action keeps its place in the envelope's line
    /// until the wait's deadline, and nothing is spent; called again with the
    /// same effect key once the window opens, it takes its turn.
    WindowWait(ChannelIdentityWindowWait),
    /// Absent, revoked or mismatched authority, an effect key already spent
    /// or retained for another verb, or a clock rollback.
    Denied,
}

/// A full envelope window one channel-identity action met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelIdentityWindowWait {
    /// The immutable envelope whose window is full.
    pub envelope_ref: EntityId,
    /// The action's engine effect key, which holds its place.
    pub effect_key: [u8; 32],
    /// Retained actions ahead of it in the envelope's line.
    pub ahead: u32,
    /// The earliest engine second the window its turn falls in opens.
    pub next_eligible_at: u64,
    /// The engine second its place lapses unless it comes back first.
    pub deadline: u64,
}

impl Vault {
    /// Atomically authorizes and reserves an action using the engine clock:
    /// `true` only when [`Self::admit_channel_identity_grant`] admits it. A
    /// full window keeps the action's place there too, and a retry with the
    /// same effect key takes its turn.
    ///
    /// A true retry reuses the reservation; it is not permission to execute a
    /// second delivery. Dispatch must retain the same engine effect key. This
    /// door never reads a caller timestamp or delegates to a dial's effect match.
    pub fn authorize_and_consume_channel_identity_grant(
        &self,
        grant_ref: &EntityId,
        candidate: &ChannelIdentityEffectCandidate,
    ) -> Result<bool> {
        Ok(self.admit_channel_identity_grant(grant_ref, candidate)?
            == ChannelIdentityGrantOutcome::Admitted)
    }

    /// Atomically authorizes one action against its envelope on the engine
    /// clock. An admitted action spends its slot and receipts its grant's
    /// use. One
    /// that meets a full window spends nothing and keeps its place in the
    /// envelope's line, in arrival order, until its deadline: slots that open
    /// go to the line first. Every call proves the action's authority again
    /// on its own transaction (grant, envelope, autonomy rung and binding),
    /// so a retained action is admitted only under authority still live and
    /// only into a slot its envelope still has.
    pub fn admit_channel_identity_grant(
        &self,
        grant_ref: &EntityId,
        candidate: &ChannelIdentityEffectCandidate,
    ) -> Result<ChannelIdentityGrantOutcome> {
        let now = self.store.authorization_now()?;
        let mut txn = self.store.env.write_txn()?;
        let admission =
            admit_channel_identity_grant_in_txn(&self.store, &txn, grant_ref, candidate, now)?;
        let outcome = match admission {
            ChannelIdentityGrantAdmission::Reserved(reservation) => {
                reservation.commit_in_txn(&self.store, &mut txn)?;
                ChannelIdentityGrantOutcome::Admitted
            }
            ChannelIdentityGrantAdmission::WindowWait(retention) => {
                ChannelIdentityGrantOutcome::WindowWait(
                    retention.retain_in_txn(&self.store, &mut txn)?,
                )
            }
            ChannelIdentityGrantAdmission::Denied => {
                return Ok(ChannelIdentityGrantOutcome::Denied);
            }
        };
        txn.commit()?;
        Ok(outcome)
    }
}

/// What one channel-identity action meets at its envelope, proven on the
/// caller's transaction and not yet written.
pub(crate) enum ChannelIdentityGrantAdmission {
    /// A slot, spent by [`ChannelIdentityGrantReservation::commit_in_txn`].
    Reserved(Box<ChannelIdentityGrantReservation>),
    /// A full window: a place in its line, kept by
    /// [`ChannelIdentityGrantRetention::retain_in_txn`].
    WindowWait(ChannelIdentityGrantRetention),
    /// Absent, revoked or mismatched authority, an effect key spent or
    /// retained for another verb, or a clock rollback.
    Denied,
}

/// One envelope slot proven on the caller's transaction and not yet spent.
/// [`Self::commit_in_txn`] spends it; dropping it spends nothing, so a caller
/// that holds, denies or aborts its effect leaves the window untouched.
pub(crate) struct ChannelIdentityGrantReservation {
    /// The standing consent Grant row the action stands on.
    consent_grant_ref: String,
    /// The action's engine effect key, which its use receipt names.
    effect_key: [u8; 32],
    envelope_ref: EntityId,
    /// The usage row this reservation was proven against.
    prior: Option<ChannelIdentityGrantUsage>,
    /// The window with this effect added, or `None` for an exact replay
    /// whose slot was spent when it was first reserved.
    next: Option<ChannelIdentityGrantUsage>,
}

impl ChannelIdentityGrantReservation {
    /// Spends the slot and writes the grant's use receipt, in the caller's
    /// write txn. An exact replay writes nothing, so it is never charged
    /// twice.
    pub(crate) fn commit_in_txn(self, store: &Store, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
        let Some(next) = self.next else {
            return Ok(());
        };
        put_usage(store, wtxn, &self.envelope_ref, self.prior.as_ref(), &next)?;
        crate::consent::record_standing_grant_use_for_store_in_txn(
            store,
            wtxn,
            &self.consent_grant_ref,
            crate::consent::EffectDigest::from_bytes(self.effect_key),
        )?;
        Ok(())
    }
}

/// One action's place in a full window's line, proven on the caller's
/// transaction and not yet written. [`Self::retain_in_txn`] keeps it;
/// dropping it keeps nothing, and the action meets the line afresh when it
/// comes back.
pub(crate) struct ChannelIdentityGrantRetention {
    envelope_ref: EntityId,
    /// The usage row this place was proven against.
    prior: Option<ChannelIdentityGrantUsage>,
    /// The row with this action's place kept, or `None` when the stored row
    /// already keeps it as it stands.
    next: Option<ChannelIdentityGrantUsage>,
    wait: ChannelIdentityWindowWait,
}

impl ChannelIdentityGrantRetention {
    /// Keeps the place in the caller's write txn and returns the wait.
    pub(crate) fn retain_in_txn(
        self,
        store: &Store,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<ChannelIdentityWindowWait> {
        if let Some(next) = &self.next {
            put_usage(store, wtxn, &self.envelope_ref, self.prior.as_ref(), next)?;
        }
        Ok(self.wait)
    }
}

/// Writes `next` over the usage row a proof read as `prior`. A second proof
/// of the same envelope inside one txn was made on the row the first one
/// replaces: fail the txn, never lose a spent slot or a kept place.
fn put_usage(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    envelope_ref: &EntityId,
    prior: Option<&ChannelIdentityGrantUsage>,
    next: &ChannelIdentityGrantUsage,
) -> Result<()> {
    if USAGE.get(store, &*wtxn, envelope_ref)?.as_ref() != prior {
        return Err(Error::InvariantViolation(
            "channel identity envelope changed inside admission transaction",
        ));
    }
    USAGE.put(store, wtxn, envelope_ref, next)
}

/// The live authority one channel-identity action stands on.
struct ActionAuthority {
    /// The standing consent Grant row the autonomy row's action grant is.
    consent_grant_ref: String,
    envelope_ref: EntityId,
    envelope: ChannelIdentityActionEnvelope,
    /// The action's verb, trimmed and lowercased.
    verb: String,
}

/// Proves `candidate`'s authority under `grant_ref` at `now` on the caller's
/// transaction: a live action Grant `grant_ref` names whose identity and
/// verb class cover the action, an envelope valid for its context and
/// counterparty class, and an autonomy row that still names this grant at a
/// rung allowing the verb.
/// `None` is a denial. Structural/storage failures stay errors; no error
/// ever falls through to a less constrained dial.
fn action_authority_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    grant_ref: &EntityId,
    candidate: &ChannelIdentityEffectCandidate,
    now: u64,
) -> Result<Option<ActionAuthority>> {
    use crate::channel_identity_autonomy::{AutonomyReader, ChannelIdentityAutonomyRung};

    let reader = AutonomyReader { store };
    let Some(action) = reader.autonomy_action_grant_in_txn(txn, *grant_ref)? else {
        return Ok(None);
    };
    let verb = candidate.verb_class.trim().to_ascii_lowercase();
    if action.identity_ref != candidate.identity_ref || !verb_in_class(&action.verb_class, &verb) {
        return Ok(None);
    }
    let envelope = match reader.validate_autonomy_action(txn, &action, now) {
        Ok(envelope) => envelope,
        Err(Error::Gate(GateError::InvalidConsentBound(_))) => return Ok(None),
        Err(error) => return Err(error),
    };
    if envelope.relationship_context != candidate.relationship_context
        || envelope.counterparty_class != candidate.counterparty_class
    {
        return Ok(None);
    }
    let mode = match reader.autonomy_mode_in_txn(
        txn,
        candidate.identity_ref,
        candidate.relationship_context,
        now,
        now,
    ) {
        Ok(mode) => mode,
        Err(Error::Gate(GateError::InvalidConsentBound(_))) => return Ok(None),
        Err(error) => return Err(error),
    };
    if mode.action_grant_ref != Some(*grant_ref)
        || (verb == "mail.send"
            && mode.rung != ChannelIdentityAutonomyRung::AutonomousWithinEnvelope)
    {
        return Ok(None);
    }
    Ok(Some(ActionAuthority {
        consent_grant_ref: action.grant_ref,
        envelope_ref: action.envelope_ref,
        envelope,
        verb,
    }))
}

/// Authorizes one channel-identity action against its envelope on the
/// caller's transaction and returns what it meets there, without writing: a
/// slot to spend, a place in the line of a full window, or a denial. The
/// line is fair: a slot that opens goes to the actions retained ahead first,
/// a place lapses at its deadline, and no wait adds a slot to the owner's
/// envelope.
pub(crate) fn admit_channel_identity_grant_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    grant_ref: &EntityId,
    candidate: &ChannelIdentityEffectCandidate,
    now: u64,
) -> Result<ChannelIdentityGrantAdmission> {
    let Some(authority) = action_authority_in_txn(store, txn, grant_ref, candidate, now)? else {
        return Ok(ChannelIdentityGrantAdmission::Denied);
    };
    let envelope_ref = authority.envelope_ref;
    let max_actions = authority.envelope.max_actions as usize;
    let window_secs = authority.envelope.window_secs;
    let prior = USAGE.get(store, txn, &envelope_ref)?;
    let mut usage = prior.clone().unwrap_or_else(|| ChannelIdentityGrantUsage {
        started: now,
        effects: Vec::new(),
        retained: Vec::new(),
    });
    if usage.effects.len() > max_actions {
        return Err(invalid_grant());
    }
    // Clock rollback cannot reset a window or spend a fresh slot.
    if now < usage.started {
        return Ok(ChannelIdentityGrantAdmission::Denied);
    }
    // An elapsed window holds nothing spent; it restarts at its next admission.
    let elapsed = now - usage.started >= window_secs;
    let key = candidate.effect_key;
    let fingerprint = *blake3::hash(authority.verb.as_bytes()).as_bytes();
    if !elapsed && let Some((_, stored)) = usage.effects.iter().find(|(spent, _)| *spent == key) {
        return Ok(if *stored == fingerprint {
            reserved(authority.consent_grant_ref, key, envelope_ref, prior, None)
        } else {
            ChannelIdentityGrantAdmission::Denied
        });
    }
    // A place lapses at its deadline; the line keeps arrival order.
    usage.retained.retain(|action| action.deadline > now);
    let place = usage
        .retained
        .iter()
        .position(|action| action.effect_key == key);
    if place.is_some_and(|at| usage.retained[at].fingerprint != fingerprint) {
        return Ok(ChannelIdentityGrantAdmission::Denied);
    }
    let ahead = place.unwrap_or(usage.retained.len());
    let spent = if elapsed { 0 } else { usage.effects.len() };
    if spent + ahead < max_actions {
        if let Some(at) = place {
            usage.retained.remove(at);
        }
        if elapsed {
            usage.started = now;
            usage.effects.clear();
        }
        usage.effects.push((key, fingerprint));
        return Ok(reserved(
            authority.consent_grant_ref,
            key,
            envelope_ref,
            prior,
            Some(usage),
        ));
    }
    // Its turn is slot `spent + ahead`, counted from this window's start (now,
    // for an elapsed window); each later window opens at least one window
    // after the one before it.
    let base = if elapsed { now } else { usage.started };
    let windows = ((spent + ahead) / max_actions.max(1)) as u64;
    let next_eligible_at = base.saturating_add(window_secs.saturating_mul(windows));
    let hold = next_eligible_at.saturating_add(window_secs.min(WINDOW_WAIT_HOLD_SECS));
    let deadline = match place {
        Some(at) => {
            let action = &mut usage.retained[at];
            action.deadline = action.deadline.max(hold);
            action.deadline
        }
        None => {
            usage.retained.push(RetainedAction {
                effect_key: key,
                fingerprint,
                deadline: hold,
            });
            hold
        }
    };
    let wait = ChannelIdentityWindowWait {
        envelope_ref,
        effect_key: key,
        ahead: u32::try_from(ahead).unwrap_or(u32::MAX),
        next_eligible_at,
        deadline,
    };
    let next = (prior.as_ref() != Some(&usage)).then_some(usage);
    Ok(ChannelIdentityGrantAdmission::WindowWait(
        ChannelIdentityGrantRetention {
            envelope_ref,
            prior,
            next,
            wait,
        },
    ))
}

fn reserved(
    consent_grant_ref: String,
    effect_key: [u8; 32],
    envelope_ref: EntityId,
    prior: Option<ChannelIdentityGrantUsage>,
    next: Option<ChannelIdentityGrantUsage>,
) -> ChannelIdentityGrantAdmission {
    ChannelIdentityGrantAdmission::Reserved(Box::new(ChannelIdentityGrantReservation {
        consent_grant_ref,
        effect_key,
        envelope_ref,
        prior,
        next,
    }))
}
