//! Who decided a topology seal, and whether that decision stands here (mesh
//! PR2-topology, amended 10-19 03:0x; contract §1-§4).
//!
//! Two seal classes share the one admission signature. A **decision seal**
//! is the owner's say-so or an agent's act within its Grant: its signature
//! covers an [`OwnerAct`] (`topology_seal`, its target the decision event)
//! beside the carrier machine, the core digest, the verdict and the reason.
//! Every replica, this one included, admits it the same way: the one carrier
//! rule ([`owner_act_signer_admits`]) for the carrier and the act's owner
//! live, both at the seal's signed authority heads, and an agent's Grant
//! naming `topology_seal` where this replica holds the Grant row (a replica
//! without it trusts the carrier, CALLS "mesh agent grant on replicas").
//! `SEALED_HERE` records only provenance for it. An
//! **engine seal** is the engine's own bookkeeping: it carries a typed
//! [`EngineCause`], never the owner's will, and keeps today's admission
//! exactly (this install's own seal locally, a trusted machine's on
//! replicas). Each cause is a named variant, so a later ruling moves one cause
//! and nothing else.
//!
//! Causal point (FIX 4649): a decision seal signs the authority-log heads its
//! carrier held as it decided ([`crate::authority::act_heads`]). Every reader
//! judges the carrier and the owner's binding at those heads, and a later
//! removal of the carrier by the one removal race: a removal that saw the
//! seal keeps it standing, one in its signed past or one that never saw it
//! retires it ([`crate::authority::ExternalAct`]). A seal whose heads this
//! replica does not hold is pending. Known limit (FIX-LIST, Phase 2): an
//! agent's Grant is still judged on the row this replica holds now, so a
//! later Grant revocation retires the agent's earlier seals.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use rmpv::Value;

use crate::authority::{
    ActAuthority, ActBy, ActSurface, AuthorityEntryHash, AuthorityFold, AuthorityKey,
    ExternalActStanding, GrantStanding, OwnerAct, OwnerActKind, grant_standing_in_txn,
    owner_act_signer_admits,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::store::Store;
use crate::vault::Vault;

use super::admission_disposition::{SealTrust, core_digest};
use super::ledger_fold::{IdentityTopologyAction, fold_identity_topology_log};
use super::stored_event::StoredIdentityOpAction;
use super::transition_table::IdentityTopologyRejection;

/// The context of a decided-on event's revision, the `seen` a deciding
/// surface shows and a door compares (mesh PR2-topology).
pub const TOPOLOGY_SEAL_REVISION_CONTEXT: &[u8] = b"oneiron/topology-seal-revision/v1";
/// The context of one deciding row's head hash inside that revision.
const TOPOLOGY_SEAL_HEAD_CONTEXT: &[u8] = b"oneiron/topology-seal-head/v1";
/// The context of the standing digest the reconcile pass compares.
const TOPOLOGY_SEAL_STANDING_CONTEXT: &[u8] = b"oneiron/topology-seal-standing/v1";

/// The typed standing outcome of a decision seal that does not count (mesh
/// PR2-reasons): never a mine-only refusal.
pub const SEAL_NO_STANDING: &str =
    "topology seal has no admitted live carrier/owner or named Grant";
/// This install has no live machine profile the one carrier rule admits, so
/// it cannot carry the owner's or an agent's decision. Key possession; FIX
/// 2222 keeps every roster key out.
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to \
                          carry a topology decision; nothing was written";
/// An agent's act never answers an owner's ask: only his own say-so does.
const AGENT_ANSWER: &str = "an agent's topology decision cannot answer the owner's ask";
/// The causal point a decision signs is bounded like an authority entry's
/// parents ([`crate::authority::MAX_PARENTS`]).
const HEADS_BOUND: &str = "this install's authority frontier is wider than one topology decision \
                           may sign; nothing was written";

/// Policy hook (CALLS "mesh PR2a unprofiled carrier fallback", open): the
/// seal an owner's decision takes when this install has no live machine
/// profile in the vault's roster to carry it. Today's capability stays: an
/// engine seal under this cause, admitted as today (this install's own seal
/// locally, a trusted machine's on replicas), claiming no owner will and
/// relabelling nothing Yours. `None` refuses with [`NO_CARRIER`] instead, once
/// the serving install is profiled at start (C4 bootstrap arm). An agent's
/// decision with no carrier always refuses: that is a new capability.
const OWNER_DECISION_WITHOUT_CARRIER: Option<EngineCause> =
    Some(EngineCause::OwnerAnswerUnprofiledCarrier);

/// Why the engine sealed a topology fact when no owner or agent decided it.
/// It never claims the owner's will.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EngineCause {
    /// Written through a door signature that names no deciding authority.
    Unattributed,
    /// Same-party-key twins converging on the smallest id (comm parties).
    CommPartyKeyTwin,
    /// A proposal cancelled because its participant was deleted (erase and
    /// tombstone replay).
    ParticipantDeleted,
    /// A deletion or redaction refusal: negative only.
    IntegrityRefusal,
    /// The Dreamer's own decision, with no owner answer and no Grant line.
    DreamerInference,
    /// An owner's answer with no owner proof in reach (a room turn).
    OwnerAnswerUnproven,
    /// An owner's decision on an install with no live machine profile in
    /// the vault's roster to carry it ([`OWNER_DECISION_WITHOUT_CARRIER`]):
    /// today's capability, claiming no owner will.
    OwnerAnswerUnprofiledCarrier,
}

impl EngineCause {
    /// The wire tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unattributed => "unattributed",
            Self::CommPartyKeyTwin => "comm_party_key_twin",
            Self::ParticipantDeleted => "participant_deleted",
            Self::IntegrityRefusal => "integrity_refusal",
            Self::DreamerInference => "dreamer_inference",
            Self::OwnerAnswerUnproven => "owner_answer_unproven",
            Self::OwnerAnswerUnprofiledCarrier => "owner_answer_unprofiled_carrier",
        }
    }

    fn parse(tag: &str) -> Option<Self> {
        Some(match tag {
            "unattributed" => Self::Unattributed,
            "comm_party_key_twin" => Self::CommPartyKeyTwin,
            "participant_deleted" => Self::ParticipantDeleted,
            "integrity_refusal" => Self::IntegrityRefusal,
            "dreamer_inference" => Self::DreamerInference,
            "owner_answer_unproven" => Self::OwnerAnswerUnproven,
            "owner_answer_unprofiled_carrier" => Self::OwnerAnswerUnprofiledCarrier,
            _ => return None,
        })
    }
}

/// Who decided, as a seal records it under its one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealAuthority {
    /// The owner's or an agent's decision: kind `topology_seal`, its target
    /// the seal's target event.
    Decision(OwnerAct),
    /// The engine's own bookkeeping.
    Engine(EngineCause),
}

impl SealAuthority {
    /// The bytes the seal's signature covers for this authority: a tag, then
    /// the owner act's canonical map or the cause's wire tag.
    pub(super) fn transcript_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        match self {
            Self::Decision(act) => {
                bytes.extend_from_slice(b"decision\0");
                rmpv::encode::write_value(&mut bytes, &crate::authority::owner_act_to_value(act))
                    .map_err(|_| Error::InvariantViolation("topology seal act encoding"))?;
            }
            Self::Engine(cause) => {
                bytes.extend_from_slice(b"engine\0");
                bytes.extend_from_slice(cause.as_str().as_bytes());
            }
        }
        Ok(bytes)
    }

    /// Appends the authority's wire entry: `act` or `cause`, never both.
    pub(super) fn encode_entry(&self, entries: &mut Vec<(Value, Value)>) {
        use super::wire_keys::{BODY_KEY_SEAL_ACT, BODY_KEY_SEAL_CAUSE};
        match self {
            Self::Decision(act) => entries.push((
                BODY_KEY_SEAL_ACT.into(),
                crate::authority::owner_act_to_value(act),
            )),
            Self::Engine(cause) => {
                entries.push((BODY_KEY_SEAL_CAUSE.into(), cause.as_str().into()))
            }
        }
    }

    /// The [`Self::encode_entry`] inverse for a seal on `target`: exactly one
    /// of `act` and `cause`, the act of kind `topology_seal` naming `target`.
    pub(super) fn decode_entry(
        map: &[(Value, Value)],
        target: EntityId,
        malformed: &'static str,
    ) -> Result<Self> {
        use super::event_body_codec::map_field;
        use super::wire_keys::{BODY_KEY_SEAL_ACT, BODY_KEY_SEAL_CAUSE};
        let bad = || Error::Sync(SyncError::InvalidIdentityTopologyEventBody(malformed));
        match (
            map_field(map, BODY_KEY_SEAL_ACT),
            map_field(map, BODY_KEY_SEAL_CAUSE),
        ) {
            (Some(value), None) => {
                let act = crate::authority::owner_act_from_value(value).map_err(|_| bad())?;
                act.validate_carried(OwnerActKind::TopologySeal, target)
                    .map_err(|_| bad())?;
                Ok(Self::Decision(act))
            }
            (None, Some(value)) => value
                .as_str()
                .and_then(EngineCause::parse)
                .map(Self::Engine)
                .ok_or_else(bad),
            _ => Err(bad()),
        }
    }
}

/// Who decides a topology write's seals, in process only.
#[derive(Debug, Clone)]
pub enum TopologySealBy {
    /// The owner (`owner()`, `owner_authorship()`) or an agent's
    /// [`crate::authority::GrantedAct`] naming `topology_seal`.
    Decision(ActAuthority),
    /// The engine's own bookkeeping.
    Engine(EngineCause),
}

/// The seal context a topology door takes (mesh PR2-topology): who decides,
/// the revision of the decided-on event the deciding surface showed, and the
/// ask an owner's decision answers. Never a field of the write metadata.
#[derive(Debug, Clone)]
pub struct TopologySeal {
    by: TopologySealBy,
    seen: Option<[u8; 32]>,
    answer: Option<EntityId>,
}

impl TopologySeal {
    /// A decision by the owner or by an agent within its Grant.
    #[must_use]
    pub fn decision(authority: ActAuthority) -> Self {
        Self {
            by: TopologySealBy::Decision(authority),
            seen: None,
            answer: None,
        }
    }

    /// The engine's own bookkeeping under `cause`.
    #[must_use]
    pub fn engine(cause: EngineCause) -> Self {
        Self {
            by: TopologySealBy::Engine(cause),
            seen: None,
            answer: None,
        }
    }

    /// The revision of the decided-on event the deciding surface showed
    /// ([`Vault::identity_topology_seal_revision`]): an undo's target, a
    /// ruling's proposal, zero for an op the write mints. The door compares
    /// it in its transaction; `None` compares nothing.
    #[must_use]
    pub fn with_seen(mut self, seen: Option<[u8; 32]>) -> Self {
        self.seen = seen;
        self
    }

    /// The owner's ask this decision answers, recorded as the act's `answer`.
    #[must_use]
    pub fn answering(mut self, ask: EntityId) -> Self {
        self.answer = Some(ask);
        self
    }
}

/// What a validated seal context records on each seal its write signs.
enum SealBasis {
    Decision {
        owner: EntityId,
        by: ActBy,
        surface: ActSurface,
        answer: Option<EntityId>,
    },
    Engine(EngineCause),
}

/// A seal context the writing transaction validated, with the carrier that
/// signs: this install's machine and key, and for a decision the causal
/// point it signs (FIX 4649; empty for an engine seal).
pub(crate) struct ResolvedSeal {
    carrier: EntityId,
    key: SigningKey,
    basis: SealBasis,
    heads: BTreeSet<AuthorityEntryHash>,
}

impl ResolvedSeal {
    /// An engine seal under `cause`, signed by this install.
    pub(super) fn engine_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        cause: EngineCause,
    ) -> Result<Self> {
        let (carrier, key) = crate::identity::machine_signer_in_txn(vault, txn)?;
        Ok(Self {
            carrier,
            key,
            basis: SealBasis::Engine(cause),
            heads: BTreeSet::new(),
        })
    }

    pub(super) fn carrier(&self) -> EntityId {
        self.carrier
    }

    pub(super) fn key(&self) -> &SigningKey {
        &self.key
    }

    /// The causal point a decision this context seals signs.
    pub(super) fn heads(&self) -> &BTreeSet<AuthorityEntryHash> {
        &self.heads
    }

    /// The authority a seal on `target`, an event minted in this
    /// transaction, records. A decision's act names `target`; its `seen` is
    /// that event's revision, zero, since no row names an id minted in this
    /// transaction.
    pub(super) fn authority_for_fresh(&self, target: EntityId) -> SealAuthority {
        match &self.basis {
            SealBasis::Decision {
                owner,
                by,
                surface,
                answer,
            } => SealAuthority::Decision(OwnerAct {
                owner: *owner,
                by: *by,
                surface: *surface,
                act: OwnerActKind::TopologySeal,
                target,
                seen: [0; 32],
                answer: *answer,
            }),
            SealBasis::Engine(cause) => SealAuthority::Engine(*cause),
        }
    }
}

fn seal_refused(reason: &'static str) -> Error {
    Error::Sync(SyncError::IdentityTopologyRejected(
        IdentityTopologyRejection::SealAuthorityRefused { reason },
    ))
}

/// Validates `seal` in the writing transaction, before any local effect: the
/// `seen` revision of `ruled` (an undo's target, a ruling's proposal; `None`
/// for an op this write mints, whose revision is zero) is current, else a
/// typed conflict naming the current revision; a decision's carrier is this
/// install under the one carrier rule (an owner's decision with no carrier
/// takes [`OWNER_DECISION_WITHOUT_CARRIER`]); the owner revalidates as a live
/// owner of this vault, or the agent's Grant still names `topology_seal`. A
/// decision captures its causal point from the same snapshot, before any
/// effect: the main-log heads and the carrier's standing rows.
pub(super) fn resolve_seal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seal: &TopologySeal,
    ruled: Option<EntityId>,
) -> Result<ResolvedSeal> {
    if let Some(seen) = seal.seen {
        let current = match ruled {
            Some(event) => topology_seal_revision_for_store_in_txn(&vault.store, txn, &event)?,
            None => [0; 32],
        };
        if seen != current {
            return Err(Error::Sync(SyncError::IdentityTopologyRejected(
                IdentityTopologyRejection::SealRevisionStale {
                    event: ruled,
                    current,
                },
            )));
        }
    }
    let (carrier, key) = crate::identity::machine_signer_in_txn(vault, txn)?;
    let mut heads = BTreeSet::new();
    let basis = match &seal.by {
        TopologySealBy::Engine(cause) => SealBasis::Engine(*cause),
        TopologySealBy::Decision(authority) => {
            // Key possession: this install carries the act with its own key,
            // under a live profile of any role, judged on the fold every
            // reader of the seal judges it on.
            let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
                &vault.store,
                vault.store.privacy_posture,
                txn,
            )?;
            let public = key.verifying_key().to_bytes();
            let carries = owner_act_signer_admits(fold.machine(carrier), &fold.roster, &public);
            match (carries, authority, OWNER_DECISION_WITHOUT_CARRIER) {
                (true, ..) => {}
                // No carrier for the owner's decision: today's engine seal,
                // under its own cause, by the policy hook.
                (false, ActAuthority::Owner(..), Some(cause)) => {
                    return Ok(ResolvedSeal {
                        carrier,
                        key,
                        basis: SealBasis::Engine(cause),
                        heads,
                    });
                }
                (false, ..) => return Err(seal_refused(NO_CARRIER)),
            }
            heads = crate::authority::act_heads(&fold, carrier);
            if heads.len() > crate::authority::MAX_PARENTS {
                return Err(seal_refused(HEADS_BOUND));
            }
            match authority {
                // Authority: the owner's proof, revalidated here.
                ActAuthority::Owner(owner, surface) => SealBasis::Decision {
                    owner: owner.revalidate_in_txn(vault, txn)?,
                    by: ActBy::Owner,
                    surface: *surface,
                    answer: seal.answer,
                },
                // Authority: the agent's Grant names the act, checked again.
                ActAuthority::Agent(granted) => {
                    if seal.answer.is_some() {
                        return Err(seal_refused(AGENT_ANSWER));
                    }
                    let owner =
                        vault.granted_act_owner_in_txn(txn, granted, OwnerActKind::TopologySeal)?;
                    SealBasis::Decision {
                        owner,
                        by: ActBy::Agent {
                            agent: granted.agent(),
                            grant: granted.grant(),
                        },
                        surface: ActSurface::ThisInstall,
                        answer: None,
                    }
                }
            }
        }
    };
    Ok(ResolvedSeal {
        carrier,
        key,
        basis,
        heads,
    })
}

/// How one decision seal stands on this replica, this one included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealStanding {
    /// It counts: an engine seal under today's rule, or a decision seal whose
    /// carrier, owner and Grant stand.
    Admitted,
    /// [`SEAL_NO_STANDING`], still pending: an authority-log head the seal
    /// signed has no fold state here, history this replica does not hold yet
    /// (FIX 4649), never judged on the fold as it stands now.
    Pending,
    /// [`SEAL_NO_STANDING`]: at the seal's signed heads its carrier was
    /// removed or no live profile named its key, or its owner's bindings were
    /// revoked; a removal of the carrier since did not see it; or the agent's
    /// Grant row is revoked or names no `topology_seal`.
    Refused,
}

impl SealStanding {
    /// The typed outcome's text, `None` when the seal counts.
    #[must_use]
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Admitted => None,
            Self::Pending | Self::Refused => Some(SEAL_NO_STANDING),
        }
    }
}

/// A decision seal's standing (mesh PR2-topology): `causal`, its carrier
/// under the one carrier rule (any role, no chain removed, never a roster
/// key) and its owner live, both at its signed heads, with every later
/// removal of the carrier having seen it (FIX 4649); and an agent's Grant
/// naming the act at `at`, the decided event's time, on the Grant row this
/// replica holds now (FIX 4649's Grant half is Phase 2). A replica without
/// the Grant row trusts the carrier.
pub(super) fn decision_standing_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    causal: ExternalActStanding,
    act: &OwnerAct,
    at: u64,
) -> Result<SealStanding> {
    match causal {
        ExternalActStanding::Pending => return Ok(SealStanding::Pending),
        ExternalActStanding::Refused => return Ok(SealStanding::Refused),
        ExternalActStanding::Stands => {}
    }
    if let ActBy::Agent { agent, grant } = act.by
        && grant_standing_in_txn(store, txn, grant, agent, act.act, at)? == GrantStanding::Refused
    {
        return Ok(SealStanding::Refused);
    }
    Ok(SealStanding::Admitted)
}

/// One deciding row's head hash: a fixed domain, the row id and its
/// canonical immutable decision bytes.
fn head_hash(id: &EntityId, decision: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TOPOLOGY_SEAL_HEAD_CONTEXT);
    hasher.update(id.as_bytes());
    hasher.update(decision);
    *hasher.finalize().as_bytes()
}

/// The revision of decided-on event `event` (mesh PR2-topology `seen`):
/// BLAKE3 over [`TOPOLOGY_SEAL_REVISION_CONTEXT`] and the sorted, distinct
/// head hashes of the live deciding rows naming it, zero when none does (a
/// fresh event, or one this replica does not hold). The rows: its admitted
/// matching dispositions, concurrent positives, refusals and conflicts alike
/// (a disposition's head covers its verified signed payload), and the
/// effective, unrejected undo, ruling and cancellation rows naming it (each
/// head covers its canonical core). Unsigned author sidecars, wrong-core,
/// untrusted and pending facts never count, nor does `SEALED_HERE`, a local
/// counter, attribution or a mutable flag. Built on the raw type-76 scan.
pub(crate) fn topology_seal_revision_for_store_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
) -> Result<[u8; 32]> {
    let Some(core) =
        super::store_entity_helpers::identity_topology_event_for_store_in_txn(store, txn, event)?
    else {
        return Ok([0; 32]);
    };
    if matches!(
        core.action,
        StoredIdentityOpAction::AdmissionDisposition(_)
            | StoredIdentityOpAction::AuthorAttribution { .. }
            | StoredIdentityOpAction::AuthorRedaction { .. }
    ) {
        return Err(Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
            "a topology seal revision names a decision event, never a sidecar",
        )));
    }
    let digest = core_digest(&core)?;
    let effective =
        super::ledger_fold::fold_effective_identity_topology_events_for_store_in_txn(store, txn)?;
    let rejected: BTreeSet<EntityId> = fold_identity_topology_log(&effective)
        .rejections
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    let referring: BTreeSet<EntityId> = effective
        .iter()
        .filter(|row| !rejected.contains(&row.event_id))
        .filter(|row| match &row.action {
            IdentityTopologyAction::Undo { target } => target == event,
            IdentityTopologyAction::ResolveProposal { proposal, .. }
            | IdentityTopologyAction::CancelProposal { proposal } => proposal == event,
            IdentityTopologyAction::Apply(_) | IdentityTopologyAction::Disposition => false,
        })
        .map(|row| row.event_id)
        .collect();
    let mut trust = SealTrust::default();
    let mut heads = BTreeSet::new();
    for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        store,
        txn,
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        None,
    )? {
        let id = id?;
        let row =
            super::store_entity_helpers::identity_topology_event_for_store_in_txn(store, txn, &id)?
                .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        if referring.contains(&id) {
            heads.insert(head_hash(&id, &core_digest(&row)?));
            continue;
        }
        let StoredIdentityOpAction::AdmissionDisposition(fact) = row.action else {
            continue;
        };
        if fact.target != *event || fact.core_digest != digest {
            continue;
        }
        fact.verify()
            .map_err(|_| Error::CorruptedIndex("identity topology admission signature"))?;
        if !trust.attributed(store, txn, &id, &fact, &core)? {
            continue;
        }
        heads.insert(head_hash(&id, &fact.signed_payload()?));
    }
    Ok(crate::authority::act_revision(
        TOPOLOGY_SEAL_REVISION_CONTEXT,
        heads,
    ))
}

/// The decision-seal standing inputs, as one digest the reconcile pass keeps
/// beside the trusted keys (mesh PR2-topology): each machine's carrier keys
/// under the one carrier rule, its removal and its chains' head rows (a new
/// revision, and the acts it saw), the owners' human binding statuses, each
/// decision seal's token and whether every head it signed is held (FIX
/// 4649), and the row state of every Grant a decision seal names. A change in
/// any of them, a Grant delete included (FIX 4652), runs the standing pass
/// again.
pub(super) fn decision_standing_digest_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TOPOLOGY_SEAL_STANDING_CONTEXT);
    for (machine, folded) in &fold.machines {
        let removed = folded.chains().any(|(_, chain)| chain.removed);
        let keys: BTreeSet<[u8; 32]> = folded
            .chains()
            .filter(|(_, chain)| chain.is_live())
            .map(|(_, chain)| chain.profile.machine_key)
            .filter(|key| !fold.roster.contains_key(&AuthorityKey::Ed25519(*key)))
            .collect();
        hasher.update(machine.as_bytes());
        hasher.update(&[u8::from(removed)]);
        hasher.update(&(keys.len() as u64).to_be_bytes());
        for key in &keys {
            hasher.update(key);
        }
        let rows: Vec<AuthorityEntryHash> = folded.chains().map(|(_, chain)| chain.entry).collect();
        hasher.update(&(rows.len() as u64).to_be_bytes());
        for row in &rows {
            hasher.update(row);
        }
    }
    let bindings: BTreeSet<(EntityId, bool)> = fold
        .actor_bindings
        .values()
        .filter(|binding| binding.actor_class == "human")
        .map(|binding| {
            (
                binding.actor_ref,
                binding.status == crate::authority::ActorBindingStatus::Active,
            )
        })
        .collect();
    hasher.update(&(bindings.len() as u64).to_be_bytes());
    for (owner, live) in &bindings {
        hasher.update(owner.as_bytes());
        hasher.update(&[u8::from(*live)]);
    }
    let mut grants = BTreeSet::new();
    let mut seals = BTreeSet::new();
    for fact in super::seal_standing::decision_seals_in_txn(store, txn)? {
        if let SealAuthority::Decision(OwnerAct {
            by: ActBy::Agent { grant, .. },
            ..
        }) = fact.authority
        {
            grants.insert(grant);
        }
        let held = fact
            .authority_heads
            .iter()
            .all(|head| fold.valid_entries.contains(head));
        seals.insert((fact.act_token()?, held));
    }
    hasher.update(&(seals.len() as u64).to_be_bytes());
    for (token, held) in &seals {
        hasher.update(token);
        hasher.update(&[u8::from(*held)]);
    }
    hasher.update(&(grants.len() as u64).to_be_bytes());
    for grant in &grants {
        hasher.update(grant.as_bytes());
        match crate::vault::live_entity_row_in_txn(store, txn, grant)? {
            crate::vault::LiveEntityRow::Live { entity_type, body } => {
                hasher.update(&[1, entity_type]);
                hasher.update(blake3::hash(&body).as_bytes());
            }
            crate::vault::LiveEntityRow::DeletedShell => {
                hasher.update(&[2]);
            }
            crate::vault::LiveEntityRow::Absent => {
                let deleted =
                    crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, grant)?
                        .deleted;
                hasher.update(&[if deleted { 3 } else { 0 }]);
            }
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

impl Vault {
    /// The revision of decided-on event `event` a surface shows the owner and
    /// passes back as a topology door's `seen`
    /// ([`TopologySeal::with_seen`]): zero for an event nobody decided on.
    pub fn identity_topology_seal_revision(&self, event: &EntityId) -> Result<[u8; 32]> {
        let txn = self.store.env.read_txn()?;
        topology_seal_revision_for_store_in_txn(&self.store, &txn, event)
    }

    /// How the seal fact `fact` stands here: `None` when `fact` is no
    /// admission seal. An engine seal counts under today's rule; a decision
    /// seal names [`SEAL_NO_STANDING`] when it does not count.
    pub fn identity_topology_seal_standing(&self, fact: &EntityId) -> Result<Option<SealStanding>> {
        let txn = self.store.env.read_txn()?;
        let Some(row) = self.identity_topology_event_in_txn(&txn, fact)? else {
            return Ok(None);
        };
        let StoredIdentityOpAction::AdmissionDisposition(seal) = row.action else {
            return Ok(None);
        };
        let Some(core) = self.identity_topology_event_in_txn(&txn, &seal.target)? else {
            return Ok(Some(SealStanding::Pending));
        };
        SealTrust::default()
            .standing(&self.store, &txn, fact, &seal, &core)
            .map(Some)
    }
}
