//! The L02 side of the owner-act record (mesh contract §3): the one rule
//! every owner act's carrier is judged by, the owner's liveness at an act's
//! causal point (§4; a topology seal outside the log is read at its signed
//! heads, [`super::act_standing`]), and what an act's receipt says of the key
//! work that follows it (contract §5). The record itself, its codec
//! and its shape check are `oneiron_authority::authority::OwnerAct`.

use std::collections::BTreeMap;

use crate::entity_id::EntityId;

use super::principal_standing::{
    grant_pact_standing_lapsed_in_txn, grant_row_pact_standing_lapsed_in_txn,
};
use super::*;

/// Whether `key` may carry an owner act for `machine`, judged on `machine`'s
/// folded chains and the authority `roster` of the same fold. The one signer
/// rule: the writer, the full fold, the resumed fold, the race, stale renewal
/// and every replica ask it, before and after the owner anchor, so every
/// replica admits the same carriers, and the store doors' structure
/// (`vouches_for`, `is_stranger`, the import order's `wanted`) takes the
/// install key any profile names, in any role, as this does.
///
/// The owner's ruling (10-19 00:5x): "Linking together machines is like a
/// computronium mesh. it doesn't matter where you said yes, if you said so.
/// i can do action X from my phone that impacts an engine on my laptop." The
/// gate is the owner's authenticated say-so at the writer; the signature
/// only says which of the vault's machines carried it. So this admits a
/// live physical machine profile of this vault whose install key is `key`,
/// in any role (yours, work or school, rented, a hosted node, an execution
/// node), as the sync wire accepts a proven peer machine
/// ([`AuthorityFold::machine_proof_key`]) and not only a "yours" one. Live:
/// not removed in any chain, not conflicted or poisoned, not stale, held or
/// unsettled where the view says so. A role change between linked roles
/// never revokes it; only removal does. It never admits a key the authority
/// roster names (the host root, an owner or roster device key: FIX 2222, the
/// unattended host root acts as nobody), nor an engine MACHINE writer, which
/// no profile names.
pub(crate) fn owner_act_signer_admits(
    machine: Option<&FoldedMachine>,
    roster: &BTreeMap<AuthorityKey, FoldedDevice>,
    key: &[u8; 32],
) -> bool {
    !roster.contains_key(&AuthorityKey::Ed25519(*key))
        && machine.is_some_and(|folded| {
            folded.chains().all(|(_, chain)| !chain.removed)
                && folded
                    .chains()
                    .any(|(_, chain)| chain.is_live() && chain.profile.machine_key == *key)
        })
}

/// Whether `owner` is a live owner at an act's causal point, as the fold
/// state `state` of its parents holds it (mesh contract §4): every replica
/// that holds the owner's removal before the act refuses it. The vault's
/// owner set itself lives in its membership rows, which no authority-log row
/// carries, so the fold reads the one owner fact the log does carry: the
/// owner's human actor bindings. An owner every binding of whom the log
/// revoked is removed; an owner the log binds nowhere is trusted on the
/// carrier's word, as a replica without an agent's Grant row trusts it, since
/// the writer revalidated him in its own transaction (CALLS "mesh1b owner
/// liveness in the fold", [`OWNER_UNBOUND_TRUSTS_CARRIER`]).
pub(super) fn owner_live_at(state: &FoldState, owner: EntityId) -> bool {
    let mut bound = false;
    for (key, binding) in &state.actor_bindings {
        if binding.actor_ref != owner || binding.actor_class != "human" {
            continue;
        }
        if state.live_actor_binding(key).is_some() {
            return true;
        }
        bound = true;
    }
    !bound && OWNER_UNBOUND_TRUSTS_CARRIER
}

/// The policy hook behind [`owner_live_at`]: an owner no authority-log row
/// binds is taken as live at the act's causal point (CALLS "mesh1b owner
/// liveness in the fold", open).
const OWNER_UNBOUND_TRUSTS_CARRIER: bool = true;

/// What an owner act's commit did about the key work that follows it (mesh
/// contract §5, the honest receipt). Only a holder opens, mints or rewraps a
/// key: a carrier that holds none records the decision, and its receipt says
/// so, never "done".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyWork {
    /// The decision is recorded and needs no key work: the world reads
    /// everywhere, so no key counts for it.
    Recorded,
    /// The decision is recorded, and a holder still has to mint or rewrap
    /// the key: this install may not read the world, or holds no wrap of
    /// its current key.
    AwaitingHolder,
    /// The decision is recorded and this install did the key work in the
    /// same commit: it minted the world's first key, wrapped the current key
    /// to the readers that lacked it, or found every reader holding it.
    Enacted,
}

/// Who decided an act, in process only and never on the wire (mesh contract
/// §1). A door takes one and records it as an [`OwnerAct`]'s `by`; the
/// supervisor's request MAC and the proof itself never enter a record.
#[derive(Debug, Clone)]
pub enum ActAuthority {
    /// The owner's own proof (`owner()`, `owner_authorship()`, a host action
    /// or a local session) and the surface it reached this install from,
    /// which is audit only. The door revalidates the owner in its own
    /// transaction.
    Owner(crate::consent::AuthenticatedOwner, ActSurface),
    /// An agent whose live Grant names the act. An agent is never relabelled
    /// as the owner.
    Agent(GrantedAct),
}

/// An agent's act its live Grant names: the agent, the Grant and the act kind
/// the Grant was checked for. Only [`Vault::granted_act`] builds one, and a
/// door checks the Grant again in its own transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedAct {
    agent: EntityId,
    grant: EntityId,
    act: OwnerActKind,
}

impl GrantedAct {
    /// The deciding agent.
    #[must_use]
    pub const fn agent(&self) -> EntityId {
        self.agent
    }

    /// The Grant that names the act.
    #[must_use]
    pub const fn grant(&self) -> EntityId {
        self.grant
    }

    /// The act kind the Grant was checked for.
    #[must_use]
    pub const fn act(&self) -> OwnerActKind {
        self.act
    }
}

/// Policy hook (CALLS "mesh PR2a agent act Grant line", open): the act kinds an
/// agent's Grant may name in this build. Topology seals, and a world's
/// settings for a tighten only (FIX 4480, CALLS "FIX 4480 agent tighten Grant
/// line"); each other door takes agents when its lane writes the Grant line
/// that names its act (contract §4).
const AGENT_GRANTABLE_ACTS: [OwnerActKind; 2] =
    [OwnerActKind::TopologySeal, OwnerActKind::WorldPrivacy];

/// The verb a Grant names a world-settings act by. A Grant can only ever name
/// a tighten: a widen is never an agent's act (FIX 4480), so no verb names it.
pub(crate) const WORLD_PRIVACY_TIGHTEN_VERB: &str = "world_privacy_tighten";

/// The verb an agent's Grant lists to name `act`: the act's wire tag, but for
/// a world's settings, whose one grantable direction is the tighten.
fn grant_verb(act: OwnerActKind) -> &'static str {
    match act {
        OwnerActKind::WorldPrivacy => WORLD_PRIVACY_TIGHTEN_VERB,
        other => other.as_str(),
    }
}

/// Policy hook (same CALLS row): whether FederationGrant `grant` names `act`
/// for `agent` at `at`, as a named action grant does (`policy.change` is the
/// precedent): its member is the agent, it confers at `at`, and its authority
/// scope names the act's verb ([`grant_verb`]) among an explicit verb set. A
/// grant whose verbs are "all" names no act: a broad grant about other verbs
/// never authorizes this one.
fn grant_names_act(
    grant: &crate::federation::FederationGrant,
    agent: EntityId,
    act: OwnerActKind,
    at: u64,
) -> bool {
    AGENT_GRANTABLE_ACTS.contains(&act)
        && grant.member_ref == agent
        && grant.confers_at(at)
        && matches!(
            &grant.authority_scope.verbs,
            crate::federation::ScopeAxis::Some(verbs) if verbs.contains(grant_verb(act))
        )
}

/// Policy hook (CALLS "FIX 4480 agent tighten Grant line", accepted with the
/// Engine's amendment of 10-19 05:0x): whether `grant` names `world` as the
/// target of its act. Its worlds axis covers the world the way every Grant
/// axis covers its targets ([`crate::federation::ScopeAxis::contains`]): an
/// explicit name and the grammar's all-worlds form both count, since a
/// tighten only lowers exposure. The verbs axis stays explicit
/// ([`grant_names_act`]): a grant over every verb still names no act.
fn grant_names_world(grant: &crate::federation::FederationGrant, world: EntityId) -> bool {
    grant
        .authority_scope
        .worlds
        .contains(&crate::federation::ScopeId(world))
}

/// What this replica holds of an agent act's Grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantStanding {
    /// The Grant row is live here and names the act for the agent.
    Names,
    /// No Grant row and no deletion of it is held here (grant travel may keep
    /// it off): the carrier is trusted, as for the owner's say-so (CALLS "mesh
    /// agent grant on replicas").
    Absent,
    /// The Grant row is deleted, revoked, another kind, or names no such act:
    /// a known revocation refuses.
    Refused,
}

/// How the Grant `grant` stands here for `agent`'s act `act` at `at`.
pub(crate) fn grant_standing_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    grant: EntityId,
    agent: EntityId,
    act: OwnerActKind,
    at: u64,
) -> crate::error::Result<GrantStanding> {
    Ok(
        match crate::vault::live_entity_row_in_txn(store, txn, &grant)? {
            crate::vault::LiveEntityRow::Live {
                entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                body,
            } => match crate::federation::decode_federation_grant_body(&body) {
                Ok(decoded) if grant_names_act(&decoded, agent, act, at) => GrantStanding::Names,
                _ => GrantStanding::Refused,
            },
            crate::vault::LiveEntityRow::Live { .. }
            | crate::vault::LiveEntityRow::DeletedShell => GrantStanding::Refused,
            crate::vault::LiveEntityRow::Absent => {
                if crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, &grant)?
                    .deleted
                {
                    GrantStanding::Refused
                } else {
                    GrantStanding::Absent
                }
            }
        },
    )
}

/// Where an agent act's Grant takes the shared vault's pact test (CALLS
/// `FIX 7548 replica pact check`, accepted by the Engine 10-21 22:4x).
#[derive(Debug, Clone, Copy)]
enum ReplicaPactCheck {
    /// At the LIVE edges only: [`crate::Vault::granted_act`] and every
    /// writer's recheck ([`crate::Vault::granted_act_owner_in_txn`]). The
    /// replica's judge of a carried act, [`grant_standing_in_txn`], reads no
    /// pact membership, so fold, replay and seal trust keep their meaning
    /// (fold schema 11), and a Grant row this replica lacks still trusts the
    /// carrier.
    LiveAdmissionOnly,
}

const GRANT_SWEEP_REPLICA_PACT_CHECK: ReplicaPactCheck = ReplicaPactCheck::LiveAdmissionOnly;

/// How a Grant reader that omitted a lapsed Grant says so (CALLS `FIX 7548
/// omission reason`, accepted by the Engine 10-21 22:4x).
#[derive(Debug, Clone, Copy)]
enum OmissionReason {
    /// The typed lapse rides the reader's existing fallback, a proposal or
    /// an ask and never a refusal, as [`PACT_STANDING_LAPSED_CODE`] on what
    /// that fallback opens. A Grant that is merely missing says nothing, and
    /// any later standing Grant wins over the lapse.
    CarryTypedLapseThroughExistingFallback,
}

const GRANT_SWEEP_OMISSION_REASON: OmissionReason =
    OmissionReason::CarryTypedLapseThroughExistingFallback;

/// The code a proposal carries when the Grant that would have applied it
/// was omitted on its lapsed pact membership alone (FIX 7548).
const PACT_STANDING_LAPSED_CODE: &str = "pact_standing_lapsed";

/// What a proposal opened because no Grant stood records of why (FIX 7548,
/// [`GRANT_SWEEP_OMISSION_REASON`]): [`PACT_STANDING_LAPSED_CODE`] when the
/// selection omitted a Grant on its pact alone, else nothing.
pub(crate) fn grant_omission(no_standing: NoStanding) -> Option<&'static str> {
    match (GRANT_SWEEP_OMISSION_REASON, no_standing) {
        (
            OmissionReason::CarryTypedLapseThroughExistingFallback,
            NoStanding::PactStandingLapsed,
        ) => Some(PACT_STANDING_LAPSED_CODE),
        (_, NoStanding::NotStanding) => None,
    }
}

/// Why a Grant selection found none: the lapse when a Grant that met the
/// selection's rule fell on its pact membership alone.
const fn no_standing(lapsed: bool) -> NoStanding {
    if lapsed {
        NoStanding::PactStandingLapsed
    } else {
        NoStanding::NotStanding
    }
}

/// The agent's Grant does not name the act here: absent, revoked, another
/// agent's, expired, or naming other verbs. Authority; nothing was written.
const GRANT_NAMES_NO_ACT: &str = "no live Grant of this agent names this act";
/// The vault has no live owner whose will an agent's act could carry.
const NO_LIVE_OWNER: &str = "this vault has no live owner whose Grant an agent's act could carry";

impl crate::Vault {
    /// The agent `agent`'s act `act`, when its live Grant `grant` names it now
    /// (mesh contract §1, `ActAuthority::Agent`) and, on a shared vault, its
    /// pact membership still stands (FIX 7548). The door that takes it
    /// checks the Grant again in its own transaction.
    pub fn granted_act(
        &self,
        agent: EntityId,
        grant: EntityId,
        act: OwnerActKind,
    ) -> crate::error::Result<GrantedAct> {
        let txn = self.store.env.read_txn()?;
        let now = self.instant_in_txn(&txn)?.secs();
        self.live_grant_names_act_in_txn(&txn, grant, agent, act, now)?;
        Ok(GrantedAct { agent, grant, act })
    }

    /// The writer's check of `granted` for `act` in its own transaction: the
    /// Grant still names the act for the agent, now, and on a shared vault
    /// keeps its pact membership (FIX 7548). Returns the vault owner whose
    /// will the agent's act carries (the existing resolver: the embedded
    /// PERSON, or the first live Owner-role member of a shared vault).
    pub(crate) fn granted_act_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        granted: &GrantedAct,
        act: OwnerActKind,
    ) -> crate::error::Result<EntityId> {
        let now = self.instant_in_txn(txn)?.secs();
        if granted.act != act {
            return Err(authority_refused(GRANT_NAMES_NO_ACT));
        }
        self.live_grant_names_act_in_txn(txn, granted.grant, granted.agent, act, now)?;
        crate::policy_model::owners_in_txn(self, txn)?
            .first()
            .copied()
            .ok_or_else(|| authority_refused(NO_LIVE_OWNER))
    }

    /// A LIVE edge's check of the Grant `grant` for `agent`'s act `act` at
    /// `at` ([`GRANT_SWEEP_REPLICA_PACT_CHECK`]): the replica's rule
    /// ([`grant_standing_in_txn`]) names the act, and on a shared vault the
    /// Grant's own pact membership still stands (FIX 7548). The lapse alone
    /// refuses with [`PACT_STANDING_LAPSED`]; a pact check that fails to read
    /// is no lapse.
    fn live_grant_names_act_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant: EntityId,
        agent: EntityId,
        act: OwnerActKind,
        at: u64,
    ) -> crate::error::Result<()> {
        if grant_standing_in_txn(&self.store, txn, grant, agent, act, at)? != GrantStanding::Names {
            return Err(authority_refused(GRANT_NAMES_NO_ACT));
        }
        match GRANT_SWEEP_REPLICA_PACT_CHECK {
            ReplicaPactCheck::LiveAdmissionOnly => {
                if grant_row_pact_standing_lapsed_in_txn(self, txn, grant) {
                    return Err(authority_refused(PACT_STANDING_LAPSED));
                }
            }
        }
        Ok(())
    }
}

impl crate::Vault {
    /// The live Grant of `agent` that names a tighten of `world`'s settings
    /// now (FIX 4480), when one does: a FEDERATION_GRANT row whose member is
    /// the agent, that confers now, lists [`WORLD_PRIVACY_TIGHTEN_VERB`] among
    /// its verbs, and whose worlds axis covers `world` (by name, or as all
    /// worlds). The first such row, in id order, whose pact membership, on
    /// a shared vault, still stands (FIX 7548): a lapsed one is passed over
    /// for a later one, and with none, the lapse.
    pub(crate) fn agent_world_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
        world: EntityId,
    ) -> crate::error::Result<std::result::Result<EntityId, NoStanding>> {
        let now = self.instant_in_txn(txn)?.secs();
        let mut lapsed = false;
        for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            txn,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            None,
        )? {
            let id = id?;
            if !self.grant_names_world_act_in_txn(txn, id, agent, world, now)? {
                continue;
            }
            if grant_row_pact_standing_lapsed_in_txn(self, txn, id) {
                lapsed = true;
                continue;
            }
            return Ok(Ok(id));
        }
        Ok(Err(no_standing(lapsed)))
    }

    /// The writer's check of `granted` for a world's settings in its own
    /// transaction: the Grant still names a tighten of `world` for the agent,
    /// now. Returns the vault owner whose will the agent's act carries, as
    /// [`Self::granted_act_owner_in_txn`] does.
    pub(crate) fn granted_world_act_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        granted: &GrantedAct,
        world: EntityId,
    ) -> crate::error::Result<EntityId> {
        let owner = self.granted_act_owner_in_txn(txn, granted, OwnerActKind::WorldPrivacy)?;
        let now = self.instant_in_txn(txn)?.secs();
        if !self.grant_names_world_act_in_txn(txn, granted.grant, granted.agent, world, now)? {
            return Err(authority_refused(GRANT_NAMES_NO_ACT));
        }
        Ok(owner)
    }

    /// Whether the live row `grant` names a tighten of `world` for `agent` at
    /// `at`.
    fn grant_names_world_act_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant: EntityId,
        agent: EntityId,
        world: EntityId,
        at: u64,
    ) -> crate::error::Result<bool> {
        Ok(
            match crate::vault::live_entity_row_in_txn(&self.store, txn, &grant)? {
                crate::vault::LiveEntityRow::Live {
                    entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                    body,
                } => crate::federation::decode_federation_grant_body(&body).is_ok_and(|decoded| {
                    grant_names_act(&decoded, agent, OwnerActKind::WorldPrivacy, at)
                        && grant_names_world(&decoded, world)
                }),
                _ => false,
            },
        )
    }
}

/// The verb a Grant of the Coach lists to name an owner's weave-digest
/// settings, his digest's rhythm and section order (FIX 5495).
pub(crate) const WEAVE_DIGEST_SETTINGS_GRANT_VERB: &str = "weave_digest_settings";

impl crate::Vault {
    /// The live Grant of the Coach `coach` that names `owner`'s weave-digest
    /// settings now (FIX 5495), when one does: a FEDERATION_GRANT row whose
    /// member is the Coach, that confers now, lists
    /// [`WEAVE_DIGEST_SETTINGS_GRANT_VERB`] among an explicit verb set (a
    /// grant over every verb names nothing), and is this owner's: he
    /// delegated it, or he is the vault's one live owner (CALLS: FIX 5495
    /// grant owner). The first such row, in id order, whose pact membership,
    /// on a shared vault, still stands (FIX 7548): a lapsed one is passed
    /// over for a later one, and with none, the lapse. The Coach's writer
    /// reads it inside the transaction that applies.
    pub(crate) fn coach_weave_digest_settings_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        coach: EntityId,
        owner: EntityId,
    ) -> crate::error::Result<std::result::Result<EntityId, NoStanding>> {
        let now = self.instant_in_txn(txn)?.secs();
        let owners = crate::policy_model::owners_in_txn(self, txn)?;
        let sole_owner = owners.len() == 1 && owners.first() == Some(&owner);
        let mut lapsed = false;
        for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            txn,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            None,
        )? {
            let id = id?;
            let crate::vault::LiveEntityRow::Live {
                entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                body,
            } = crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?
            else {
                continue;
            };
            let Ok(grant) = crate::federation::decode_federation_grant_body(&body) else {
                continue;
            };
            if grant.member_ref == coach
                && grant.confers_at(now)
                && matches!(
                    &grant.authority_scope.verbs,
                    crate::federation::ScopeAxis::Some(verbs)
                        if verbs.contains(WEAVE_DIGEST_SETTINGS_GRANT_VERB)
                )
                && (grant.delegated_by == Some(owner) || sole_owner)
            {
                if grant_pact_standing_lapsed_in_txn(self, txn, id, grant.scope, grant.member_ref) {
                    lapsed = true;
                    continue;
                }
                return Ok(Ok(id));
            }
        }
        Ok(Err(no_standing(lapsed)))
    }
}

/// A typed authority refusal naming its rule (mesh PR2-reasons).
pub(crate) fn authority_refused(reason: &'static str) -> crate::error::Error {
    crate::error::Error::Record(crate::error::RecordError::AuthorityRefused(reason))
}

/// A door check's refusal as its branch's typed reason `reason`; a storage
/// fault stays itself, so a failing disk never reads as a refusal.
pub(crate) fn authority_refusal_as(
    reason: &'static str,
) -> impl Fn(crate::error::Error) -> crate::error::Error {
    use crate::error::ErrorKind;
    move |error| match error.kind() {
        ErrorKind::Storage | ErrorKind::Io | ErrorKind::MapFull | ErrorKind::CorruptedIndex => {
            error
        }
        _ => authority_refused(reason),
    }
}
