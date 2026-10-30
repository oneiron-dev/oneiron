//! Authenticated identity carried by a scoped read.
mod weave_admin;
use crate::EntityId;
use crate::federation::{Scope, ScopeAxis, ScopeId};

/// `worlds` as a world-only Scope: that axis kept, every other axis top.
/// The world checks meet and compare these projections alone (OF-453 B06);
/// a row door still judges the whole Scope with `admits`.
pub(crate) fn world_only(worlds: ScopeAxis<ScopeId>) -> Scope {
    Scope {
        worlds,
        ..Scope::top()
    }
}

/// Where one ordinary record sits, as a world-only Scope: a claim's world,
/// else base reality, which also holds every record that is not a claim.
pub(crate) fn record_world_scope(world: Option<EntityId>) -> Scope {
    let world = ScopeId(world.unwrap_or_else(crate::claim::base_world_id));
    world_only(std::iter::once(world).collect())
}

/// Actor key bound to a scoped read lane over the `core:read` surface.
///
/// The fields are private and construction rejects blank actor refs, so a
/// [`ScopedRead`](crate::claim::ScopedRead) cannot be built as an unkeyed bulk read handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedReadActorKey {
    actor_ref: String,
    actor_class: Option<String>,
    pub(super) principal_ref: Option<EntityId>,
    pub(super) enforce_access_grants: bool,
    /// With `enforce_access_grants`: a row naming no relationship and no
    /// private scope stays readable (see [`Self::require_relationship_grants`]).
    pub(super) unscoped_rows_open: bool,
    pub(super) proof: Option<crate::authority::VerifiedSlip>,
    /// The proof's Scope as every read door checks it; see
    /// [`Self::authority_scope`].
    authority: Option<crate::federation::Scope>,
    /// A host-bound channel on a channel-aware read door, never a grant.
    pub(super) channel: Option<String>,
    /// Set only on the vault owner's own key; see [`Self::vault_owner`].
    owner: Option<EntityId>,
    /// Set only on a narrower credential of the owner's; see
    /// [`Self::exempt_while_owner`].
    pub(super) owner_exemption: Option<EntityId>,
    /// The room turn this key reads inside, when a host bound one.
    pub(super) room_turn: Option<Box<RoomTurnCeiling>>,
    /// The room whose signed facets a named-room read outside a turn reads
    /// inside (FIX 643); see [`Self::within_room_facets`].
    pub(super) room_facets: Option<EntityId>,
    /// The worlds this read asked for (ARCH-0022). Every row it serves,
    /// ranked or reached through the graph, lies in one of them.
    pub(super) worlds: Option<crate::pipeline::WorldAuthoritySet>,
    /// Where the read's rows go: off this device or not, and each machine a
    /// connection proved beside that (mesh PR2b); see [`Self::at`] and
    /// [`Self::for_destination`].
    destination: crate::settings::ReadDestination,
    /// Set only on a host action's key (FIX 2222); see
    /// [`Self::guarded_by_host_action`].
    host_action: Option<crate::authority::HostActionGuard>,
    /// Set only on an owner key held to a request's own owner proof; see
    /// [`Self::guarded_by_owner_proof`].
    owner_proof: Option<Box<crate::consent::AuthenticatedOwner>>,
    /// Set only on a due Owner schedule's owner key (FIX 1259); see
    /// [`Self::vault_owner_by_census`].
    owner_by_census: bool,
    /// A saved lane's records caveat, carried with no proof (OF-506); see
    /// [`Self::within_records`].
    pub(super) record_bound: Option<std::collections::BTreeSet<String>>,
}

/// Where a read's caller sits relative to this device (DEC-0005). Only the
/// host decides it, from the connection the caller reached it on; nothing the
/// caller sends sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerLocality {
    /// On this device: the embedded host, or a caller on its local socket or
    /// loopback.
    OnDevice,
    /// Anywhere else.
    OffDevice,
}

/// A room turn's read ceiling (ARCH-0067 §8). It travels with the key, so
/// every lane built from it reads inside the room's Scope and roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoomTurnCeiling {
    pub(crate) room: EntityId,
    /// The member reading through this ceiling; every other member is a peer.
    pub(crate) caller: EntityId,
    /// The turn's Scope terms, shared by the turn and every lane built from
    /// it; see [`TurnTerms`].
    pub(crate) terms: TurnTerms,
    /// The room's audience, sorted and unique: its members and the entry
    /// refs of its live speakers (FIX 1388/1389). Each row must pass the
    /// all-of-audience rule for every one of them (ARCH-0006a). It projects
    /// who hears the room and never proves membership: standing, worlds,
    /// the clearance meet's members and peer reads are the members' alone.
    pub(crate) roster: Vec<EntityId>,
    /// Every other member's read key: a row the room reads must be one each
    /// of them may read too, private principal rows and NOTEs included.
    pub(crate) peers: Vec<ScopedReadActorKey>,
    /// The thread this ceiling reads, when it is a thread's (OF-529): each
    /// refresh re-proves the caller's standing on that thread, which a
    /// thread's own Ready receipt gives without a seat. `None` is the room's.
    pub(crate) branch: Option<EntityId>,
    /// Whether this is a member's personal read of the room or thread, never
    /// a held turn's (FIX 5545). A personal read only shows the caller what
    /// it reads itself, so its roster and peers stand in each private thread
    /// under the CURRENT rule while the caller's own read still meets each
    /// turn under CONTENT. A held ceiling, whose words reach the roster,
    /// holds every one of them to CONTENT (FIX 5636).
    pub(crate) personal: bool,
}

/// What `room_scope` gives for a roster, as two terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoomTerms {
    /// The room's world ceiling: every row it reads lies in it, public or
    /// not.
    pub(crate) worlds: crate::federation::Scope,
    /// The facets the room limits its reads to (owner ruling FACET-READ): its
    /// project's slice facet, met with what each later snapshot finds there.
    /// `All` is a room with no facet.
    pub(crate) facets: crate::federation::ScopeAxis<crate::federation::ScopeId>,
    /// The met clearance of the members that bring one (ILDF2), and of an
    /// Owner or Admin reading a private thread off the room (FIX 6497):
    /// `None` while only the owner and the vault's own agents are in the meet.
    pub(crate) clearance: Option<crate::federation::Scope>,
    /// Whether the clearance holds rows to P7. A turn does; a member's own
    /// read of the room outside a turn keeps only the world, audience and
    /// peer gates, and never takes a clearance.
    pub(crate) p7: bool,
}

impl RoomTerms {
    /// The room's Scope: the world ceiling met with the clearance, in the
    /// room's facets. P7 judges no facet, so they only report the limit.
    pub(crate) fn room_scope(&self) -> crate::federation::Scope {
        let mut scope = match &self.clearance {
            Some(clearance) => self.worlds.meet(clearance),
            None => self.worlds.clone(),
        };
        scope.facets = scope.facets.meet(&self.facets);
        scope
    }

    /// `self` met with `now`; a term `now` lacks never widens it.
    fn meet(&self, now: &Self) -> Self {
        Self {
            worlds: self.worlds.meet(&now.worlds),
            facets: self.facets.meet(&now.facets),
            clearance: if self.p7 {
                meet_clearance(self.clearance.as_ref(), now.clearance.as_ref())
            } else {
                None
            },
            p7: self.p7,
        }
    }
}

/// One room turn's terms, shared by its handle and every lane built from
/// it. Each read meets what its own snapshot finds into them, so a turn only
/// narrows: a clearance it lost stays lost across verbs, and only a new turn
/// reads wider again.
#[derive(Debug, Clone)]
pub(crate) struct TurnTerms(std::sync::Arc<std::sync::Mutex<RoomTerms>>);

impl PartialEq for TurnTerms {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for TurnTerms {}

impl TurnTerms {
    pub(crate) fn new(terms: RoomTerms) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(terms)))
    }

    /// The terms as the turn holds them now.
    pub(crate) fn get(&self) -> RoomTerms {
        self.with(RoomTerms::clone)
    }

    /// `read` over the terms as the turn holds them now.
    pub(crate) fn with<R>(&self, read: impl FnOnce(&RoomTerms) -> R) -> R {
        read(
            &self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Meets `now` into the turn and returns what the turn holds after.
    pub(crate) fn meet(&self, now: &RoomTerms) -> RoomTerms {
        let mut held = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let met = held.meet(now);
        if met != *held {
            *held = met.clone();
        }
        met
    }

    /// Meets one snapshot's clearance into the turn, if it holds rows to P7.
    pub(crate) fn meet_clearance(&self, clearance: Option<&crate::federation::Scope>) {
        let Some(clearance) = clearance else {
            return;
        };
        let mut held = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !held.p7 {
            return;
        }
        let met = meet_clearance(held.clearance.as_ref(), Some(clearance));
        if met != held.clearance {
            held.clearance = met;
        }
    }

    /// Meets the facets one snapshot finds on the room into the turn and
    /// returns what the turn holds after: a project re-signed to another
    /// facet mid-turn leaves the turn neither.
    pub(crate) fn meet_facets(
        &self,
        facets: &crate::federation::ScopeAxis<crate::federation::ScopeId>,
    ) -> crate::federation::ScopeAxis<crate::federation::ScopeId> {
        let mut held = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let met = held.facets.meet(facets);
        if met != held.facets {
            held.facets = met.clone();
        }
        met
    }

    /// Whether the turn holds rows to P7.
    pub(crate) fn p7(&self) -> bool {
        self.with(|terms| terms.p7)
    }
}

impl RoomTurnCeiling {
    /// Whether `record` ([`record_world_scope`]) lies under the room's world
    /// ceiling.
    pub(crate) fn admits_world(&self, record: &Scope) -> bool {
        let ceiling = self
            .terms
            .with(|terms| world_only(terms.worlds.worlds.clone()));
        record.is_narrowing_of(&ceiling)
    }

    /// P7 for one record the room reads: with a clearance in the meet, the
    /// record's own Scope sits under the room's Scope or is positively
    /// public. A record with no stamp is never public.
    pub(crate) fn discloses(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
    ) -> crate::Result<bool> {
        let Some(scope) = self
            .terms
            .with(|terms| terms.clearance.as_ref().map(|_| terms.room_scope()))
        else {
            return Ok(true);
        };
        crate::disclosure::discloses_raw(vault, txn, &scope, id, raw)
    }

    /// This ceiling conjoined with `now`, the room as a later snapshot reads
    /// it: `now`'s terms met into the turn's, both rosters as one audience,
    /// and every peer read either holds. A member who joined binds the read;
    /// one who left still binds a lane built while it belonged. Refreshing a
    /// ceiling can therefore narrow the read and never drop a restriction it
    /// held. The thread it reads, if any, stays this ceiling's, and so does
    /// whether it is personal.
    #[must_use]
    pub(crate) fn narrowed_by(&self, now: &Self) -> Self {
        let mut roster = self.roster.clone();
        roster.extend(&now.roster);
        roster.sort_unstable();
        roster.dedup();
        let mut peers = self.peers.clone();
        for peer in &now.peers {
            if !peers.contains(peer) {
                peers.push(peer.clone());
            }
        }
        self.terms.meet(&now.terms.get());
        Self {
            room: self.room,
            caller: self.caller,
            terms: self.terms.clone(),
            roster,
            peers,
            branch: self.branch,
            personal: self.personal,
        }
    }

    /// Whether every id of `roster`, a member or a live entry ref, already
    /// binds this ceiling.
    pub(crate) fn binds_all(&self, roster: &[EntityId]) -> bool {
        roster
            .iter()
            .all(|member| self.roster.binary_search(member).is_ok())
    }
}

/// Two clearance terms met; `None` is no term, so it never narrows.
pub(crate) fn meet_clearance(
    a: Option<&crate::federation::Scope>,
    b: Option<&crate::federation::Scope>,
) -> Option<crate::federation::Scope> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.meet(b)),
        (one, other) => one.or(other).cloned(),
    }
}

impl ScopedReadActorKey {
    #[must_use]
    pub fn new(actor_ref: impl Into<String>) -> Option<Self> {
        Self::from_parts(actor_ref.into(), None)
    }

    #[must_use]
    pub fn with_actor_class(
        actor_ref: impl Into<String>,
        actor_class: impl Into<String>,
    ) -> Option<Self> {
        Self::from_parts(actor_ref.into(), Some(actor_class.into()))
    }

    /// A key that reads no row. It names its actor as
    /// [`Self::with_actor_class`] does, under the same identity checks, and
    /// carries an all-Bottom credential Scope that every read door meets, so
    /// no grant the actor holds widens it. It holds no proof, no grant and no
    /// owner binding or exemption, even for the vault owner's own id. A verb
    /// hook whose caller's read key does not build reads under it, never on
    /// the actor's own lane.
    #[must_use]
    pub fn read_nothing(
        actor_ref: impl Into<String>,
        actor_class: impl Into<String>,
    ) -> Option<Self> {
        let mut key = Self::from_parts(actor_ref.into(), Some(actor_class.into()))?;
        key.authority = Some(Scope::default());
        Some(key)
    }

    fn from_parts(actor_ref: String, actor_class: Option<String>) -> Option<Self> {
        if actor_ref.trim().is_empty() {
            return None;
        }
        let actor_class = actor_class
            .and_then(|class| (!class.trim().is_empty()).then(|| class.trim().to_owned()));
        Some(Self {
            actor_ref: actor_ref.trim().to_owned(),
            actor_class,
            principal_ref: None,
            enforce_access_grants: false,
            unscoped_rows_open: false,
            proof: None,
            authority: None,
            channel: None,
            owner: None,
            owner_exemption: None,
            room_turn: None,
            room_facets: None,
            worlds: None,
            destination: crate::settings::ReadDestination::on_device(),
            host_action: None,
            owner_proof: None,
            owner_by_census: false,
            record_bound: None,
        })
    }

    /// The vault owner's own key: the owner's un-narrowed Grant.
    ///
    /// DEC-0005: an own device's ceiling defaults to all of the owner's vault,
    /// and ARCH-0057: a manifest never overrules the person on their own
    /// vault. So this key resolves to the full (legacy) floor, matches no
    /// manifest grant row, and needs no positive record stamp. The off-record
    /// band never reaches base, so it is absent by construction.
    ///
    /// Crate-private on purpose: only the Memory facade mints it, after the
    /// owner verification passes, and every read transaction re-checks that
    /// binding before it resolves a plan (`ScopedRead` refuses a key whose
    /// owner binding no longer holds).
    #[must_use]
    pub(crate) fn vault_owner(owner: EntityId) -> Self {
        Self {
            actor_ref: owner.to_hex(),
            actor_class: Some(
                crate::edge::EdgeActorClass::Human
                    .gate_actor_class()
                    .to_owned(),
            ),
            principal_ref: None,
            enforce_access_grants: false,
            unscoped_rows_open: false,
            proof: None,
            authority: None,
            channel: None,
            owner: Some(owner),
            owner_exemption: None,
            room_turn: None,
            room_facets: None,
            worlds: None,
            destination: crate::settings::ReadDestination::on_device(),
            host_action: None,
            owner_proof: None,
            owner_by_census: false,
            record_bound: None,
        }
    }

    /// The vault owner's own key for a due Owner schedule's recorded Owner
    /// (FIX 1259): [`Self::vault_owner`], whose owner binding each read
    /// proves by the live-owner census in its own snapshot (`owner` a live
    /// Owner of this vault, his PERSON live) instead of an owner actor
    /// binding, so a live co-Owner with none reads as his own Owner lane and
    /// no wider. Only a schedule's recorded-Owner binding builds one; it is
    /// no owner proof and authorizes no act.
    #[must_use]
    pub(crate) fn vault_owner_by_census(owner: EntityId) -> Self {
        Self {
            owner_by_census: true,
            ..Self::vault_owner(owner)
        }
    }

    /// Whether this owner key's binding is the live-owner census
    /// ([`Self::vault_owner_by_census`]).
    pub(crate) fn owner_by_census(&self) -> bool {
        self.owner_by_census
    }

    /// This key, held to the host action it was built for (FIX 2222): every
    /// read proves again in its own snapshot that the vault is self-hosted
    /// and that the root, or the dev mode, still acts as this owner. Only
    /// `HostActionAuthority` builds the guard.
    #[must_use]
    pub(crate) fn guarded_by_host_action(
        mut self,
        guard: crate::authority::HostActionGuard,
    ) -> Self {
        self.host_action = Some(guard);
        self
    }

    /// The host action this key reads for, when it is one's.
    pub(crate) fn host_action_guard(&self) -> Option<&crate::authority::HostActionGuard> {
        self.host_action.as_ref()
    }

    /// This key, held to the owner proof a request authenticated (WILL-PLAN
    /// L13 row 01): every read revalidates `owner` in its own snapshot, as an
    /// owner act does (`AuthenticatedOwner::revalidate_in_txn`: this vault, a
    /// live person who owns it now, any credential or host action the proof
    /// bound), so a key built before the owner lapsed reads nothing after.
    /// Only [`crate::Vault::owner_proof_read_key`] builds one.
    #[must_use]
    pub(crate) fn guarded_by_owner_proof(
        mut self,
        owner: crate::consent::AuthenticatedOwner,
    ) -> Self {
        self.owner_proof = Some(Box::new(owner));
        self
    }

    /// The owner proof this key reads for, when it is one's.
    pub(crate) fn owner_proof_guard(&self) -> Option<&crate::consent::AuthenticatedOwner> {
        self.owner_proof.as_deref()
    }

    /// The owner this key was minted for, when it is the vault owner's key.
    pub(crate) fn vault_owner_ref(&self) -> Option<EntityId> {
        self.owner
    }

    /// Whether this key reads past every facet bound in `txn` (owner ruling
    /// FACET-READ = A): the vault owner's own key, and a narrower credential
    /// of the owner's while its holder is still the bound owner there. A
    /// delegate's key, or a transferred one, never is. The one predicate the
    /// read lane and every door that judges a facet narrowing share.
    pub(crate) fn facets_owner_exempt_in(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
    ) -> crate::error::Result<bool> {
        if self.owner.is_some() {
            return Ok(true);
        }
        let Some(owner) = self.owner_exemption else {
            return Ok(false);
        };
        crate::memory::owner_exemption_holds_in_txn(vault, txn, owner).map_err(|refusal| {
            crate::error::Error::Claim(crate::error::ClaimError::ScopedReadOwnerNotLive(Box::new(
                refusal,
            )))
        })
    }

    /// Whether this is the vault owner's own key, which reads all of the
    /// owner's vault while its binding holds (`Self::vault_owner`).
    #[must_use]
    pub fn reads_as_vault_owner(&self) -> bool {
        self.owner.is_some()
    }

    /// How a reader holding this key sees a stored key: as stored for the
    /// vault owner's own key, as its handle for every other. A door derives
    /// it from the key it reads under each time, never from a stored sight.
    pub(crate) fn secret_sight(&self) -> crate::secret_custody::SecretSight {
        if self.reads_as_vault_owner() {
            crate::secret_custody::SecretSight::Owner
        } else {
            crate::secret_custody::SecretSight::Masked
        }
    }

    /// This key, bound to the credential it was presented with: every read
    /// checks `proof` as it checks any credential's, live (unexpired and
    /// unrevoked) in the read's own snapshot and within its records and
    /// channels, while the key's own floor decides what the read admits.
    #[must_use]
    pub(crate) fn while_live(mut self, proof: &crate::authority::VerifiedSlip) -> Self {
        self.proof = Some(proof.clone());
        self
    }

    /// Read inside a room turn. The ceiling only narrows: every check this key
    /// already makes still runs.
    #[must_use]
    pub(crate) fn in_room_turn(mut self, ceiling: RoomTurnCeiling) -> Self {
        self.room_turn = Some(Box::new(ceiling));
        self
    }

    /// The room turn this key reads inside, when a host bound one.
    pub(crate) fn room_turn(&self) -> Option<&RoomTurnCeiling> {
        self.room_turn.as_deref()
    }

    /// Read inside `room`'s signed facets as each snapshot finds them, as a
    /// turn in it does (FIX 643): a named-room read outside a turn keeps every
    /// other term it has. Like every facet bound, it only narrows, and the
    /// owner's key reads past it.
    #[must_use]
    pub(crate) fn within_room_facets(mut self, room: EntityId) -> Self {
        self.room_facets = Some(room);
        self
    }

    /// Read only rows in `worlds`, each where `record_world_in` places it: a
    /// claim by its own world, a TASK and its facts by their birth, any
    /// other record as base reality. The ceiling only narrows: it meets any
    /// the key already holds.
    #[must_use]
    pub(crate) fn within_worlds(mut self, worlds: crate::pipeline::WorldAuthoritySet) -> Self {
        self.worlds = Some(match self.worlds.take() {
            Some(held) => held.meet(&worlds),
            None => worlds,
        });
        self
    }

    /// This key held to `scope`, a saved lane's frozen read Scope (OF-506),
    /// as every read door holds a credential's. It only narrows: it meets
    /// any Scope the key already holds.
    #[must_use]
    pub(super) fn within_authority(mut self, scope: Scope) -> Self {
        self.authority = Some(match self.authority.take() {
            Some(held) => held.meet(&scope),
            None => scope,
        });
        self
    }

    /// This key held to `records`, a saved lane's frozen records caveat
    /// (OF-506): it reads only the rows named there, as the credential's own
    /// caveat held it. It only narrows: it meets any bound the key holds.
    #[must_use]
    pub(super) fn within_records(mut self, records: &std::collections::BTreeSet<String>) -> Self {
        self.record_bound = Some(match self.record_bound.take() {
            Some(held) => held.intersection(records).cloned().collect(),
            None => records.clone(),
        });
        self
    }

    /// Read for a caller at `locality`. A caller off this device reads no
    /// row a device-local world keeps here, whatever its credential grants:
    /// DEC-0005 gives the owner's own devices, not the owner, a ceiling over
    /// those worlds. The ceiling only narrows: once off the device, a key
    /// never reads on it again.
    #[must_use]
    pub fn at(mut self, locality: CallerLocality) -> Self {
        self.destination.meet(&locality.into());
        self
    }

    /// Read for a caller whose rows go to `destination`: the machine its
    /// connection proved rides beside the locality, and every read judges
    /// the world settings for it in its own snapshot (mesh PR2b). It only
    /// narrows, as [`Self::at`] does: each machine is a conjunct, and a later
    /// on-device locality never erases one.
    #[must_use]
    pub fn for_destination(mut self, destination: &crate::settings::ReadDestination) -> Self {
        self.destination.meet(destination);
        self
    }

    /// Whether this key reads for a caller off this device.
    pub(crate) fn off_device(&self) -> bool {
        self.destination.is_off_device()
    }

    /// Where this key's rows go.
    pub(crate) fn destination(&self) -> &crate::settings::ReadDestination {
        &self.destination
    }

    /// Attach the authenticated principal. An unbound delegated caller has no grants.
    #[must_use]
    pub fn require_access_grants(mut self, principal_ref: Option<EntityId>) -> Self {
        self.principal_ref = principal_ref;
        self.enforce_access_grants = true;
        self
    }

    /// A vault-internal reader (the Dreamer), or a credential's holder other
    /// than the owner, under the delegated relationship gate: a row that
    /// names a relationship or a private scope passes only on this
    /// principal's live grants, and a holder with no principal has none. A
    /// row that names neither is the vault's own and stays readable, where a
    /// delegated key refuses every such MESSAGE or SUMMARY.
    #[must_use]
    pub(crate) fn require_relationship_grants(self, principal_ref: Option<EntityId>) -> Self {
        Self {
            unscoped_rows_open: true,
            ..self.require_access_grants(principal_ref)
        }
    }

    /// A narrower credential of the vault owner's: it reads a relationship's
    /// rows as the owner does only while `owner` is still the vault's bound
    /// owner in the read's own snapshot, so a lane kept past a revocation
    /// loses the exemption with the binding. Otherwise it reads under the gate
    /// any other holder's key does ([`Self::require_relationship_grants`]).
    /// It never takes the owner's floor.
    #[must_use]
    pub(crate) fn exempt_while_owner(self, owner: EntityId) -> Self {
        Self {
            owner_exemption: Some(owner),
            ..self.require_relationship_grants(Some(owner))
        }
    }

    /// Constructs a read capability only from a log/MAC/holder-verified slip.
    #[must_use]
    pub fn from_verified_slip(proof: &crate::authority::VerifiedSlip) -> Option<Self> {
        // `core:read` is the host's spelling of the same verb (the server's pairing and OAuth
        // slips carry it; its relay already reads either as a read grant).
        if !(proof.allows_verb("read") || proof.allows_verb("core:read")) {
            return None;
        }
        let mut key = Self::from_parts(
            proof.claims().holder_ref.clone(),
            proof.claims().actor_class.clone(),
        )?;
        key.authority = Some(Self::read_authority(proof.scope()));
        key.proof = Some(proof.clone());
        Some(key)
    }

    /// [`Self::from_verified_slip`] for a credential that names a row it
    /// writes about rather than reads (FIX 8155): the same holder, class,
    /// proof and record, world, facet and channel bounds, its verb axis
    /// taken to admit `read`, so a write-only credential is judged by its
    /// bounds and never by a read verb it was not asked to hold.
    #[must_use]
    pub(crate) fn from_verified_slip_as_target(
        proof: &crate::authority::VerifiedSlip,
    ) -> Option<Self> {
        let mut key = Self::from_parts(
            proof.claims().holder_ref.clone(),
            proof.claims().actor_class.clone(),
        )?;
        let mut authority = Self::read_authority(proof.scope());
        if let crate::federation::ScopeAxis::Some(verbs) = &mut authority.verbs {
            verbs.insert("read".to_owned());
        }
        key.authority = Some(authority);
        key.proof = Some(proof.clone());
        Some(key)
    }

    /// A slip's Scope as every read door checks a proof of it: one that
    /// names `core:read` names `read` too.
    pub(crate) fn read_authority(scope: &crate::federation::Scope) -> crate::federation::Scope {
        let mut authority = scope.clone();
        if let crate::federation::ScopeAxis::Some(verbs) = &mut authority.verbs
            && verbs.contains("core:read")
        {
            verbs.insert("read".to_owned());
        }
        authority
    }

    pub(crate) fn authenticated_person(&self) -> Option<EntityId> {
        if self.enforce_access_grants {
            self.principal_ref
        } else {
            EntityId::from_hex(&self.actor_ref).ok()
        }
    }

    /// The proof's Scope. A host slip spells the read verb `core:read`; every
    /// read door takes it as the `read` class it names, as
    /// [`Self::from_verified_slip`] already does.
    pub(crate) fn authority_scope(&self) -> Option<&crate::federation::Scope> {
        self.authority.as_ref()
    }

    /// The worlds this read asked for, as a world-only ceiling; `None` when
    /// it asked for none.
    pub(crate) fn asked_world_ceiling(&self) -> Option<Scope> {
        self.worlds
            .as_ref()
            .map(|worlds| world_only(worlds.scope_axis()))
    }

    /// The asked worlds met with the worlds the verified credential grants,
    /// once, as one world-only ceiling: top when neither limits the read.
    pub(crate) fn world_ceiling(&self) -> Scope {
        let asked = self.asked_world_ceiling().unwrap_or_else(Scope::top);
        match self.authority_scope() {
            Some(credential) => asked.meet(&world_only(credential.worlds.clone())),
            None => asked,
        }
    }

    /// Whether the read's verified credential grants only some worlds.
    pub(crate) fn has_world_ceiling(&self) -> bool {
        self.authority
            .as_ref()
            .is_some_and(|granted| !matches!(granted.worlds, crate::federation::ScopeAxis::All))
    }

    #[must_use]
    pub fn actor_ref(&self) -> &str {
        &self.actor_ref
    }

    #[must_use]
    pub fn actor_class(&self) -> Option<&str> {
        self.actor_class.as_deref()
    }
}
