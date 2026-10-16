//! Authenticated identity carried by a scoped read.
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
    /// Set only on the vault owner's own key; see [`Self::vault_owner`].
    owner: Option<EntityId>,
    /// Set only on a narrower credential of the owner's; see
    /// [`Self::exempt_while_owner`].
    pub(super) owner_exemption: Option<EntityId>,
    /// The room turn this key reads inside, when a host bound one.
    pub(super) room_turn: Option<Box<RoomTurnCeiling>>,
    /// The worlds this read asked for (ARCH-0022). Every row it serves,
    /// ranked or reached through the graph, lies in one of them.
    pub(super) worlds: Option<crate::pipeline::WorldAuthoritySet>,
    /// Whether the caller sits off this device; see [`Self::at`].
    off_device: bool,
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
    /// The room's members, sorted and unique: each row must pass the
    /// all-of-audience rule for every one of them (ARCH-0006a).
    pub(crate) roster: Vec<EntityId>,
    /// Every other member's read key: a row the room reads must be one each
    /// of them may read too, private principal rows and NOTEs included.
    pub(crate) peers: Vec<ScopedReadActorKey>,
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
    /// The met clearance of the members that bring one (ILDF2): `None` while
    /// only the owner and the vault's own agents are in the meet.
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
    /// held.
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
        }
    }

    /// Whether every member of `roster` already binds this ceiling.
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
            owner: None,
            owner_exemption: None,
            room_turn: None,
            worlds: None,
            off_device: false,
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
            owner: Some(owner),
            owner_exemption: None,
            room_turn: None,
            worlds: None,
            off_device: false,
        }
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

    /// Read for a caller at `locality`. A caller off this device reads no
    /// row a device-local world keeps here, whatever its credential grants:
    /// DEC-0005 gives the owner's own devices, not the owner, a ceiling over
    /// those worlds. The ceiling only narrows: once off the device, a key
    /// never reads on it again.
    #[must_use]
    pub fn at(mut self, locality: CallerLocality) -> Self {
        self.off_device |= locality == CallerLocality::OffDevice;
        self
    }

    /// Whether this key reads for a caller off this device.
    pub(crate) fn off_device(&self) -> bool {
        self.off_device
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
