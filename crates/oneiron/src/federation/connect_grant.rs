//! The guest grant a vault-to-vault Connect pact governs (FIX 3016, ARCH-0043
//! #guest-grants, #relationship-lifecycle).
//!
//! Each owner mints, for the peer vault, one FEDERATION_GRANT of purpose
//! [`FederationGrantScope::Connect`] and role Guest: read and propose inside
//! explicit local named worlds, never base and never a received foreign
//! world. The grant names a vault-resident guest actor for that peer, never a
//! host key or a vault id, and that actor's row carries the origin vault.
//!
//! A minted grant is inert until one Active pact binds it: every reader asks
//! [`pact_admits_grant`], which refuses a Connect grant while it is Unpacted.
//! The pact's dual-signed contract stays the worlds/facets/bands triple; the
//! offer and accept doors require the local outbound half to be exactly
//! [`connect_direction_projection`] of the stored scope. The stored six-axis
//! scope (audience, verbs, sensitivity, the type-byte bands) is this vault's
//! own clamp on every exported record, not a dual-signed term.

use rmpv::Value;

use super::codec::{encode_msgpack_value, invalid_grant, required_value};
use super::{
    FederationDirectionScope, FederationGrant, FederationGrantPreset, FederationGrantRole,
    FederationGrantScope, Scope, ScopeAxis, SelectorRange, selector_range_of,
};
use crate::Vault;
use crate::authority::{
    AuthorityFold, AuthorityVaultId, FederationGrantActivation, federation_grant_activation,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower, derived_domains, is_foreign_world_id_range};
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Scope kind of a Connect guest grant on disk.
pub(super) const SCOPE_KIND_CONNECT: &str = "connect";

const CONNECT_SCOPE_KEYS: [&str; 2] = ["kind", "peer_vault_id"];

/// The verb classes a Connect guest grant may carry: a guest reads and
/// proposes, and never writes or administers (ARCH-0043 #guest-grants).
const CONNECT_GUEST_VERBS: [&str; 2] = ["read", "propose"];

/// The guest actor row's body: its kind tag, a display name, and the origin
/// vault (64 hex).
const GUEST_ACTOR_SCHEMA_VERSION: u64 = 1;
const GUEST_ACTOR_KIND: &str = "connect_guest";
const GUEST_ACTOR_KEYS: [&str; 4] = ["schema_version", "kind", "name", "origin_vault"];

/// What [`Vault::mint_connect_grant`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectGrantMinted {
    /// The new FEDERATION_GRANT, which the owner names to offer or accept.
    pub grant: EntityId,
    /// The vault-resident guest actor the grant names for the peer vault.
    pub guest_actor: EntityId,
    /// The scope stored: the request, inside the Connect guest ceiling.
    pub resolved_scope: Scope,
    /// The second the grant stops conferring; `None` until revoked.
    pub expires_at: Option<u64>,
}

impl FederationGrant {
    /// The guest grant a Connect with `peer_vault_id` governs, naming
    /// `guest_actor`: role and preset Guest, no Ask payload, no delegator,
    /// an explicit read/propose scope over named worlds, optional expiry.
    pub fn connect_guest(
        peer_vault_id: AuthorityVaultId,
        guest_actor: EntityId,
        authority_scope: Scope,
        expires_at: Option<u64>,
    ) -> Result<Self> {
        let grant = Self {
            authority_scope,
            scope: FederationGrantScope::Connect { peer_vault_id },
            member_ref: guest_actor,
            role: FederationGrantRole::Guest,
            preset: FederationGrantPreset::Guest,
            expires_at,
            delegated_by: None,
            guest: None,
        };
        grant.validate()?;
        Ok(grant)
    }
}

pub(super) fn encode_connect_scope(peer_vault_id: &AuthorityVaultId) -> Value {
    Value::Map(vec![
        (
            Value::from(CONNECT_SCOPE_KEYS[0]),
            Value::from(SCOPE_KIND_CONNECT),
        ),
        (
            Value::from(CONNECT_SCOPE_KEYS[1]),
            Value::from(bytes_to_hex_lower(peer_vault_id)),
        ),
    ])
}

pub(super) fn decode_connect_scope(entries: &[(Value, Value)]) -> Result<FederationGrantScope> {
    super::grant::validate_scope_keys(entries, &CONNECT_SCOPE_KEYS)?;
    let peer_vault_id = required_value(entries, CONNECT_SCOPE_KEYS[1])?
        .as_str()
        .and_then(canonical_vault_id)
        .ok_or_else(invalid_grant)?;
    let scope = FederationGrantScope::Connect { peer_vault_id };
    scope.validate()?;
    Ok(scope)
}

/// A vault id spelled as canonical lower hex, or `None`.
fn canonical_vault_id(value: &str) -> Option<AuthorityVaultId> {
    let id = crate::deletion::parse_hex::<32>(value)?;
    (bytes_to_hex_lower(&id) == value).then_some(id)
}

/// The shape every Connect guest grant's authority holds, on encode and
/// decode: verbs read/propose only, worlds named (never base, never a
/// foreign-range id), and a band set the pact triple can carry.
pub(super) fn validate_connect_authority(scope: &Scope) -> Result<()> {
    let verbs = matches!(&scope.verbs, ScopeAxis::Some(verbs)
        if !verbs.is_empty()
            && verbs.iter().all(|verb| CONNECT_GUEST_VERBS.contains(&verb.as_str())));
    let worlds = matches!(&scope.worlds, ScopeAxis::Some(worlds)
    if !worlds.is_empty()
        && worlds.iter().all(|world| {
            world.0 != crate::claim::base_world_id() && !is_foreign_world_id_range(world.0)
        }));
    if verbs && worlds && connect_direction_projection(scope).is_some() {
        Ok(())
    } else {
        Err(invalid_grant())
    }
}

/// The pact direction a Connect grant's stored scope projects to: worlds and
/// facets as stored, and each type-byte band as the classification or family
/// its kind belongs to. Deterministic; the stored bytes stay the clamp on
/// each exported record. `None` when a band names a kind with no replication
/// identity or the triple fails pact validation.
pub(crate) fn connect_direction_projection(scope: &Scope) -> Option<FederationDirectionScope> {
    let bands = match &scope.bands {
        ScopeAxis::All => ScopeAxis::All,
        ScopeAxis::Bottom => ScopeAxis::Bottom,
        ScopeAxis::Some(kinds) => SelectorRange::normalize(
            kinds
                .iter()
                .map(|kind| selector_range_of(*kind))
                .collect::<Option<Vec<_>>>()?,
        )
        .into_iter()
        .collect(),
    };
    let direction = FederationDirectionScope {
        worlds: scope.worlds.clone(),
        facets: scope.facets.clone(),
        bands,
    };
    direction.validate().ok()?;
    Some(direction)
}

/// Whether a pact direction is a guest slice: named worlds without base.
pub(crate) fn is_guest_slice(direction: &FederationDirectionScope) -> bool {
    matches!(&direction.worlds, ScopeAxis::Some(worlds)
        if !worlds.is_empty()
            && worlds.iter().all(|world| world.0 != crate::claim::base_world_id()))
}

/// Whether `grant`'s purpose can back a sync selector or document READ: a
/// shared-vault member grant, or a Connect guest grant. An Ask guest grant
/// discloses facts for one ask and never backs a selector slice.
pub(crate) fn grant_serves_selector(grant: &FederationGrant) -> bool {
    match grant.scope {
        FederationGrantScope::Vault { .. } => !grant.role.is_guest(),
        FederationGrantScope::Connect { .. } => grant.role.is_guest(),
        FederationGrantScope::Ask { .. } => false,
    }
}

/// Whether the fold's pact states let `grant` (stored as `grant_id`) confer.
/// A Connect grant confers only through exactly one Active operative pact
/// with its own peer vault: Unpacted, it is inert. Every other purpose keeps
/// the generic gate, Unpacted or Active.
pub(crate) fn pact_admits_grant(
    fold: &AuthorityFold,
    grant_id: &EntityId,
    grant: &FederationGrant,
) -> bool {
    let activation = federation_grant_activation(fold, grant_id);
    let FederationGrantScope::Connect { peer_vault_id } = grant.scope else {
        return !matches!(activation, FederationGrantActivation::Inactive(_));
    };
    activation == FederationGrantActivation::Active
        && fold
            .active_pact_delivery_context(grant_id)
            .ok()
            .and_then(|(pact_id, _)| fold.federation_pacts.get(&pact_id))
            .is_some_and(|pact| pact.peer_vault_id == peer_vault_id)
}

/// Refuses unless `grant_ref` is a live Connect guest grant here for
/// `peer_vault_id`, unexpired now, whose scope projects exactly to
/// `outbound`, the pact half this vault shares. Ask, membership, own-device
/// and Delegate rows all refuse.
pub(crate) fn require_connect_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant_ref: &EntityId,
    peer_vault_id: &AuthorityVaultId,
    outbound: &FederationDirectionScope,
) -> Result<()> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, grant_ref)?
    else {
        return Err(Error::EntityNotFound);
    };
    let grant = super::decode_federation_grant_body(&body)?;
    if grant.scope
        != (FederationGrantScope::Connect {
            peer_vault_id: *peer_vault_id,
        })
        || !grant.role.is_guest()
        || !grant.confers_at(vault.store.clock.now_recorded_at())
    {
        return Err(refused(
            "the grant is not a live Connect grant for that peer vault",
        ));
    }
    if connect_direction_projection(&grant.authority_scope).as_ref() != Some(outbound) {
        return Err(refused(
            "the pact's outbound scope is not the Connect grant's scope",
        ));
    }
    Ok(())
}

/// One live Connect per peer, locally (FIX 3016): refuses while a
/// non-terminal pact with `peer_vault_id` stands, unless it is `retry_of`,
/// the pact an exact retry names. A local door rule, not distributed
/// uniqueness across replicas.
pub(crate) fn require_one_connect_per_peer(
    fold: &AuthorityFold,
    peer_vault_id: &AuthorityVaultId,
    retry_of: Option<&[u8; 32]>,
) -> Result<()> {
    if fold.federation_pacts.iter().any(|(pact_id, pact)| {
        pact.peer_vault_id == *peer_vault_id
            && !pact.status.is_terminal()
            && Some(pact_id) != retry_of
    }) {
        return Err(refused(
            "this vault already has a live Connect with that peer vault",
        ));
    }
    Ok(())
}

fn refused(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

/// Refuses a requested Connect scope whose named worlds are not live local
/// WORLD rows, or whose named facets are not live FACET rows.
fn require_local_named_axes(vault: &Vault, txn: &heed::RoTxn<'_>, scope: &Scope) -> Result<()> {
    let ScopeAxis::Some(worlds) = &scope.worlds else {
        return Err(refused("a Connect grant names its worlds"));
    };
    let facets: Vec<&super::ScopeId> = match &scope.facets {
        ScopeAxis::Some(facets) => facets.iter().collect(),
        ScopeAxis::All | ScopeAxis::Bottom => Vec::new(),
    };
    for (id, kind) in worlds
        .iter()
        .map(|world| (world, ENTITY_TYPE_WORLD))
        .chain(facets.into_iter().map(|facet| (facet, ENTITY_TYPE_FACET)))
    {
        if live_entity_row_in_txn(&vault.store, txn, &id.0)?.live_type() != Some(kind) {
            return Err(refused(
                "a Connect grant names only this vault's live worlds and facets",
            ));
        }
    }
    Ok(())
}

fn guest_actor_body(peer_vault_id: &AuthorityVaultId) -> Result<Vec<u8>> {
    let origin = bytes_to_hex_lower(peer_vault_id);
    encode_msgpack_value(
        &Value::Map(vec![
            (
                Value::from(GUEST_ACTOR_KEYS[0]),
                Value::from(GUEST_ACTOR_SCHEMA_VERSION),
            ),
            (
                Value::from(GUEST_ACTOR_KEYS[1]),
                Value::from(GUEST_ACTOR_KIND),
            ),
            (
                Value::from(GUEST_ACTOR_KEYS[2]),
                Value::from(format!("Connected vault {}", &origin[..8])),
            ),
            (Value::from(GUEST_ACTOR_KEYS[3]), Value::from(origin)),
        ]),
        "connect guest actor MessagePack encode failed",
    )
}

impl Vault {
    /// Mints the guest grant a Connect with `peer_vault_id` will govern,
    /// approved by `owner` (FIX 3016). In one writer: a live Owner and an
    /// unconflicted local root; not this vault; no live Connect with that
    /// peer; worlds that are this vault's live named worlds, never base or a
    /// received foreign world; verbs read/propose only; the request inside
    /// the manifest's Connect guest ceiling (an excess refuses, never a
    /// clamp); an expiry, when given, in the future. The grant names the
    /// peer's vault-resident guest actor, resolved or created here. It is
    /// inert until both owners' Connect makes its pact Active.
    pub fn mint_connect_grant(
        &self,
        owner: &AuthenticatedOwner,
        peer_vault_id: AuthorityVaultId,
        authority_scope: Scope,
        expires_at: Option<u64>,
    ) -> Result<ConnectGrantMinted> {
        self.with_write_txn_grouped(|txn| {
            self.mint_connect_grant_in_txn(txn, owner, peer_vault_id, authority_scope, expires_at)
        })
    }

    fn mint_connect_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        peer_vault_id: AuthorityVaultId,
        requested: Scope,
        expires_at: Option<u64>,
    ) -> Result<ConnectGrantMinted> {
        owner.revalidate_in_txn(self, txn)?;
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if fold.vault_root_is_conflicted() {
            return Err(refused("this vault's authority root is in conflict"));
        }
        let local = fold
            .vault_id
            .ok_or_else(|| refused("this vault has no authority root yet"))?;
        if peer_vault_id == local {
            return Err(refused("a vault cannot connect to itself"));
        }
        require_one_connect_per_peer(&fold, &peer_vault_id, None)?;
        validate_connect_authority(&requested)
            .map_err(|_| refused("a Connect grant reads or proposes named worlds only"))?;
        require_local_named_axes(self, txn, &requested)?;
        let ceiling = self.connect_guest_ceiling_in_txn(txn)?;
        if !requested.is_narrowing_of(&ceiling) {
            return Err(refused(
                "the requested scope exceeds the Connect guest ceiling",
            ));
        }
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        if expires_at.is_some_and(|expires| expires <= now) {
            return Err(refused("a Connect grant's expiry must be in the future"));
        }
        let resolved = requested.meet(&ceiling);
        let guest_actor = self.connect_guest_actor_in_txn(txn, &local, &peer_vault_id, now)?;
        let grant = FederationGrant::connect_guest(
            peer_vault_id,
            guest_actor,
            resolved.clone(),
            expires_at,
        )?;
        if !grant.confers_at(now) {
            return Err(refused(
                "the requested scope confers no read: name its bands, audience and sensitivity",
            ));
        }
        let id = self.store.clock.entity_id()?;
        self.put_connect_row_in_txn(
            txn,
            id,
            ENTITY_TYPE_FEDERATION_GRANT,
            now,
            super::encode_federation_grant_body(&grant)?,
            true,
        )?;
        Ok(ConnectGrantMinted {
            grant: id,
            guest_actor,
            resolved_scope: resolved,
            expires_at,
        })
    }

    /// The peer's vault-resident guest actor: one PERSON row per (this
    /// vault, peer vault), its id derived from both, its body carrying the
    /// origin vault. Resolved when present with the same body; created when
    /// absent; anything else at that id refuses.
    fn connect_guest_actor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        local: &AuthorityVaultId,
        peer_vault_id: &AuthorityVaultId,
        now: u64,
    ) -> Result<EntityId> {
        let actor = EntityId::derive(
            derived_domains::CONNECT_GUEST_ACTOR,
            &[&local[..], &peer_vault_id[..]],
        )?;
        let body = guest_actor_body(peer_vault_id)?;
        match live_entity_row_in_txn(&self.store, txn, &actor)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_PERSON,
                body: stored,
            } if stored == body => return Ok(actor),
            LiveEntityRow::Absent => {}
            LiveEntityRow::Live { .. } | LiveEntityRow::DeletedShell => {
                return Err(refused(
                    "the peer vault's guest actor row is not a live Connect guest",
                ));
            }
        }
        self.put_connect_row_in_txn(txn, actor, ENTITY_TYPE_PERSON, now, body, false)?;
        Ok(actor)
    }

    fn put_connect_row_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        entity_type: u8,
        now: u64,
        data: Vec<u8>,
        allow_maintenance: bool,
    ) -> Result<()> {
        // FEDERATION_GRANT is an engine-authored maintenance kind; this door
        // and its checks are the only Connect minting path.
        crate::batch::apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id,
                entity_type,
                occurred: crate::TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data,
                allow_maintenance,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }

    /// The origin vault a Connect guest actor stands for: what attribution
    /// of a peer's replicated rows names. `None` when `actor` is not a live
    /// Connect guest actor here.
    pub fn connect_guest_origin_vault(&self, actor: &EntityId) -> Result<Option<AuthorityVaultId>> {
        let txn = self.store.env.read_txn()?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_PERSON,
            body,
        } = live_entity_row_in_txn(&self.store, &txn, actor)?
        else {
            return Ok(None);
        };
        let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut body.as_slice()) else {
            return Ok(None);
        };
        let field = |key: &str| {
            entries
                .iter()
                .find(|(name, _)| name.as_str() == Some(key))
                .and_then(|(_, value)| value.as_str())
        };
        if field(GUEST_ACTOR_KEYS[1]) != Some(GUEST_ACTOR_KIND) {
            return Ok(None);
        }
        Ok(field(GUEST_ACTOR_KEYS[3]).and_then(canonical_vault_id))
    }
}
