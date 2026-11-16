//! Whether a Grant row stands (Fable pass 28, DESIGN 3.1): what the verified fold's counted
//! acts say of it, never the row alone. A row gives nothing by itself.
//!
//! [`StandingGrant`] is the witness a conferring reader takes. Only
//! [`Vault::standing_grant_in_txn`] builds one, so a reader that takes it cannot confer from a
//! row the fold does not stand behind. A row that does not stand is skipped, never an error,
//! so a forged row cannot block a reader either.
//!
//! The readers move to it in pass 28 R3, each with the hand-written guard it replaces; the
//! Grant kinds with no act of their own before R2 get the general grant act, whose giving
//! commits to the row's terms under the row's own terms key; a guest's Grant is given by it
//! since R3c (an Ask guest's with its ask, a Connect guest's at its owner's mint), and a
//! Connect guest's stands only while one Active operative pact with its peer binds it too.
//! No act gives an own-device or an engine-default Grant: R4 reads each as derived, the first
//! while the fold names its holder a live Owner of the vault, the second while it holds no
//! more than the build's default table, and every other row no counted act names stands for
//! nothing.

use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityFold, GrantFamily};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

use super::{
    FederationGrant, FederationGrantRole, FederationGrantScope, GrantTermsKey, ScopeAxis,
    decode_federation_grant_body_keyed, own_device_residence_scope,
};

/// A Grant the verified fold stands behind: its row, and the counted act that gives it.
#[derive(Debug, Clone)]
pub(crate) struct StandingGrant {
    id: EntityId,
    grant: FederationGrant,
    act: AuthorityEntryHash,
}

impl StandingGrant {
    /// The FEDERATION_GRANT row's id.
    pub(crate) fn id(&self) -> EntityId {
        self.id
    }

    /// The Grant as its row holds it, which is what its act states.
    pub(crate) fn grant(&self) -> &FederationGrant {
        &self.grant
    }

    /// The Grant, taken out of the witness.
    pub(crate) fn into_grant(self) -> FederationGrant {
        self.grant
    }

    /// The counted act that gives the Grant.
    #[allow(dead_code, reason = "pass 28 R3's later readers name the act")]
    pub(crate) fn act(&self) -> &AuthorityEntryHash {
        &self.act
    }

    /// The Grant row `id`, whose stored `body` this is, while `fold` stands behind it at
    /// `now` in one of `families`: the one check every standing read makes
    /// ([`Vault::standing_grant_in_txn`]). The caller has read the row live.
    fn in_fold(
        fold: &AuthorityFold,
        id: EntityId,
        body: &[u8],
        families: &[GrantFamily],
        now: u64,
    ) -> Option<Self> {
        let (grant, terms_key) = decode_federation_grant_body_keyed(body).ok()?;
        Self::decoded_in_fold(fold, id, grant, terms_key, families, Some(now))
    }

    /// [`Self::in_fold`] for a body already decoded. A Connect guest's Grant stands only
    /// while one Active operative pact with its own peer binds it, beside its counted giving
    /// ([`super::pact_admits_grant`]): its owner's mint gives it, and the pact both owners
    /// signed puts it to use. Expiry is read at `now`; `None` reads none, for a door that
    /// judges expiry itself.
    fn decoded_in_fold(
        fold: &AuthorityFold,
        id: EntityId,
        grant: FederationGrant,
        terms_key: Option<GrantTermsKey>,
        families: &[GrantFamily],
        now: Option<u64>,
    ) -> Option<Self> {
        // Expiry alone: what a live Grant then confers (a verb, a class, a git push) is
        // its reader's, so `FederationGrant::is_live_at`, Access's predicate, is not
        // asked here (it refuses every git push Grant and a class-only scope).
        if now.is_some_and(|now| expired(&grant, now)) {
            return None;
        }
        let act = given_in_fold(fold, id, &grant, terms_key.as_ref(), families)?;
        if matches!(grant.scope, FederationGrantScope::Connect { .. })
            && !super::pact_admits_grant(fold, &id, &grant)
        {
            return None;
        }
        Some(Self { id, grant, act })
    }
}

/// Whether `grant` has expired at `now`: from its expiry second on.
fn expired(grant: &FederationGrant, now: u64) -> bool {
    grant.expires_at.is_some_and(|expires_at| now >= expires_at)
}

/// The counted act that gives the Grant row `id`, holding `grant` under `terms_key`, in one
/// of `families`, while no counted act ended its line and the giving states exactly the row;
/// `None` for every other row. Expiry is not read here.
fn given_in_fold(
    fold: &AuthorityFold,
    id: EntityId,
    grant: &FederationGrant,
    terms_key: Option<&GrantTermsKey>,
    families: &[GrantFamily],
) -> Option<AuthorityEntryHash> {
    let line = fold
        .grant_line(id)
        .filter(|line| !line.ended && line.family.is_some_and(|f| families.contains(&f)))?;
    let (act, terms) = line.giving.as_ref()?;
    terms.matches_row(id, grant, terms_key).then_some(*act)
}

/// The owner's counted mint that gives his agent Grant row `id` (an `owner_agent` row, a git
/// push Grant or a Steward mint's row), holding `grant` under `terms_key`: the row holds
/// `residence`, this vault's own (no mint carries it, and every writer puts that one), the
/// line is given in [`GrantFamily::OwnerAgent`], no counted act ended it, and the mint states
/// the row, term for term. `None` for a row no counted mint gives, one put back after its
/// revoke, one whose terms are not its mint's and one over another residence (a rewritten
/// scope would read another vault's pact). Expiry is the reader's: a lister of the owner's agent
/// Grants (backfill, a grantless agent, the default mint) asks which Grants name a holder,
/// expired or not, and each conferring reader reads the expiry at its own time.
#[must_use]
pub(crate) fn owner_agent_mint_in_fold(
    fold: &AuthorityFold,
    id: EntityId,
    grant: &FederationGrant,
    terms_key: Option<&GrantTermsKey>,
    residence: &FederationGrantScope,
) -> Option<AuthorityEntryHash> {
    if grant.scope != *residence {
        return None;
    }
    given_in_fold(fold, id, grant, terms_key, &[GrantFamily::OwnerAgent])
}

/// The families an act gives a Grant row over a shared vault in, read from the row's shape;
/// `None` for a base agent's Steward Grant, which stands on the owner's counted mint or, no
/// act naming it, as the engine's default (R4, [`derived_row`]).
///
/// The shape only narrows: the row stands only when its line was given in one of these
/// families, so a row whose shape names another family than its act stands for nothing.
/// A member row is a person's membership (SharedMember) or a house seated in its org at a
/// role by its binder (HouseLink), both `FederationGrant::new` rows. An owner's agent
/// Grant, a git push Grant and an `engine.controls` Grant are the owner's signed mints
/// (OwnerAgent); an admin's delegate is the Delegate family; a guest's Grant is read by
/// [`guest_row_families`].
#[must_use]
pub(crate) fn shared_row_families(grant: &FederationGrant) -> Option<&'static [GrantFamily]> {
    if super::is_system_agent_steward_grant(grant) {
        return None;
    }
    if grant.role == FederationGrantRole::Guest {
        return Some(guest_row_families(grant));
    }
    const OWNER_MINT: &[GrantFamily] = &[GrantFamily::OwnerAgent];
    const DELEGATE: &[GrantFamily] = &[GrantFamily::Delegate];
    const MEMBER: &[GrantFamily] = &[GrantFamily::SharedMember, GrantFamily::HouseLink];
    Some(if is_owner_mint_row(grant) {
        OWNER_MINT
    } else if grant.role == FederationGrantRole::Delegate {
        DELEGATE
    } else {
        MEMBER
    })
}

/// The families an act gives a guest's Grant row in, read from the row's shape (pass 28 R3c):
/// an Ask guest's Grant is given with its ask (AskGuest), an inquiry edge by its owner's mint
/// and every rewrite of its terms (InquiryEdge), any other Connect guest's Grant by its owner's
/// mint (Connect). No writer gives a guest's Grant over a vault, so such a row stands for
/// nothing.
#[must_use]
fn guest_row_families(grant: &FederationGrant) -> &'static [GrantFamily] {
    match grant.scope {
        FederationGrantScope::Ask { .. } => &[GrantFamily::AskGuest],
        FederationGrantScope::Connect { .. } if grant.inquiry_terms.is_some() => {
            &[GrantFamily::InquiryEdge]
        }
        FederationGrantScope::Connect { .. } => &[GrantFamily::Connect],
        FederationGrantScope::Vault { .. } => &[],
    }
}

/// What the live guest Grant row `id`, whose stored body is `body`, confers at `now` under
/// `fold` (pass 28 R3c): the row of a guest's Grant given by its counted act in its shape's
/// family ([`guest_row_families`]), which no counted act ended (the guest's revoke ends it,
/// `SlipGrantRevoke`), whose terms are its act's, unexpired, and, a Connect guest's Grant, bound
/// by one Active operative pact with its peer. `None` for every other row: one no counted act
/// gives (a forged row), one put back after its revoke, one widened in place, a Connect Grant
/// no Active pact binds, and any row that is no guest's. The caller has read the row live.
#[must_use]
pub(crate) fn guest_grant_in_fold(
    fold: &AuthorityFold,
    id: EntityId,
    body: &[u8],
    now: u64,
) -> Option<StandingGrant> {
    let (grant, terms_key) = decode_federation_grant_body_keyed(body).ok()?;
    if grant.role != FederationGrantRole::Guest {
        return None;
    }
    let families = guest_row_families(&grant);
    StandingGrant::decoded_in_fold(fold, id, grant, terms_key, families, Some(now))
}

/// What a Grant row confers to a reader: a row the fold stands behind ([`StandingGrant`]),
/// or a row of a kind no act gives, read as derived (pass 28 R4, [`derived_row`]).
#[derive(Debug, Clone)]
pub(crate) enum SharedGrantRow {
    /// A row the verified fold stands behind.
    Standing(StandingGrant),
    /// A base agent's engine-default Steward Grant, within the build's default table, or (on
    /// the own-device residence, [`grant_row_in_fold`]) an own-device Grant whose holder the
    /// fold names a live Owner of the vault.
    Derived(EntityId, FederationGrant),
}

impl SharedGrantRow {
    /// The row's id and its Grant.
    pub(crate) fn into_parts(self) -> (EntityId, FederationGrant) {
        match self {
            Self::Standing(standing) => (standing.id, standing.grant),
            Self::Derived(id, grant) => (id, grant),
        }
    }

    /// The FEDERATION_GRANT row's id.
    pub(crate) fn id(&self) -> EntityId {
        match self {
            Self::Standing(standing) => standing.id(),
            Self::Derived(id, _) => *id,
        }
    }

    /// The Grant as its row holds it.
    pub(crate) fn grant(&self) -> &FederationGrant {
        match self {
            Self::Standing(standing) => standing.grant(),
            Self::Derived(_, grant) => grant,
        }
    }
}

/// Every Grant row over shared vault `vault_id` in `txn` that confers at `now` to a
/// membership reader, in id order: each row the fold stands behind in its shape's families,
/// and each base agent's engine-default Steward Grant ([`derived_row`]). A row no counted act gives,
/// one put back after its end, one whose terms are not its act's and one that does not
/// decode give nothing and never fault (a forged row cannot block a reader either).
/// Expiry is read at `now`; every other predicate (verbs, pact, PERSON) is the reader's.
///
/// # Errors
///
/// A store or authority-fold read failure.
pub(crate) fn shared_vault_grants_for_store_in_txn(
    store: &Store,
    fold: &AuthorityFold,
    txn: &heed::RoTxn<'_>,
    vault_id: u64,
    now: u64,
) -> Result<Vec<SharedGrantRow>> {
    let scope = FederationGrantScope::vault(vault_id);
    let mut rows = Vec::new();
    for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        store,
        txn,
        ENTITY_TYPE_FEDERATION_GRANT,
        None,
    )? {
        let id = id?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(store, txn, &id)?
        else {
            continue;
        };
        let Ok((grant, terms_key)) = decode_federation_grant_body_keyed(&body) else {
            continue;
        };
        if grant.scope != scope {
            continue;
        }
        rows.extend(shared_grant_row_decoded(
            store,
            fold,
            txn,
            id,
            grant,
            terms_key,
            Some(now),
        )?);
    }
    Ok(rows)
}

/// What the live Grant row `id`, whose stored body is `body`, confers to a membership
/// reader at `now` under `fold` ([`shared_vault_grants_for_store_in_txn`] for one row whose
/// scope the caller has read), read in `txn`: `None` for a row that does not stand. The
/// caller has read the row live.
///
/// # Errors
///
/// A store read failure (an engine-default row's Steward reach, [`derived_row`]).
pub(crate) fn shared_grant_row_in_fold(
    store: &Store,
    fold: &AuthorityFold,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &[u8],
    now: u64,
) -> Result<Option<SharedGrantRow>> {
    let Ok((grant, terms_key)) = decode_federation_grant_body_keyed(body) else {
        return Ok(None);
    };
    shared_grant_row_decoded(store, fold, txn, id, grant, terms_key, Some(now))
}

/// What the live Grant row `id` of this vault's own store, whose stored body is `body`,
/// confers at `now` under `fold`. A row over this shared vault (its scope is `shared_scope`,
/// [`Vault::shared_vault_scope_in_txn`]) reads as [`shared_grant_row_in_fold`] reads it. Of
/// every other row (an own-device residence row, a guest's Grant), an owner's signed mint
/// row (an `owner_agent` row, a git push Grant, an `engine.controls` Grant, or any row whose
/// counted line an owner's mint gives, a Steward mint among them) stands only on its counted
/// mint and over this vault's residence (the own-device one: over a shared vault it holds
/// the shared scope), a guest's Grant as [`guest_grant_in_fold`] reads it, and the rest read
/// as derived ([`derived_row`]): an own-device Grant stands while `owners`, the vault's live
/// owners ([`crate::policy_model::owners_in_txn`]), hold its holder. Read in `txn`; `None`
/// for a row that does not stand. The caller has read the row live.
///
/// # Errors
///
/// A store read failure (an engine-default row's Steward reach, [`derived_row`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn grant_row_in_fold(
    store: &Store,
    fold: &AuthorityFold,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &[u8],
    shared_scope: Option<&FederationGrantScope>,
    owners: &[EntityId],
    now: u64,
) -> Result<Option<SharedGrantRow>> {
    let read = grant_row_at(store, fold, txn, id, body, shared_scope, Some(now))?;
    let live_owner = read.holder().is_some_and(|holder| owners.contains(holder));
    Ok(read.into_row(live_owner))
}

/// What [`grant_row_at`] reads a row as: a read, or an own-device Grant no counted act
/// names, which stands while the fold names its holder a live Owner of the vault. The
/// caller asks that, from the owner set it holds or reads.
enum RowRead {
    /// The row's read: standing, derived or nothing.
    Read(Option<SharedGrantRow>),
    /// An own-device Grant ([`super::is_provisioned_own_device_row`]) no counted act names.
    OwnDevice(EntityId, FederationGrant),
}

impl RowRead {
    /// The holder whose Owner standing the read waits on: `Some` for an own-device Grant.
    fn holder(&self) -> Option<&EntityId> {
        match self {
            Self::Read(_) => None,
            Self::OwnDevice(_, grant) => Some(&grant.member_ref),
        }
    }

    /// The read, an own-device Grant standing when `live_owner` says the fold names its
    /// holder a live Owner of the vault.
    fn into_row(self, live_owner: bool) -> Option<SharedGrantRow> {
        match self {
            Self::Read(row) => row,
            Self::OwnDevice(id, grant) => live_owner.then_some(SharedGrantRow::Derived(id, grant)),
        }
    }
}

/// [`grant_row_in_fold`] with expiry read at `now`, or none read (`None`), before the
/// own-device Grant's holder is judged.
fn grant_row_at(
    store: &Store,
    fold: &AuthorityFold,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &[u8],
    shared_scope: Option<&FederationGrantScope>,
    now: Option<u64>,
) -> Result<RowRead> {
    let Ok((grant, terms_key)) = decode_federation_grant_body_keyed(body) else {
        return Ok(RowRead::Read(None));
    };
    let owner_mint = is_owner_mint_row(&grant);
    // The own-device residence is a `Vault` scope too, so the row's scope shape alone never
    // tells a member row from a personal vault's row.
    if shared_scope == Some(&grant.scope) {
        return Ok(RowRead::Read(shared_grant_row_decoded(
            store, fold, txn, id, grant, terms_key, now,
        )?));
    }
    // No mint carries its row's residence, and every writer puts this vault's own: the shared
    // scope above, else the own-device residence ([`owner_agent_mint_in_fold`]). A mint's row
    // put back over another scope stands for nothing (review #8943 P1-1), whether its shape
    // names the mint or only its counted line does: a Steward mint holding `read` is neither
    // an `owner_agent` row nor an `engine.controls` one (review #8943, Astra P1).
    if (owner_mint || given_by_owner_mint(fold, id))
        && (shared_scope.is_some() || grant.scope != own_device_residence_scope())
    {
        return Ok(RowRead::Read(None));
    }
    if owner_mint || grant.role == FederationGrantRole::Guest {
        let families = if owner_mint {
            &[GrantFamily::OwnerAgent][..]
        } else {
            guest_row_families(&grant)
        };
        return Ok(RowRead::Read(
            StandingGrant::decoded_in_fold(fold, id, grant, terms_key, families, now)
                .map(SharedGrantRow::Standing),
        ));
    }
    // The engine stands a base agent's default at the vault's root: the own-device residence
    // on a personal vault, where the row stays once the vault is shared.
    derived_row(
        store,
        fold,
        txn,
        id,
        grant,
        terms_key,
        &own_device_residence_scope(),
        now,
    )
}

/// Whether the stored body `body` decodes to an own-device row over `scope`, which no owner's
/// mint gives.
fn is_own_device_row_at(body: &[u8], scope: &FederationGrantScope) -> bool {
    decode_federation_grant_body_keyed(body).is_ok_and(|(grant, _)| {
        grant.scope == *scope && super::is_own_device_grant(&grant) && !is_owner_mint_row(&grant)
    })
}

/// Whether `grant` is the row of an owner's signed mint: an `owner_agent` row, a git push
/// Grant or an `engine.controls` Grant ([`GrantFamily::OwnerAgent`]).
fn is_owner_mint_row(grant: &FederationGrant) -> bool {
    grant.owner_agent || grant.is_git_push() || super::is_engine_controls_grant(grant)
}

/// Whether the fold's line of the Grant row `id` was given by an owner's signed mint
/// ([`GrantFamily::OwnerAgent`]), whatever the row's shape says now: a Steward mint of any
/// verbs among them.
fn given_by_owner_mint(fold: &AuthorityFold, id: EntityId) -> bool {
    fold.grant_line(id)
        .is_some_and(|line| line.family == Some(GrantFamily::OwnerAgent))
}

/// A row over `residence` that is neither an owner's mint nor a guest's Grant, read as
/// derived (pass 28 R4; FIX [GRANT-UNACTED-ARM-WIDER-THAN-DERIVED]). A row a counted act
/// names stands only on that act's line, whatever its shape says now: a counted guest's row
/// re-put as a member row, or a member row re-put in a steward's shape, keeps its line's terms
/// and its end (review #8855 P1-1), and a line two families name, or only an end, gives it
/// nothing. Of a row no counted act names, only the two kinds no act gives stand, unexpired:
/// a base agent's engine-default Steward Grant within the build's default table
/// ([`super::is_engine_default_row`]), for the verbs its agent's Steward reach still gives
/// ([`engine_default_within_reach`]), and an own-device Grant as the pairing door provisions
/// it ([`super::is_provisioned_own_device_row`]), whose holder the caller judges, for no more
/// than the vault's Owner default gives now ([`own_device_within_default`]). Every other
/// row (a member, viewer or steward row put with no act, an own-device row widened past its
/// provisioned terms) stands for nothing.
///
/// # Errors
///
/// A store read failure (the Steward reach or the policy manifest, read in `txn`).
#[allow(clippy::too_many_arguments)]
fn derived_row(
    store: &Store,
    fold: &AuthorityFold,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    grant: FederationGrant,
    terms_key: Option<GrantTermsKey>,
    residence: &FederationGrantScope,
    now: Option<u64>,
) -> Result<RowRead> {
    if let Some(line) = fold.grant_line(id) {
        return Ok(RowRead::Read(line.family.and_then(|family| {
            StandingGrant::decoded_in_fold(fold, id, grant, terms_key, &[family], now)
                .map(SharedGrantRow::Standing)
        })));
    }
    if grant.scope != *residence || now.is_some_and(|now| expired(&grant, now)) {
        return Ok(RowRead::Read(None));
    }
    if super::is_engine_default_row(&grant) {
        return Ok(RowRead::Read(engine_default_within_reach(
            store, txn, id, grant,
        )?));
    }
    if super::is_provisioned_own_device_row(&grant) {
        return own_device_within_default(store, txn, id, grant);
    }
    Ok(RowRead::Read(None))
}

/// An own-device row `grant` at `id`, which no act gives, read for the meet of its stored
/// authority scope with the vault's Owner default for its holder now, read in `txn`
/// ([`super::own_device::own_device_default_scope_in`], the scope the pairing door provisions;
/// FIX [OWN-DEVICE-ROW-SCOPE-NOT-BOUND-BY-OWNER-DEFAULT]). No act commits to the stored scope,
/// so a row re-put wider than its pairing confers only the default, and the owner's narrowing
/// of the default reaches every device paired before it; a widening never widens a stored row.
/// Nothing when the vault's policy resolves no Owner default, or when the meet confers nothing,
/// as the pairing door then provisions nothing. A provisioned row never expires.
fn own_device_within_default(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    mut grant: FederationGrant,
) -> Result<RowRead> {
    let Some(default) =
        super::own_device::own_device_default_scope_in(store, txn, grant.member_ref)?
    else {
        return Ok(RowRead::Read(None));
    };
    grant.authority_scope = grant.authority_scope.meet(&default);
    if !FederationGrant::scope_confers_at(&grant.authority_scope, grant.kind, None, 0) {
        return Ok(RowRead::Read(None));
    }
    Ok(RowRead::OwnDevice(id, grant))
}

/// A base agent's engine-default row `grant` at `id`, which no act gives, read for the meet
/// with its agent's Steward reach in `txn` ([`super::steward_reach_in`], the meet every
/// Steward use reads; Engine RULING R4-DEFAULT-END-AFTER-WHOLE-REVOKE = C): the verbs every
/// standing row gives, and each data axis no wider than any standing row holds it. Every row
/// that stands naming the agent counts in that meet, this one among them, so a row no act
/// gives can only narrow it: after the owner's whole revoke, the opt-out's row gives no verb,
/// and a default-shape row put after it gives none at any reader; after a narrowing it gives
/// only the verbs the owner kept; and it reaches no record the standing rows do not reach
/// together (the policy scope the engine stood its default under among them). `None` when the
/// meet leaves it no verb.
fn engine_default_within_reach(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    mut grant: FederationGrant,
) -> Result<Option<SharedGrantRow>> {
    let Some(reach) = super::steward_reach_in(store, txn, grant.member_ref)? else {
        return Ok(None);
    };
    let ScopeAxis::Some(verbs) = &grant.authority_scope.verbs else {
        return Ok(None);
    };
    let met: ScopeAxis<String> = verbs.intersection(&reach.verbs).cloned().collect();
    if met.is_bottom() {
        return Ok(None);
    }
    let mut scope = grant.authority_scope.meet(&reach.scope);
    scope.verbs = met;
    grant.authority_scope = scope;
    Ok(Some(SharedGrantRow::Derived(id, grant)))
}

/// The Grant row `id` of `family` as `fold` stands behind it at `now`, read in `txn`
/// ([`Vault::standing_grant_in_txn`] over a fold the caller holds, for a reader that reads
/// many rows under one fold).
///
/// # Errors
///
/// A store read failure; never a row that does not stand.
pub(crate) fn standing_grant_in_fold(
    store: &Store,
    fold: &AuthorityFold,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    family: GrantFamily,
    now: u64,
) -> Result<Option<StandingGrant>> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = live_entity_row_in_txn(store, txn, &id)?
    else {
        return Ok(None);
    };
    Ok(StandingGrant::in_fold(fold, id, &body, &[family], now))
}

fn shared_grant_row_decoded(
    store: &Store,
    fold: &AuthorityFold,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    grant: FederationGrant,
    terms_key: Option<GrantTermsKey>,
    now: Option<u64>,
) -> Result<Option<SharedGrantRow>> {
    Ok(match shared_row_families(&grant) {
        // A base agent's Steward row: the engine stands its default at the shared scope once
        // the vault is shared, and no own-device Grant is a Steward row.
        None => {
            let residence = grant.scope.clone();
            derived_row(store, fold, txn, id, grant, terms_key, &residence, now)?.into_row(false)
        }
        Some(families) => StandingGrant::decoded_in_fold(fold, id, grant, terms_key, families, now)
            .map(SharedGrantRow::Standing),
    })
}

impl Vault {
    /// What the Grant row `id` of `family` confers at `now`, read in `txn`: the row, when it
    /// is live, decodes, has not expired, is given in `family` and is exactly what the one
    /// counted act that gives it states (a general grant act's commitment opens with the row's
    /// own terms key), and no counted act ended it. `None` for every other row: one no counted
    /// act gives (a forged row), one put again after its end, one whose terms are not its
    /// act's, one that two acts the fold cannot order both give, and one given in another
    /// family.
    ///
    /// The reader names the family it reads and judges the giver by that family's own rule.
    /// A row's shape does not tell its family (a house link and a member row are both
    /// `FederationGrant::new` rows; a base agent's Steward Grant and a house's steward link
    /// can match), so the family is the act's, never the row's.
    ///
    /// # Errors
    ///
    /// A store or authority-fold read failure; never a row that does not stand.
    pub(crate) fn standing_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        family: GrantFamily,
        now: u64,
    ) -> Result<Option<StandingGrant>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        standing_grant_in_fold(&self.store, &fold, txn, id, family, now)
    }

    /// The guest Grant row `id` as the verified fold stands behind it at `now`, read in `txn`
    /// ([`guest_grant_in_fold`] over this vault's fold); `None` for a row that does not stand.
    ///
    /// # Errors
    ///
    /// A store or authority-fold read failure; never a row that does not stand.
    pub(crate) fn guest_grant_standing_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        now: u64,
    ) -> Result<Option<StandingGrant>> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(None);
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        Ok(guest_grant_in_fold(&fold, id, &body, now))
    }

    /// Whether a counted act of `family` gives the live Grant row `id` and states it term for
    /// term, while no counted act ended its line: an act door's check before it gives the row
    /// again (pass 28 R3c). It asks no expiry and no pact, so an owner's rewrite of an inquiry
    /// edge's terms runs before the company accepts its pact, as it did; a row no counted act
    /// gives, or one widened in place, is no Grant of his to give again.
    ///
    /// # Errors
    ///
    /// A store or authority-fold read failure.
    pub(crate) fn grant_row_given_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        family: GrantFamily,
    ) -> Result<bool> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(false);
        };
        let Ok((grant, terms_key)) = decode_federation_grant_body_keyed(&body) else {
            return Ok(false);
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        Ok(given_in_fold(&fold, id, &grant, terms_key.as_ref(), &[family]).is_some())
    }

    /// What the live Grant row `id`, whose stored body is `body`, confers at `now` as
    /// [`grant_row_in_fold`] reads it under this vault's fold: a row a counted act names stands
    /// only on that act's line, whatever its shape says now, so a counted guest's row re-put as
    /// a member or own-device row keeps its line's terms and its end (review #8855 P1-1); a row
    /// no counted act names stands only as derived (pass 28 R4), an own-device Grant while the
    /// fold names its holder a live Owner of the vault. The vault's owners are read only for an
    /// own-device Grant.
    ///
    /// # Errors
    ///
    /// A store, authority-fold or owner-census read failure.
    pub(crate) fn grant_row_at_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        body: &[u8],
        now: u64,
    ) -> Result<Option<SharedGrantRow>> {
        let shared_scope = self.shared_vault_scope_in_txn(txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let read = grant_row_at(
            &self.store,
            &fold,
            txn,
            id,
            body,
            shared_scope.as_ref(),
            Some(now),
        )?;
        self.derived_read_in_txn(txn, read)
    }

    /// Whether the live Grant row `id`, whose stored body is `body`, stands at `now`
    /// ([`Self::grant_row_at_in_txn`]).
    ///
    /// # Errors
    ///
    /// A store, authority-fold or owner-census read failure.
    pub(crate) fn grant_row_stands_at_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        body: &[u8],
        now: u64,
    ) -> Result<bool> {
        Ok(self.grant_row_at_in_txn(txn, id, body, now)?.is_some())
    }

    /// `read` resolved: an own-device Grant stands while the fold names its holder a live
    /// Owner of this vault ([`crate::policy_model::is_live_vault_owner_in_txn`]), read only
    /// for such a row.
    fn derived_read_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        read: RowRead,
    ) -> Result<Option<SharedGrantRow>> {
        let live_owner = match read.holder() {
            Some(holder) => crate::policy_model::is_live_vault_owner_in_txn(self, txn, holder)?,
            None => false,
        };
        Ok(read.into_row(live_owner))
    }

    /// Whether a counted act ended the line of Grant `id` (pass 28 R3c): a guest's revoke
    /// (`SlipGrantRevoke`), a membership withdrawal or a grant act's end, on every replica that
    /// folded it. A Grant whose line ended confers nothing, whatever its row says, and an end
    /// is forever. Until it counts, a reader of a withdrawal asks the end this install owes
    /// ([`super::grant_end_owed_in_txn`]); the two replace the local withdrawal marker.
    ///
    /// # Errors
    ///
    /// An authority-fold read failure.
    pub(crate) fn grant_line_ended_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
    ) -> Result<bool> {
        Ok(self
            .authority_view_readonly_in_txn(txn)?
            .grant_line(id)
            .is_some_and(|line| line.ended))
    }

    /// Whether the live Grant row `id` over a shared vault confers to a membership reader
    /// at the vault clock ([`shared_grant_row_in_fold`]); false for any other row.
    ///
    /// # Errors
    ///
    /// A store or authority-fold read failure.
    pub(crate) fn shared_grant_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
    ) -> Result<bool> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(false);
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        Ok(shared_grant_row_in_fold(
            &self.store,
            &fold,
            txn,
            id,
            &body,
            self.store.clock.now_recorded_at(),
        )?
        .is_some())
    }

    /// Whether `fold` stands behind the live Grant row `id` of this vault's own store, whose
    /// stored body is `body` ([`grant_row_in_fold`] with this vault's shared scope), with its
    /// expiry not read: a door that judges expiry itself, after its other refusals, so a
    /// lapsed delegation still says so (the sync selector's doors, pass 28 R3d). False for a
    /// row no counted act gives, one put back after its end and one whose terms are not its
    /// act's; an own-device or engine-default row stands as derived (pass 28 R4), the
    /// own-device one while the fold names its holder a live Owner. The caller has read the
    /// row live.
    ///
    /// # Errors
    ///
    /// A store or owner-census read failure.
    pub(crate) fn grant_row_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        id: EntityId,
        body: &[u8],
    ) -> Result<bool> {
        Ok(self.conferred_grant_in_txn(txn, fold, id, body)?.is_some())
    }

    /// The terms the live Grant row `id` of this vault's own store, whose stored body is
    /// `body`, confers as `fold` stands behind it ([`Self::grant_row_stands_in_txn`]): the
    /// row's own terms, but an engine-default row's authority scope met with its agent's
    /// Steward reach (pass 28 R4, Engine RULING R4-DEFAULT-END-AFTER-WHOLE-REVOKE = C), and an
    /// own-device row's met with the vault's Owner default now ([`own_device_within_default`]). A
    /// door that judges by the row's authority scope reads it here, never from the stored
    /// body (review r4c P2-1..3). `None` for a row that stands for nothing.
    ///
    /// # Errors
    ///
    /// A store or owner-census read failure.
    pub(crate) fn conferred_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        id: EntityId,
        body: &[u8],
    ) -> Result<Option<FederationGrant>> {
        // The creation door does not reserve the residence's id: on a vault shared under it, a
        // device paired while the vault was personal keeps its own-device row at the shared
        // scope, and a selector over the residence reads that row as on a personal vault
        // (review #8943 P1-2). A reader of a member's role still reads every row at the shared
        // scope as a member row ([`grant_row_in_fold`]).
        let shared_scope = self
            .shared_vault_scope_in_txn(txn)?
            .filter(|scope| !is_own_device_row_at(body, scope));
        let read = grant_row_at(
            &self.store,
            fold,
            txn,
            id,
            body,
            shared_scope.as_ref(),
            None,
        )?;
        Ok(self
            .derived_read_in_txn(txn, read)?
            .map(|row| row.grant().clone()))
    }

    /// The scope of a Grant row over this vault as a shared vault: `Some` only when this vault
    /// is one. A personal vault's rows (an own-device Grant, the owner's agent Grants) carry
    /// the own-device residence scope, which is a `Vault` scope too, so a row's scope shape
    /// alone never tells a member row from them; only a row whose scope is this one is read as
    /// a member row ([`shared_grant_row_in_fold`]).
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub(crate) fn shared_vault_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<FederationGrantScope>> {
        Ok(self
            .shared_vault_creation_in_txn(txn)?
            .map(|creation| FederationGrantScope::vault(creation.vault_id)))
    }

    /// [`shared_vault_grants_for_store_in_txn`] over this vault's fold, at the vault clock.
    ///
    /// # Errors
    ///
    /// A store or authority-fold read failure.
    pub(crate) fn shared_vault_grants_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
    ) -> Result<Vec<SharedGrantRow>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        shared_vault_grants_for_store_in_txn(
            &self.store,
            &fold,
            txn,
            vault_id,
            self.store.clock.now_recorded_at(),
        )
    }
}
