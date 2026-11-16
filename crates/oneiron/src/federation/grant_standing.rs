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
//! commits to the row's terms under the row's own terms key; own-device and engine-default
//! Grants are read as derived in R4.

use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityFold, GrantFamily};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

use super::{
    FederationGrant, FederationGrantRole, FederationGrantScope, GrantTermsKey,
    decode_federation_grant_body_keyed,
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
        Self::decoded_in_fold(fold, id, grant, terms_key, families, now)
    }

    /// [`Self::in_fold`] for a body already decoded.
    fn decoded_in_fold(
        fold: &AuthorityFold,
        id: EntityId,
        grant: FederationGrant,
        terms_key: Option<GrantTermsKey>,
        families: &[GrantFamily],
        now: u64,
    ) -> Option<Self> {
        // Expiry alone: what a live Grant then confers (a verb, a class, a git push) is
        // its reader's, so `FederationGrant::is_live_at`, Access's predicate, is not
        // asked here (it refuses every git push Grant and a class-only scope).
        if grant.expires_at.is_some_and(|expires_at| now >= expires_at) {
            return None;
        }
        let act = given_in_fold(fold, id, &grant, terms_key.as_ref(), families)?;
        Some(Self { id, grant, act })
    }
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
/// push Grant or a Steward mint's row), holding `grant` under `terms_key`: the line is given
/// in [`GrantFamily::OwnerAgent`], no counted act ended it, and the mint states the row, term
/// for term. `None` for a row no counted mint gives, one put back after its revoke and one
/// whose terms are not its mint's. Expiry is the reader's: a lister of the owner's agent
/// Grants (backfill, a grantless agent, the default mint) asks which Grants name a holder,
/// expired or not, and each conferring reader reads the expiry at its own time.
#[must_use]
pub(crate) fn owner_agent_mint_in_fold(
    fold: &AuthorityFold,
    id: EntityId,
    grant: &FederationGrant,
    terms_key: Option<&GrantTermsKey>,
) -> Option<AuthorityEntryHash> {
    given_in_fold(fold, id, grant, terms_key, &[GrantFamily::OwnerAgent])
}

/// The families an act gives a Grant row over a shared vault in, read from the row's shape;
/// `None` for a row read from itself until its own pass 28 step: a base agent's
/// engine-default Steward Grant (R4) and a guest's Grant (R3 guests and slips).
///
/// The shape only narrows: the row stands only when its line was given in one of these
/// families, so a row whose shape names another family than its act stands for nothing.
/// A member row is a person's membership (SharedMember) or a house seated in its org at a
/// role by its binder (HouseLink), both `FederationGrant::new` rows. An owner's agent
/// Grant, a git push Grant and an `engine.controls` Grant are the owner's signed mints
/// (OwnerAgent); an admin's delegate is the Delegate family.
#[must_use]
pub(crate) fn shared_row_families(grant: &FederationGrant) -> Option<&'static [GrantFamily]> {
    if super::is_system_agent_steward_grant(grant) || grant.role == FederationGrantRole::Guest {
        return None;
    }
    const OWNER_MINT: &[GrantFamily] = &[GrantFamily::OwnerAgent];
    const DELEGATE: &[GrantFamily] = &[GrantFamily::Delegate];
    const MEMBER: &[GrantFamily] = &[GrantFamily::SharedMember, GrantFamily::HouseLink];
    Some(
        if grant.owner_agent || grant.is_git_push() || super::is_engine_controls_grant(grant) {
            OWNER_MINT
        } else if grant.role == FederationGrantRole::Delegate {
            DELEGATE
        } else {
            MEMBER
        },
    )
}

/// What a Grant row over a shared vault confers to a membership reader: a row the fold
/// stands behind ([`StandingGrant`]), or a row still read from itself
/// ([`shared_row_families`] `None`), which the reader judges as before pass 28 R3.
#[derive(Debug, Clone)]
pub(crate) enum SharedGrantRow {
    /// A row the verified fold stands behind.
    Standing(StandingGrant),
    /// A base agent's engine-default Steward Grant, a guest's Grant or (on an own-device
    /// residence, [`grant_row_in_fold`]) an own-device Grant, read from its row until its own
    /// pass 28 step.
    Unacted(EntityId, FederationGrant),
}

impl SharedGrantRow {
    /// The row's id and its Grant.
    pub(crate) fn into_parts(self) -> (EntityId, FederationGrant) {
        match self {
            Self::Standing(standing) => (standing.id, standing.grant),
            Self::Unacted(id, grant) => (id, grant),
        }
    }

    /// The FEDERATION_GRANT row's id.
    pub(crate) fn id(&self) -> EntityId {
        match self {
            Self::Standing(standing) => standing.id(),
            Self::Unacted(id, _) => *id,
        }
    }

    /// The Grant as its row holds it.
    pub(crate) fn grant(&self) -> &FederationGrant {
        match self {
            Self::Standing(standing) => standing.grant(),
            Self::Unacted(_, grant) => grant,
        }
    }
}

/// Every Grant row over shared vault `vault_id` in `txn` that confers at `now` to a
/// membership reader, in id order: each row the fold stands behind in its shape's families,
/// and each row [`shared_row_families`] still reads from itself. A row no counted act gives,
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
        rows.extend(shared_grant_row_decoded(fold, id, grant, terms_key, now));
    }
    Ok(rows)
}

/// What the live Grant row `id`, whose stored body is `body`, confers to a membership
/// reader at `now` under `fold` ([`shared_vault_grants_for_store_in_txn`] for one row whose
/// scope the caller has read): `None` for a row that does not stand. The caller has read
/// the row live.
#[must_use]
pub(crate) fn shared_grant_row_in_fold(
    fold: &AuthorityFold,
    id: EntityId,
    body: &[u8],
    now: u64,
) -> Option<SharedGrantRow> {
    let (grant, terms_key) = decode_federation_grant_body_keyed(body).ok()?;
    shared_grant_row_decoded(fold, id, grant, terms_key, now)
}

/// What the live Grant row `id` of this vault's own store, whose stored body is `body`,
/// confers at `now` under `fold`. A row over this shared vault (its scope is `shared_scope`,
/// [`Vault::shared_vault_scope_in_txn`]) reads as [`shared_grant_row_in_fold`] reads it. Of
/// every other row (an own-device residence row, a guest's Grant), an owner's signed mint
/// row (an `owner_agent` row, a git push Grant, an `engine.controls` Grant) stands only on
/// its counted mint, and the rest (an own-device or engine-default Grant, read as derived in
/// R4; a guest's Grant until R3c) read from themselves. `None` for a row that does not stand.
/// The caller has read the row live.
#[must_use]
pub(crate) fn grant_row_in_fold(
    fold: &AuthorityFold,
    id: EntityId,
    body: &[u8],
    shared_scope: Option<&FederationGrantScope>,
    now: u64,
) -> Option<SharedGrantRow> {
    let (grant, terms_key) = decode_federation_grant_body_keyed(body).ok()?;
    // The own-device residence is a `Vault` scope too, so the row's scope shape alone never
    // tells a member row from a personal vault's row.
    if shared_scope == Some(&grant.scope) {
        return shared_grant_row_decoded(fold, id, grant, terms_key, now);
    }
    let owner_mint =
        grant.owner_agent || grant.is_git_push() || super::is_engine_controls_grant(&grant);
    if owner_mint {
        return StandingGrant::decoded_in_fold(
            fold,
            id,
            grant,
            terms_key,
            &[GrantFamily::OwnerAgent],
            now,
        )
        .map(SharedGrantRow::Standing);
    }
    grant
        .expires_at
        .is_none_or(|expires_at| now < expires_at)
        .then_some(SharedGrantRow::Unacted(id, grant))
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
    fold: &AuthorityFold,
    id: EntityId,
    grant: FederationGrant,
    terms_key: Option<GrantTermsKey>,
    now: u64,
) -> Option<SharedGrantRow> {
    match shared_row_families(&grant) {
        None => grant
            .expires_at
            .is_none_or(|expires_at| now < expires_at)
            .then_some(SharedGrantRow::Unacted(id, grant)),
        Some(families) => StandingGrant::decoded_in_fold(fold, id, grant, terms_key, families, now)
            .map(SharedGrantRow::Standing),
    }
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
        Ok(
            shared_grant_row_in_fold(&fold, id, &body, self.store.clock.now_recorded_at())
                .is_some(),
        )
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
