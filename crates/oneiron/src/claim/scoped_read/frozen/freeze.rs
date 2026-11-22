//! [`FrozenReadLane::freeze`]: the saver's live lane, frozen when its work
//! is saved for later (OF-506), and the judgments only the freeze makes.

use super::super::{ScopedRead, ScopedReadActorKey};
use super::{FrozenReadLane, SavedCredential};
use crate::claim::world_access::WorldAuthoritySet;
use crate::error::{Error, Result};
use oneiron_authority::federation::{Scope, ScopeAxis};
use oneiron_records::claim::scoped_read::frozen::GUEST_LANE_NOT_SAVED;

impl FrozenReadLane {
    /// `lane`, frozen. A lane under no narrowing freezes as the principal's
    /// own, except under a credential that keeps its Scope at top
    /// (`keeps_top_scope`), whose credential's id stays with a top read
    /// Scope, under a key the access gate binds, that names no human class
    /// or whose actor is no live owner, which keeps its grant basis and its
    /// key's own Scope, if any (Sol F3 on #8061; F1/F2/F3 on #8065; FIX
    /// SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS, FIX
    /// OWNER-LANE-WITHOUT-CLASS-REBUILDS-AS-HUMAN), or under another
    /// credential that names a grant, whose id stays with no Scope
    /// ([`Self::reads_as_principal`]): each rebuild judges that grant (FIX
    /// OWN-DEVICE-GRANT-NOT-RECHECKED). Otherwise the
    /// credential's id, read Scope and records caveat, each agent Grant
    /// alternative alone, the asked worlds and the room facets are kept, and
    /// no Scope where the key held none. Such a lane also keeps its key's
    /// grant basis (`NativeReadBasis`). A key rebuilt from a frozen lane
    /// keeps the credential it carries (`SavedCredential`). A channel caveat the lane
    /// did not meet freezes as a Scope that reads nothing, as the live lane
    /// read nothing under it.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] for a lane whose bound has no frozen form,
    /// so dropping it would widen the saved read: a room turn, an audience
    /// or peer reads, a narrowed guest credential, whose grant's current
    /// Scope binds only through its proof (a key homed in no conversation of
    /// this vault is no such bound: the lane keeps its home), or a key bound
    /// by two credentials, as a frozen lane keeps one. A store failure
    /// reading the owner binding or the live-owner census.
    pub fn freeze(lane: &ScopedRead<'_>) -> Result<Self> {
        Self::freeze_judged(lane, None)
    }

    /// [`Self::freeze`] in the caller's snapshot `txn` of `lane`'s vault: a
    /// human key's live-owner census is read there, never in a snapshot of
    /// its own, which the thread holding `txn` cannot open (MDB_BAD_RSLOT).
    /// So a door that reads its reply in `txn` freezes its lane at the same
    /// instant (blind review P1 on #9864).
    ///
    /// # Errors
    /// As [`Self::freeze`].
    pub(crate) fn freeze_in(lane: &ScopedRead<'_>, txn: &heed::RoTxn<'_>) -> Result<Self> {
        Self::freeze_judged(lane, Some(txn))
    }

    /// [`Self::freeze`], the live-owner census read in `txn` when the caller
    /// holds one.
    fn freeze_judged(lane: &ScopedRead<'_>, txn: Option<&heed::RoTxn<'_>>) -> Result<Self> {
        let key = &lane.actor_key;
        if key.room_turn.is_some() || lane.audience.is_some() || !lane.peer_reads.is_empty() {
            return Err(Error::InvalidConfig(
                "a saved read lane carries no room turn, audience or peer read".into(),
            ));
        }
        let claims = key
            .proof
            .as_ref()
            .map(crate::authority::VerifiedSlip::claims);
        let mut records = claims
            .map(|claims| claims.records.clone())
            .unwrap_or_default();
        // A key rebuilt from a frozen lane holds its records caveat as a
        // bound, not in its proof: keep it, met with the proof's caveat. A
        // bound that meets to no row reads nothing.
        let mut bound_reads_nothing = false;
        if let Some(bound) = &key.record_bound {
            records = if records.is_empty() {
                bound.clone()
            } else {
                records.intersection(bound).cloned().collect()
            };
            bound_reads_nothing = records.is_empty();
        }
        let channel_refused = claims.is_some_and(|claims| !lane.credential_channel_allows(claims))
            || bound_reads_nothing;
        let scope_narrows = key.authority_scope().is_some_and(|scope| {
            Scope {
                verbs: ScopeAxis::All,
                ..scope.clone()
            } != Scope::top()
        });
        let worlds = key.worlds.as_ref().map(WorldAuthoritySet::scope_axis);
        let names_grant = claims.is_some_and(|claims| claims.grant_ref.is_some());
        // A credential whose principal's own key would regain what its key
        // lacked keeps its read Scope even at top; so does a rebuilt key
        // that carries a saved credential and a frozen Scope. A key rebuilt
        // from a narrowed lane carries that lane's credential whole
        // (`SavedCredential::Live`), even where its own proof is that
        // credential: frozen as its principal's own lane, it would regain
        // the owner standing its basis took away (blind review P1 on #8061).
        let rebuilt_from_narrowed = key.authority_scope().is_some()
            && key
                .saved_credentials
                .iter()
                .any(|credential| matches!(credential, SavedCredential::Live { .. }));
        let keeps_scope = rebuilt_from_narrowed
            || match &key.proof {
                Some(proof) => keeps_top_scope(key, proof),
                None => !key.saved_credentials.is_empty() && key.authority_scope().is_some(),
            };
        let narrows_beyond_home = scope_narrows
            || !records.is_empty()
            || channel_refused
            || worlds.is_some()
            || key.room_facets.is_some()
            || key.grant_alternatives().is_some();
        // A key homed in no conversation of this vault narrows too, so its
        // lane never freezes as its principal's own (RULING
        // SECREAD-HOME-READ-DOORS = B). The lane keeps that home whole
        // (`home_unnamed`), so the home alone never refuses a lane whose
        // credential names a grant: a delegate holding the owner's
        // transferred credential saves its work, home kept (FIX
        // HOMED-GRANT-CREDENTIAL-LANE-NOT-SAVED).
        let narrows = narrows_beyond_home || key.is_homed_unnamed();
        // A key under the access gate keeps its grant basis, whose
        // principal's rebuilt key would admit the unscoped rows it refused
        // (Sol F3 on #8061), the owner's floor under that gate among them
        // (Sol F3 on #8065). So does the key of every actor that is no live
        // owner: a lane with no basis rebuilds for such an asker under the
        // access gate, so the gate its key read under stands again only from
        // its basis (FIX SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS). So does
        // a live owner's key that names no human class: every rebuild from
        // the principal's row reads as a PERSON, human, so its class stands
        // again only from its basis (FIX
        // OWNER-LANE-WITHOUT-CLASS-REBUILDS-AS-HUMAN).
        let basis = key.native_read_basis();
        let keeps_basis = basis.closes_unscoped_rows()
            || (!keeps_scope && !narrows && !human_key_of_live_owner(lane, txn)?);
        // The lane stays bound to each credential a rebuilt key carries, and
        // to the proof's own unless the lane freezes as its principal's own
        // with no grant to judge. A credential that names a grant stands
        // only while the grant does: frozen as its holder's principal lane,
        // saved work read on after the grant was withdrawn (FIX
        // OWN-DEVICE-GRANT-NOT-RECHECKED). Each keeps the earlier end a caveat
        // set it, and an attenuated proof the end its caveats left it; one
        // credential held to two ends keeps the earlier (FIX
        // SAVED-LANE-OUTLIVES-CAVEAT-EXPIRY).
        let mut credentials: Vec<([u8; 32], Option<u64>)> = Vec::new();
        let mut bind = |id: [u8; 32], end: Option<u64>| match credentials
            .iter_mut()
            .find(|(bound, _)| *bound == id)
        {
            Some((_, kept)) => *kept = earlier_end(*kept, end),
            None => credentials.push((id, end)),
        };
        for credential in &key.saved_credentials {
            bind(credential.slip_id(), credential.expires_at());
        }
        if let Some(proof) = &key.proof
            && (names_grant || keeps_scope || keeps_basis || narrows)
        {
            let claims = proof.claims();
            bind(
                claims.slip_id,
                (!proof.is_unattenuated()).then_some(claims.expires_at),
            );
        }
        let (credential, credential_expires_at) = match credentials.as_slice() {
            [] => (None, None),
            [(credential, end)] => (Some(*credential), *end),
            _ => {
                return Err(Error::InvalidConfig(
                    "a saved read lane is bound by one credential".into(),
                ));
            }
        };
        if !keeps_scope && !keeps_basis && !narrows {
            // No Scope: a rebuild keeps the principal's own floor and owner
            // authority while the credential stands, past any end of its own
            // (FIX 3377).
            return Ok(Self {
                credential,
                ..Self::principal()
            });
        }
        if names_grant && narrows_beyond_home {
            return Err(Error::InvalidConfig(GUEST_LANE_NOT_SAVED.into()));
        }
        // The lane keeps the key's own Scope, and none where it held none:
        // every such lane keeps its grant basis, and a top Scope would stand
        // as read authority the live key lacked, a policy floor of its own
        // (Sol F1/F2 on #8065). Where no row binds a key's class, a key with
        // no Scope reads nothing, and one with a Scope reads what that Scope
        // admits (FIX FROZEN-LANE-FREEZES-ABSENT-AUTHORITY-AS-TOP). A key
        // agent Grants bind keeps each Grant's alternative, never their meet:
        // two Grants on disjoint worlds meet to no world, and saved work must
        // read what each one alone admits (FIX AGENT-GRAPHFS-GRANT-WORLDS).
        let (authority, grant_alternatives) = if channel_refused {
            (Some(Scope::default()), None)
        } else {
            (
                key.authority_scope().cloned(),
                key.grant_alternatives().map(<[Scope]>::to_vec),
            )
        };
        Ok(Self {
            credential,
            credential_expires_at,
            authority,
            grant_alternatives,
            records,
            worlds,
            room_facets: key.room_facets,
            home_unnamed: key.is_homed_unnamed(),
            native_basis: Some(basis),
            withheld: Vec::new(),
        })
    }
}

/// The earlier of two ends a credential is held to, either of which may be
/// unset.
fn earlier_end(first: Option<u64>, second: Option<u64>) -> Option<u64> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (first, second) => first.or(second),
    }
}

/// Whether a lane read under `proof` by `key` keeps its read Scope even at
/// top (PR 5614; FIX 14344, Astra F2 on #8029): `key` lacks the vault
/// owner's full floor, and its principal's own key would regain what it
/// lacked. A credential that names no grant keeps it so. So does one that
/// names a grant but failed the owner's own path (`credential_key.rs`): an
/// owner's attenuated credential, which kept only the owner's exemption,
/// one handed to another key, whose holder is a delegate, and one of
/// another actor class on its holder's PERSON. A guest's own credential
/// names a grant and holds no owner standing its principal's key could
/// regain, so it keeps no top Scope; its lane keeps its grant basis, as the
/// lane of every actor that is no live owner does (FIX
/// SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS).
fn keeps_top_scope(key: &ScopedReadActorKey, proof: &crate::authority::VerifiedSlip) -> bool {
    let claims = proof.claims();
    !key.reads_as_vault_owner()
        && (claims.grant_ref.is_none()
            || key.owner_exemption.is_some()
            || proof.is_transferred()
            || !matches!(claims.actor_class.as_deref(), None | Some("human")))
}

/// Whether `lane`'s key names the human class and its actor is a live owner
/// of its vault, judged in `txn`, the caller's snapshot, or in a snapshot of
/// its own when the caller holds none
/// (`ScopedReadActorKey::actor_is_live_owner_in`): only such a lane freezes
/// as its principal's own with no basis. A key that names no class, or
/// another, is no such key, whatever the census says of its actor (FIX
/// OWNER-LANE-WITHOUT-CLASS-REBUILDS-AS-HUMAN).
///
/// # Errors
/// A store failure opening the snapshot, reading the owner binding or the
/// live-owner census.
fn human_key_of_live_owner(lane: &ScopedRead<'_>, txn: Option<&heed::RoTxn<'_>>) -> Result<bool> {
    if lane.actor_key.actor_class() != Some("human") {
        return Ok(false);
    }
    match txn {
        Some(txn) => lane.actor_key.actor_is_live_owner_in(lane.vault, txn),
        None => {
            let txn = lane.vault.store.env.read_txn()?;
            lane.actor_key.actor_is_live_owner_in(lane.vault, &txn)
        }
    }
}
