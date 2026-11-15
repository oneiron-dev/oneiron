//! OF-506 (FIX 1857): a read lane frozen when work is saved for later, and
//! rebuilt each time that work reads.
//!
//! A saved question, or a queued summary, reads long after the caller that
//! saved it has gone, and no credential travels with it. [`FrozenReadLane`]
//! keeps the SCOPE the saver's live lane read under: its credential's id,
//! read Scope and records caveat, each agent Grant alternative that bound
//! it, the worlds it asked for and the room whose facets bound it. It never
//! keeps a proof: nothing here deserializes into a
//! `VerifiedSlip`, and a frozen lane authorizes nothing on its own.
//!
//! Each rebuild ([`FrozenReadLane::narrow_in_txn`]) starts from the
//! principal's own live key and only narrows it, so a rebuilt lane is the
//! frozen scope met with live authority: the credential must still be live
//! in the rebuild's snapshot (unexpired, unrevoked, its grant, invitation
//! and delegation standing), the owner exemption is proved again on every
//! read, and the principal's relationship grants are read live. A revocation
//! after the save therefore never widens what the work reads. A lane that
//! read under no narrowing freezes as its principal's own
//! ([`FrozenReadLane::principal`]), unless its credential's native key lacks
//! the owner's full floor and its principal's own key would regain what it
//! lacked (that lane keeps its credential and a top read Scope), or its
//! credential names a grant: that lane still reads as its principal's own,
//! with no Scope, but stays held to the credential while the grant stands
//! ([`FrozenReadLane::reads_as_principal`]), so a rebuild after the grant is
//! withdrawn reads nothing (FIX OWN-DEVICE-GRANT-NOT-RECHECKED). A lane that
//! keeps a Scope also keeps the grant basis its live key read under
//! ([`NativeReadBasis`]), so a rebuild never regains the owner's floor or
//! exemption that key lacked (FIX 14344). Only a live owner's lane freezes
//! with no basis: the lane of any other actor keeps its key's basis, and a
//! lane with none, saved before the basis was kept or by an engine path
//! that froze no live lane, rebuilds for an asker that is no live owner
//! under the access gate (FIX SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS).
//!
//! A rebuilt key carries the lane's credential ([`SavedCredential`]), and
//! every read under it judges that credential again in its own snapshot: a
//! key rebuilt while the credential held and kept past its withdrawal reads
//! nothing, and freezing that key again keeps the credential.
//!
//! Sight is never frozen: a door that serves a secret derives it again from
//! the rebuilt lane.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::*;
use crate::claim::world_access::WorldAuthoritySet;
use oneiron_authority::federation::{Scope, ScopeAxis, ScopeId};

/// [`FrozenReadLane::freeze`]'s refusal of a narrowed guest credential's lane.
const GUEST_LANE_NOT_SAVED: &str = "a narrowed guest credential's read lane is not saved";

/// The credential a saved lane froze, as a key rebuilt from that lane
/// carries it with no proof (OF-506): every read under the key judges it
/// again in its own snapshot (`ScopedRead::proof_live_in`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SavedCredential {
    /// A narrowed lane's credential: it holds while it is live, that is
    /// unexpired, unrevoked and its grant, invitation and delegation
    /// standing (`Vault::capability_slip_id_is_live_in_txn`).
    Live([u8; 32]),
    /// The credential of a lane that reads as its principal's own
    /// ([`FrozenReadLane::reads_as_principal`]): it holds while it is
    /// unrevoked and its grant, invitation and delegation stand, past its
    /// own expiry (`Vault::capability_slip_id_stands_in_txn`). A paired
    /// device's renewal lets the old credential run out (FIX 3377), so its
    /// expiry ends no saved work; the grant's withdrawal does.
    Standing([u8; 32]),
}

impl SavedCredential {
    /// The credential's slip id.
    #[must_use]
    pub(crate) fn slip_id(self) -> [u8; 32] {
        match self {
            Self::Live(id) | Self::Standing(id) => id,
        }
    }

    /// Whether this credential still holds in `txn`.
    ///
    /// # Errors
    /// A store, fold or clock failure judging it.
    pub(crate) fn holds_in(self, vault: &crate::Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        match self {
            Self::Live(id) => vault.capability_slip_id_is_live_in_txn(txn, &id),
            Self::Standing(id) => vault.capability_slip_id_stands_in_txn(txn, &id),
        }
    }
}

/// The grant basis a saved lane's live key read under (FIX 14344, Astra F2
/// on #8029), kept beside its frozen Scope as a queued summary's
/// declaration keeps it (`requester_owner_exemption`,
/// `requester_relationship_grants`), or alone on a lane under the access
/// gate (Sol F3 on #8061) and on the lane of an actor that is no live owner
/// (FIX SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS). A rebuild over the
/// principal's own key, or over a current caller's, reads under the meet of
/// that key and this basis (`ScopedReadActorKey::within_native_basis`): it
/// never regains an owner standing the live key lacked, nor reads a row
/// either gate refused (Sol R1/R2 on #8061).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeReadBasis {
    /// The owner standing the live key held. Each read still proves the
    /// owner binding again.
    pub(crate) owner_standing: NativeOwnerStanding,
    /// The grant gate the live key read under.
    pub(crate) grant_gate: NativeGrantGate,
    /// The principal on whose grants that gate admitted a row; `None` under
    /// no gate, and under a gate bound to no principal, which admitted no
    /// row on a grant (Sol F5 on #8065).
    pub(crate) grant_principal: Option<EntityId>,
}

/// The owner standing a saved lane's live key held ([`NativeReadBasis`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeOwnerStanding {
    /// Neither the owner's floor nor an owner exemption: a delegate's key,
    /// or any other holder's.
    Absent,
    /// A narrower credential's owner exemption, never the owner's floor:
    /// the owner's own attenuated credential (Sol F1 on #8061).
    Exemption,
    /// The vault owner's full floor. An exemption beside it is not
    /// recorded, so a gate the floor read under binds its rebuild for every
    /// row (Sol R2 on #8061).
    Floor,
}

/// The grant gate a saved lane's live key read under ([`NativeReadBasis`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeGrantGate {
    /// No grant gate: the owner's floor, or a key no gate binds, which read
    /// every unscoped row its policy admitted (Sol F7 on #8061).
    Ungated,
    /// The relationship-only gate: a relationship's rows pass on the
    /// principal's grants, unscoped rows stay readable.
    Relationship,
    /// The access gate, which also closes every unscoped MESSAGE and
    /// SUMMARY.
    Access,
}

impl NativeReadBasis {
    /// Whether this is the access gate (Sol F3 on #8061 and on #8065): such
    /// a key refused the unscoped MESSAGE and SUMMARY rows its principal's
    /// own rebuilt key admits under the relationship gate, so its lane keeps
    /// this basis, and each rebuild refuses them again. The owner's floor
    /// under the access gate refused them too: the floor passes the policy
    /// check, not the grant gate.
    fn closes_unscoped_rows(self) -> bool {
        self.grant_gate == NativeGrantGate::Access
    }
}

/// The scope a read lane read under when its work was saved (OF-506). The
/// engine mints it from the saver's live lane ([`Self::freeze`]) or as the
/// principal's own ([`Self::principal`]); no caller authors one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenReadLane {
    /// The id of the credential that bounds the saved lane. Every rebuild
    /// reads nothing once it is no longer live. `None` on a lane no
    /// credential bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential: Option<[u8; 32]>,
    /// The read Scope the saved lane was held to, as every read door checks
    /// a credential's; `None` on a lane held to none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<Scope>,
    /// Set only on a lane the owner's agent Grants naming its credential's
    /// holder bound (FIX AGENT-GRAPHFS-GRANT-WORLDS): the credential's Scope
    /// met with each Grant that stood for `read` at the save, each alone.
    /// `authority` holds their envelope, and a rebuilt key reads a row only
    /// inside one of them, as the saving key did. Empty: none stood, and
    /// the lane reads nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant_alternatives: Option<Vec<Scope>>,
    /// The credential's records caveat, as entity ids in hex; empty when it
    /// named none.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    records: BTreeSet<String>,
    /// The worlds the saved lane asked for, as a Scope worlds axis; `None`
    /// when it asked for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worlds: Option<ScopeAxis<ScopeId>>,
    /// The room whose signed facets the saved lane read inside (FIX 643).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    room_facets: Option<EntityId>,
    /// The grant basis the saved lane's live key read under (FIX 14344):
    /// kept on every lane that keeps a Scope, and on a lane under the access
    /// gate or of an actor that is no live owner, which keeps no Scope its
    /// live key lacked (Sol F1/F2/F3 on #8065; FIX
    /// SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS). `None` on a live owner's
    /// lane that reads as its principal's own, and on one saved before the
    /// basis was kept, which rebuilds under the access gate for an asker
    /// that is no live owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_basis: Option<NativeReadBasis>,
    /// The fields a narrower reader's view of this lane withheld a row or a
    /// scope id from (FIX 12171, 12285), by name: `records` when the caveat
    /// names a row that reader does not read, `room_facets` when it does not
    /// read the room, and `authority.worlds`, `authority.facets`,
    /// `authority.audience`, `grant_alternatives.worlds`,
    /// `grant_alternatives.facets`, `grant_alternatives.audience` or
    /// `worlds` when that axis names an id the reader's own lane does not
    /// cover. Empty on every saved or rebuilt
    /// lane: only [`Self::reader_view`] fills it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    withheld: Vec<String>,
}

impl FrozenReadLane {
    /// The principal's own lane: no narrowing beyond the principal's live
    /// authority. An engine-built record that no caller's lane saved (a
    /// question created or edited with no lane, an internal one-off ask, a
    /// review's dissent question) keeps it, and so does an un-narrowed key of
    /// a live owner. Each rebuild reads as the principal's own only for an
    /// asker that is a live owner, and under the access gate for any other
    /// (FIX SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS).
    #[must_use]
    pub fn principal() -> Self {
        Self::default()
    }

    /// Whether this is the principal's own lane ([`Self::principal`]).
    #[must_use]
    pub fn is_principal(&self) -> bool {
        *self == Self::default()
    }

    /// Whether this lane reads as its principal's own: [`Self::principal`],
    /// or that lane held only to a credential that must still stand (FIX
    /// OWN-DEVICE-GRANT-NOT-RECHECKED). An unrestricted live owner's lane
    /// whose credential names a grant freezes so: it keeps no Scope, so a
    /// rebuild keeps its principal's own floor and owner authority while the
    /// grant stands, and reads nothing once it does not.
    #[must_use]
    pub fn reads_as_principal(&self) -> bool {
        Self {
            credential: None,
            ..self.clone()
        }
        .is_principal()
    }

    /// The credential each rebuild of this lane, and each read under the
    /// rebuilt key, judges: whole on a narrowed lane, by its standing on one
    /// that reads as its principal's own.
    fn saved_credential(&self) -> Option<SavedCredential> {
        self.credential.map(|id| {
            if self.reads_as_principal() {
                SavedCredential::Standing(id)
            } else {
                SavedCredential::Live(id)
            }
        })
    }

    /// `lane`, frozen. A lane under no narrowing freezes as the principal's
    /// own, except under a credential that keeps its Scope at top
    /// (`keeps_top_scope`), whose credential's id stays with a top read
    /// Scope, under a key the access gate binds or whose actor is no live
    /// owner, which keeps its grant basis and its key's own Scope, if any
    /// (Sol F3 on #8061; F1/F2/F3 on #8065; FIX
    /// SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS), or under another
    /// credential that names a grant, whose id stays with no Scope
    /// ([`Self::reads_as_principal`]): each rebuild judges that grant (FIX
    /// OWN-DEVICE-GRANT-NOT-RECHECKED). Otherwise the
    /// credential's id, read Scope and records caveat, each agent Grant
    /// alternative alone, the asked worlds and the room facets are kept. A
    /// lane that keeps a Scope also keeps its key's grant basis
    /// (`NativeReadBasis`). A key rebuilt from a frozen lane keeps the
    /// credential it carries (`SavedCredential`). A channel caveat the lane
    /// did not meet freezes as a Scope that reads nothing, as the live lane
    /// read nothing under it.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] for a lane whose bound has no frozen form,
    /// so dropping it would widen the saved read: a room turn, an audience
    /// or peer reads, a narrowed guest credential, whose grant's current
    /// Scope binds only through its proof, or a key bound by two
    /// credentials, as a frozen lane keeps one. A store failure reading the
    /// owner binding or the live-owner census.
    pub fn freeze(lane: &ScopedRead<'_>) -> Result<Self> {
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
                .any(|credential| matches!(credential, SavedCredential::Live(_)));
        let keeps_scope = rebuilt_from_narrowed
            || match &key.proof {
                Some(proof) => keeps_top_scope(key, proof),
                None => !key.saved_credentials.is_empty() && key.authority_scope().is_some(),
            };
        let narrows = scope_narrows
            || !records.is_empty()
            || channel_refused
            || worlds.is_some()
            || key.room_facets.is_some()
            || key.grant_alternatives().is_some();
        // A key under the access gate keeps its grant basis, whose
        // principal's rebuilt key would admit the unscoped rows it refused
        // (Sol F3 on #8061), the owner's floor under that gate among them
        // (Sol F3 on #8065). So does the key of every actor that is no live
        // owner: a lane with no basis rebuilds for such an asker under the
        // access gate, so the gate its key read under stands again only from
        // its basis (FIX SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS).
        let basis = key.native_read_basis();
        let keeps_basis = basis.closes_unscoped_rows()
            || (!keeps_scope && !narrows && !actor_is_live_owner(lane)?);
        // The lane stays bound to each credential a rebuilt key carries, and
        // to the proof's own unless the lane freezes as its principal's own
        // with no grant to judge. A credential that names a grant stands
        // only while the grant does: frozen as its holder's principal lane,
        // saved work read on after the grant was withdrawn (FIX
        // OWN-DEVICE-GRANT-NOT-RECHECKED).
        let mut credentials: Vec<[u8; 32]> = key
            .saved_credentials
            .iter()
            .copied()
            .map(SavedCredential::slip_id)
            .collect();
        if let Some(claims) = claims
            && (names_grant || keeps_scope || keeps_basis || narrows)
            && !credentials.contains(&claims.slip_id)
        {
            credentials.push(claims.slip_id);
        }
        let credential = match credentials.as_slice() {
            [] => None,
            [credential] => Some(*credential),
            _ => {
                return Err(Error::InvalidConfig(
                    "a saved read lane is bound by one credential".into(),
                ));
            }
        };
        if !keeps_scope && !keeps_basis && !narrows {
            // No Scope: a rebuild keeps the principal's own floor and owner
            // authority while the credential stands.
            return Ok(Self {
                credential,
                ..Self::principal()
            });
        }
        if names_grant && narrows {
            return Err(Error::InvalidConfig(GUEST_LANE_NOT_SAVED.into()));
        }
        // A key agent Grants bind keeps each Grant's alternative, never their
        // meet: two Grants on disjoint worlds meet to no world, and saved work
        // must read what each one alone admits (FIX AGENT-GRAPHFS-GRANT-WORLDS).
        let (authority, grant_alternatives) = if channel_refused {
            (Some(Scope::default()), None)
        } else if keeps_scope || narrows {
            (
                Some(key.authority_scope().cloned().unwrap_or_else(Scope::top)),
                key.grant_alternatives().map(<[Scope]>::to_vec),
            )
        } else {
            // Kept for its grant basis alone, with the key's own Scope, if
            // any: a top Scope would stand as read authority the live key
            // lacked, a policy floor of its own and no own Grant alternative
            // (Sol F1/F2 on #8065).
            (key.authority_scope().cloned(), None)
        };
        Ok(Self {
            credential,
            authority,
            grant_alternatives,
            records,
            worlds,
            room_facets: key.room_facets,
            native_basis: Some(basis),
            withheld: Vec::new(),
        })
    }

    /// The rows this lane names (FIX 12171): each row its records caveat
    /// names, then the room whose facets bound it. A caveat entry that is no
    /// entity id names no row.
    #[must_use]
    pub fn named_rows(&self) -> Vec<EntityId> {
        self.records
            .iter()
            .filter_map(|row| EntityId::from_hex(row).ok())
            .chain(self.room_facets)
            .collect()
    }

    /// This lane as a narrower lane of its principal reads it (FIX 12171,
    /// 12285), `reads` answering for each row [`Self::named_rows`] names and
    /// `bound` for the scope ids, the reader's own lane bound
    /// ([`ScopedRead::refs_readable_each_with_scope_id_bound`]): the records
    /// caveat keeps the rows the reader reads, and the room stays while the
    /// reader reads it. The worlds, facets and audience axes of the read
    /// Scope and of each frozen agent Grant alternative, and the asked
    /// worlds, keep each id `bound` covers on that axis; base
    /// reality is the base world id there, so it stays while the reader
    /// reads base. An open or empty axis names no id and stays as it is.
    /// Each field that lost a row or an id is named in `withheld`, so an
    /// emptied caveat never reads as no caveat. The credential id stays, so
    /// a narrowed lane still reads as narrowed. The answer is a reply's
    /// view: no rebuild narrows by it.
    #[must_use]
    pub fn reader_view(&self, reads: impl Fn(&EntityId) -> bool, bound: &Scope) -> Self {
        let mut lane = self.clone();
        lane.records
            .retain(|row| EntityId::from_hex(row).is_ok_and(|id| reads(&id)));
        if lane.records.len() < self.records.len() {
            lane.withheld.push("records".to_owned());
        }
        if lane.room_facets.is_some_and(|room| !reads(&room)) {
            lane.room_facets = None;
            lane.withheld.push("room_facets".to_owned());
        }
        if let Some(authority) = &mut lane.authority {
            for (field, axis, covered) in [
                ("authority.worlds", &mut authority.worlds, &bound.worlds),
                ("authority.facets", &mut authority.facets, &bound.facets),
                (
                    "authority.audience",
                    &mut authority.audience,
                    &bound.audience,
                ),
            ] {
                if keep_covered_ids(axis, covered) {
                    lane.withheld.push(field.to_owned());
                }
            }
        }
        if let Some(alternatives) = &mut lane.grant_alternatives {
            let mut cut = BTreeSet::new();
            for alternative in alternatives.iter_mut() {
                for (field, axis, covered) in [
                    (
                        "grant_alternatives.worlds",
                        &mut alternative.worlds,
                        &bound.worlds,
                    ),
                    (
                        "grant_alternatives.facets",
                        &mut alternative.facets,
                        &bound.facets,
                    ),
                    (
                        "grant_alternatives.audience",
                        &mut alternative.audience,
                        &bound.audience,
                    ),
                ] {
                    if keep_covered_ids(axis, covered) {
                        cut.insert(field);
                    }
                }
            }
            lane.withheld.extend(cut.into_iter().map(str::to_owned));
        }
        if let Some(worlds) = &mut lane.worlds
            && keep_covered_ids(worlds, &bound.worlds)
        {
            lane.withheld.push("worlds".to_owned());
        }
        lane
    }

    /// Whether `error` is [`Self::freeze`]'s refusal of a narrowed guest
    /// credential's lane (FIX 12059), which a door that admitted that lane
    /// answers as its own typed record-scope refusal.
    #[must_use]
    pub fn is_guest_lane_refusal(error: &Error) -> bool {
        matches!(error, Error::InvalidConfig(message) if message.as_str() == GUEST_LANE_NOT_SAVED)
    }

    /// `key`, the principal's own live key, narrowed by this frozen lane in
    /// `txn`: held to the saved key's grant basis, the frozen Scope, records
    /// caveat, worlds and room facets, each only narrowing. A lane whose credential no longer holds
    /// in `txn` (`SavedCredential`) reads nothing, and the rebuilt key
    /// carries that credential, so each later read judges it again in its
    /// own snapshot. The principal's own lane returns `key` unchanged, and a
    /// lane that reads as its principal's own
    /// ([`Self::reads_as_principal`]) returns it held to its credential
    /// alone, each while its asker is a live owner in `txn`; for any other
    /// asker either returns it under the access gate (FIX
    /// SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS).
    ///
    /// # Errors
    /// A store, fold or clock failure judging the credential or the asker's
    /// owner standing.
    pub fn narrow_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        key: ScopedReadActorKey,
    ) -> Result<ScopedReadActorKey> {
        if self.is_principal() {
            return rebuild_without_basis_in(vault, txn, key);
        }
        let saved = self.saved_credential();
        if let Some(credential) = saved
            && !credential.holds_in(vault, txn)?
        {
            return ScopedReadActorKey::read_nothing(
                key.actor_ref(),
                key.actor_class().unwrap_or_default(),
            )
            .ok_or(Error::InvariantViolation("frozen read lane actor"));
        }
        // A key held past this snapshot judges the credential at each read
        // (review R1 of #8029): rebuilt while it held, it reads nothing once
        // it no longer does. A key whose own proof is the credential of a
        // lane that reads as its principal's own already judges it at each
        // use. A narrowed lane's credential binds even a key whose proof
        // shares its id (a transferred credential keeps its mint's id), so
        // the rebuilt key, frozen again, keeps this lane's Scope and basis
        // (blind review P1 on #8061).
        let proof_id = key.proof.as_ref().map(|proof| proof.claims().slip_id);
        let mut key = match saved {
            Some(credential)
                if matches!(credential, SavedCredential::Live(_))
                    || proof_id != Some(credential.slip_id()) =>
            {
                key.bound_by_saved_credential(credential)
            }
            _ => key,
        };
        if self.reads_as_principal() {
            return rebuild_without_basis_in(vault, txn, key);
        }
        // The principal's own key never lends the rebuild an owner standing
        // the saved key lacked (FIX 14344, Astra F2 on #8029).
        if let Some(basis) = self.native_basis {
            key = key.within_native_basis(basis);
        }
        // A lane kept for its grant basis alone holds no Scope its live key
        // lacked (Sol F1/F2 on #8065); a lane saved before the basis was
        // kept reads under top.
        if self.authority.is_some() || self.native_basis.is_none() {
            key = key.within_authority(self.authority.clone().unwrap_or_else(Scope::top));
        }
        if let Some(alternatives) = &self.grant_alternatives {
            key = key.within_grant_alternatives(alternatives);
        }
        // The Grants of the save bind beside those of each snapshot that
        // serves a row: a Grant revoked or lapsed since the save narrows the
        // rebuilt lane (REVIEW-7051 P1). The principal is the credential's
        // holder; a principal no Grant has ever named is not narrowed.
        if (self.credential.is_some() || self.grant_alternatives.is_some())
            && let Ok(holder) = EntityId::from_hex(key.actor_ref())
        {
            key = key.bound_by_live_agent_grants(holder);
        }
        if !self.records.is_empty() {
            key = key.within_records(&self.records);
        }
        if let Some(worlds) = self
            .worlds
            .as_ref()
            .map(WorldAuthoritySet::from_scope_axis)
            .transpose()?
            .flatten()
        {
            key = key.within_worlds(worlds);
        }
        if let Some(room) = self.room_facets {
            key = key.within_room_facets(room);
        }
        Ok(key)
    }

    /// [`Self::narrow_in_txn`] in its own snapshot.
    ///
    /// # Errors
    /// As [`Self::narrow_in_txn`], and a store failure opening the snapshot.
    pub fn narrow(
        &self,
        vault: &crate::Vault,
        key: ScopedReadActorKey,
    ) -> Result<ScopedReadActorKey> {
        let txn = vault.store.env.read_txn()?;
        self.narrow_in_txn(vault, &txn, key)
    }
}

/// Keeps each id `axis` names that `covered` holds (FIX 12285); whether it
/// cut one. An open or empty axis names no id and stays; one cut to no id
/// is bottom.
fn keep_covered_ids(axis: &mut ScopeAxis<ScopeId>, covered: &ScopeAxis<ScopeId>) -> bool {
    let ScopeAxis::Some(ids) = axis else {
        return false;
    };
    let named = ids.len();
    ids.retain(|id| covered.contains(id));
    if ids.len() == named {
        return false;
    }
    if ids.is_empty() {
        *axis = ScopeAxis::Bottom;
    }
    true
}

impl ScopedRead<'_> {
    /// This lane, frozen ([`FrozenReadLane::freeze`]).
    ///
    /// # Errors
    /// As [`FrozenReadLane::freeze`].
    pub fn freeze(&self) -> Result<FrozenReadLane> {
        FrozenReadLane::freeze(self)
    }

    /// Which of `sets` resolve whole for this lane, as
    /// [`Self::refs_readable_each`] judges them, and the scope ids this
    /// lane's own bounds cover, both in one snapshot (FIX 12285): what a
    /// frozen lane of its principal's is viewed by
    /// ([`FrozenReadLane::reader_view`]). The bound is one Scope over the
    /// worlds, facets and audience axes, every other axis open: the worlds
    /// it asked for met with its credential's and a room turn's, base
    /// reality as the base world id there; its credential's facets met with
    /// a room turn's and a named room's as this snapshot finds them, open
    /// while its key reads past every facet (owner ruling FACET-READ = A);
    /// and its credential's audience. No row is judged for the bound.
    ///
    /// # Errors
    /// As [`Self::refs_readable_each`], and a store failure reading a
    /// room's facets or the owner exemption.
    pub fn refs_readable_each_with_scope_id_bound(
        &self,
        sets: &[Vec<EntityId>],
    ) -> Result<(Vec<bool>, Scope)> {
        let rtxn = self.grant_read_txn()?;
        let each = if sets.is_empty() {
            Vec::new()
        } else {
            self.refs_readable_each_in(&rtxn, sets)?
        };
        Ok((each, self.scope_id_bound_in(&rtxn)?))
    }

    /// This lane's own bound on the scope ids in `txn`; see
    /// [`Self::refs_readable_each_with_scope_id_bound`].
    fn scope_id_bound_in(&self, txn: &heed::RoTxn<'_>) -> Result<Scope> {
        let key = &self.actor_key;
        let mut bound = key.world_ceiling();
        if let Some(credential) = key.authority_scope() {
            bound.facets = credential.facets.clone();
            bound.audience = credential.audience.clone();
        }
        if let Some(turn) = &key.room_turn {
            let (worlds, facets) = turn
                .terms
                .with(|terms| (terms.worlds.worlds.clone(), terms.facets.clone()));
            let now = crate::context_board::room_facets_axis_in(self.vault, txn, turn.room)?;
            bound.worlds = bound.worlds.meet(&worlds);
            bound.facets = bound.facets.meet(&facets).meet(&now);
        }
        if let Some(room) = key.room_facets {
            let named = crate::context_board::room_facets_axis_in(self.vault, txn, room)?;
            bound.facets = bound.facets.meet(&named);
        }
        if key.facets_owner_exempt_in(self.vault, txn)? {
            bound.facets = ScopeAxis::All;
        }
        Ok(bound)
    }

    /// A frozen lane's records caveat on the row `id`: the rows a rebuilt
    /// key's records bound names, as a credential's records caveat holds
    /// them. A key with no records bound is unbound here.
    pub(super) fn record_bound_allows(&self, id: &EntityId) -> bool {
        self.actor_key
            .record_bound
            .as_ref()
            .is_none_or(|records| records.contains(&id.to_hex()))
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

/// `key`, its principal's own live key, rebuilt for a lane that keeps no
/// grant basis (FIX SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS): unchanged
/// while its actor is a live owner in `txn`
/// (`ScopedReadActorKey::actor_is_live_owner_in`), and otherwise met with
/// the access gate on the grants of the key's own principal, with no owner
/// standing. Such a lane does not say which gate its key read under: it was
/// saved before the basis was kept, or by an engine path that froze no live
/// lane (a question created or edited with no lane, an internal one-off
/// ask, a review's dissent question), so it fails closed. An access grant
/// on a row's conversation still admits that row.
///
/// # Errors
/// A store failure reading the owner binding or the live-owner census.
fn rebuild_without_basis_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    key: ScopedReadActorKey,
) -> Result<ScopedReadActorKey> {
    if key.actor_is_live_owner_in(vault, txn)? {
        return Ok(key);
    }
    let grant_principal = key.principal_ref;
    Ok(key.within_native_basis(NativeReadBasis {
        owner_standing: NativeOwnerStanding::Absent,
        grant_gate: NativeGrantGate::Access,
        grant_principal,
    }))
}

/// Whether `lane`'s actor is a live owner of its vault, judged in a snapshot
/// of its own (`ScopedReadActorKey::actor_is_live_owner_in`).
///
/// # Errors
/// A store failure opening the snapshot, reading the owner binding or the
/// live-owner census.
fn actor_is_live_owner(lane: &ScopedRead<'_>) -> Result<bool> {
    let txn = lane.vault.store.env.read_txn()?;
    lane.actor_key.actor_is_live_owner_in(lane.vault, &txn)
}
