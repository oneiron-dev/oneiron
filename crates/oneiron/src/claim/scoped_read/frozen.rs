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
//! under the access gate (FIX SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS). The
//! basis keeps the actor class that key was proved as, which policy rows
//! match on, or that it named none: a rebuild reads under it, never under
//! the class its principal's row type gives (FIX
//! SAVED-LANE-REBUILD-SUBSTITUTES-ACTOR-CLASS; round 2 review P1 of #9590).
//!
//! A rebuilt key carries the lane's credential ([`SavedCredential`]), and
//! every read under it judges that credential again in its own snapshot: a
//! key rebuilt while the credential held and kept past its withdrawal reads
//! nothing, and freezing that key again keeps the credential. A narrowed
//! lane also keeps the earlier end a caveat set its credential, which its
//! mint's liveness does not judge: from that end it reads nothing, as the
//! live proof did (FIX SAVED-LANE-OUTLIVES-CAVEAT-EXPIRY).
//!
//! Sight is never frozen: a door that serves a secret derives it again from
//! the rebuilt lane.

mod freeze;
mod rebuild;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::*;
use oneiron_authority::federation::{Scope, ScopeAxis, ScopeId};

#[doc(hidden)]
use oneiron_records::claim::scoped_read::frozen::{GUEST_LANE_NOT_SAVED, keep_covered_ids};

/// The credential a saved lane froze, as a key rebuilt from that lane
/// carries it with no proof (OF-506): every read under the key judges it
/// again in its own snapshot (`ScopedRead::proof_live_in`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SavedCredential {
    /// A narrowed lane's credential: it holds while it is live, that is
    /// unexpired, unrevoked and its grant, invitation and delegation
    /// standing, its read Scope inside its current membership grant
    /// (`Vault::saved_read_credential_is_live_in_txn`), and, when a
    /// caveat set it an earlier end than its mint's, before that end, as
    /// its live proof was held to it (FIX SAVED-LANE-OUTLIVES-CAVEAT-EXPIRY).
    Live {
        /// The credential's slip id.
        id: [u8; 32],
        /// The caveat's earlier end, in seconds on the vault's clock;
        /// `None` when the saved proof was its mint, which ends with it.
        expires_at: Option<u64>,
    },
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
            Self::Live { id, .. } | Self::Standing(id) => id,
        }
    }

    /// The earlier end a caveat set this credential, which a narrowed lane
    /// keeps (FIX SAVED-LANE-OUTLIVES-CAVEAT-EXPIRY); `None` for a credential
    /// that ends with its mint, and for one that stands past its own expiry
    /// (`Self::Standing`).
    #[must_use]
    pub(crate) fn expires_at(self) -> Option<u64> {
        match self {
            Self::Live { expires_at, .. } => expires_at,
            Self::Standing(_) => None,
        }
    }

    /// Whether this credential still holds in `txn`.
    ///
    /// # Errors
    /// A store, fold or clock failure judging it.
    pub(crate) fn holds_in(self, vault: &crate::Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        match self {
            Self::Live { id, expires_at } => {
                if let Some(end) = expires_at
                    && vault.instant_in_txn(txn)?.secs() >= end
                {
                    return Ok(false);
                }
                vault.saved_read_credential_is_live_in_txn(txn, &id)
            }
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
/// either gate refused (Sol R1/R2 on #8061), and it reads as the actor
/// class the live key was proved as: a key built from the principal's row
/// takes that class, and a caller's key of another class reads nothing
/// (`ScopedReadActorKey::within_saved_actor_class`, Sol F1 on #8134). A
/// basis saved before the class was kept leaves the key's own (Astra F1/F2
/// on #8134); one whose live key named no class reads with none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The actor class the live key read as, which each policy row's class
    /// matched (`scoped_read_actor_matches`): a credential's from its proof,
    /// so an agent-class credential on a PERSON keeps `agent` (FIX
    /// SAVED-LANE-REBUILD-SUBSTITUTES-ACTOR-CLASS). `None` for a key that
    /// named no class (`classless`), and for a basis saved before the class
    /// was kept: a rebuild of that one reads under its own key's class, as
    /// before (Astra F1/F2 on #8134).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) actor_class: Option<String>,
    /// Set when the live key named no class, and so matched no policy row
    /// bound to one (round 2 review P1 of #9590): each rebuild reads with no
    /// class, as that key did, and a caller's key that names a class reads
    /// nothing. Unset on a key that named a class, and on a basis saved
    /// before this was kept.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) classless: bool,
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
    fn closes_unscoped_rows(&self) -> bool {
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
    /// The earlier end a caveat set that credential, in seconds on the
    /// vault's clock, as the saved key's live proof was held to it: every
    /// rebuild, and every read under a rebuilt key, reads nothing from then
    /// on, while the credential's mint may still be live (FIX
    /// SAVED-LANE-OUTLIVES-CAVEAT-EXPIRY). `None` when the saved proof was
    /// its mint, whose own end the credential's liveness judges, and on a
    /// lane that reads as its principal's own, whose credential's expiry
    /// ends no saved work (FIX 3377).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_expires_at: Option<u64>,
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
    /// Whether the saved lane's reader was homed in no conversation of this
    /// vault (`ScopedReadActorKey::homed_unnamed`): every rebuild reads no
    /// stamped claim outside a room of this vault, as the saving key did.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    home_unnamed: bool,
    /// The grant basis the saved lane's live key read under (FIX 14344), its
    /// actor class among it: kept on every lane that keeps a Scope, and on a
    /// lane under the access gate or of an actor that is no live owner,
    /// which keeps no Scope its live key lacked (Sol F1/F2/F3 on #8065; FIX
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
    /// rebuilt key, judges: whole on a narrowed lane, with the earlier end a
    /// caveat set it, by its standing on one that reads as its principal's
    /// own.
    fn saved_credential(&self) -> Option<SavedCredential> {
        self.credential.map(|id| {
            if self.reads_as_principal() {
                SavedCredential::Standing(id)
            } else {
                SavedCredential::Live {
                    id,
                    expires_at: self.credential_expires_at,
                }
            }
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
