//! FIX 7461: a question's own locally built reader also reads what its own
//! live owner authority admits (owner principle 2: the owner reads all of the
//! owner's vault, whichever lane a question built for it).
//!
//! Off unless the lane opts in ([`ScopedRead::with_own_owner_authority`]),
//! and only a question's own identity reader does, never a lane built on a
//! credential a caller supplied. A row's own admission is today's (B) first,
//! then the reader's own live Grants (FIX 7462), both unchanged; only once
//! both refuse is the same row judged again, whole, under the owner's key,
//! and only while the key's own actor is a live owner of this vault in the
//! read's snapshot (`policy_model::is_live_vault_owner_in_txn`). The owner's
//! key keeps everything the lane's key bounds its read by: its destination,
//! worlds, room turn, channel, relationship principal and owner exemption;
//! the lane keeps its audience, peers, session view, room ceiling and claim
//! status; the request a read asked is met as the Grant alternative meets
//! it. It never stands for a key that supplies a proof, carries a Scope, is
//! already the owner's or is held to a host action or an owner proof. It
//! only ever adds a row: a store, fold or decode failure admits nothing and
//! leaves the read's answer, counted in a warning that names no content.
//!
//! FIX 7661: a row only this alternative admitted keeps the owner lane that
//! admitted it ([`OwnAdmission::ByOwner`]), so its full-row entry may read
//! what the row was written from as that same lane does, once today's source
//! check refused it. Nothing stores it and no caller outside this lane sees
//! it.

use super::access_gate::HeldAuthority;
use super::agent_grants::{AskedFilter, as_request};
use super::*;

/// Which alternative admitted a row's own admission (FIX 7661): read by the
/// full-row entry alone, never stored and never public.
pub(super) enum OwnAdmission<'v> {
    /// Every alternative refused the row.
    Refused,
    /// B, or one of the reader's own Grants, admitted it.
    Admitted,
    /// Only the reader's own owner authority admitted it, under this lane.
    ByOwner(Box<ScopedRead<'v>>),
}

impl OwnAdmission<'_> {
    /// Whether any alternative admitted the row.
    pub(super) fn admitted(&self) -> bool {
        !matches!(self, Self::Refused)
    }
}

impl<'v> ScopedRead<'v> {
    /// This lane, a question's own locally built reader, opted into its
    /// reader's own live owner authority (FIX 7461): a row its own admission
    /// and its reader's own Grants refuse is read again under the reader's
    /// owner key while the reader is a live owner of this vault. Never for a
    /// lane built on a caller's credential.
    #[must_use]
    pub(crate) fn with_own_owner_authority(mut self) -> Self {
        self.own_owner_authority = true;
        self
    }

    /// The owner alternative for the row `raw` of `id`, tried only once B
    /// and the reader's own Grants refused it: the owner lane that reads it,
    /// when this opted-in lane's reader, a live owner of this vault now,
    /// reads it under its owner key; `None` otherwise. `filter` is the one B
    /// judged it under, `asked` what the read asked beyond its key's floor.
    #[expect(
        clippy::too_many_arguments,
        reason = "the owner alternative judges the row B judged, under B's filter and request"
    )]
    pub(super) fn own_row_owner_lane_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority<'v>,
        asked: &AskedFilter,
    ) -> Option<ScopedRead<'v>> {
        let owner = self.owner_reader()?;
        let request = match asked {
            AskedFilter::Known(request) => request.clone(),
            // B's own filter, met with the owner's floor: never wider than
            // the caller asked. One that reads nothing leaves nothing.
            AskedFilter::Unknown if filter.deny_all => return None,
            AskedFilter::Unknown => Some(as_request(filter)),
        };
        self.own_row_as_owner_in(rtxn, policy, id, raw, request.as_ref(), authority, owner)
            .unwrap_or_else(|error| {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "a reader's own owner authority admitted nothing it could not judge; the read \
                     keeps its own answer (FIX 7461)"
                );
                None
            })
    }

    /// The reader the owner alternative may stand for: this opted-in lane's
    /// own actor, while its key supplies no proof, carries no Scope, is not
    /// already the owner's and is held to no host action or owner proof.
    fn owner_reader(&self) -> Option<EntityId> {
        let key = &self.actor_key;
        if !self.own_owner_authority
            || key.proof.is_some()
            || key.authority_scope().is_some()
            || key.vault_owner_ref().is_some()
            || key.host_action_guard().is_some()
            || key.owner_proof_guard().is_some()
        {
            return None;
        }
        EntityId::from_hex(key.actor_ref()).ok()
    }

    /// The row under `owner`'s own key, once `owner` is a live owner of this
    /// vault in `rtxn`: its whole admission under the owner's floor, met with
    /// `request` as the read met its own, and the owner lane that admitted
    /// it.
    #[expect(
        clippy::too_many_arguments,
        reason = "the row's admission as its live owner takes the row, its request and authority"
    )]
    fn own_row_as_owner_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        request: Option<&RetrievalFilter>,
        authority: &HeldAuthority<'v>,
        owner: EntityId,
    ) -> Result<Option<ScopedRead<'v>>> {
        if !crate::policy_model::is_live_vault_owner_in_txn(self.vault, rtxn, &owner)? {
            return Ok(None);
        }
        let lane = self.as_owner(owner)?;
        let floor = policy.retrieval_floor_for_actor(Some(&lane.actor_key));
        let filter = crate::gate::narrow_retrieval_filter(&floor, request)?
            .under_credential_of(&lane.actor_key);
        Ok(lane
            .own_row_readable_in(rtxn, policy, id, raw, &filter, authority, None)?
            .then_some(lane))
    }

    /// This lane read by `owner`, its own reader, under the owner's key: the
    /// key keeps this key's destination, worlds, room turn, channel,
    /// relationship principal and owner exemption, and the lane keeps this
    /// lane's audience, peers, session view, room ceiling and claim status.
    fn as_owner(&self, owner: EntityId) -> Result<ScopedRead<'v>> {
        let key = &self.actor_key;
        let mut owner_key =
            ScopedReadActorKey::vault_owner(owner).for_destination(key.destination());
        owner_key.principal_ref = key.principal_ref;
        owner_key.enforce_access_grants = key.enforce_access_grants;
        owner_key.unscoped_rows_open = key.unscoped_rows_open;
        owner_key.channel.clone_from(&key.channel);
        owner_key.owner_exemption = key.owner_exemption;
        owner_key.room_turn.clone_from(&key.room_turn);
        owner_key.worlds.clone_from(&key.worlds);
        let room_ceiling = self
            .room_ceiling
            .lock()
            .map_err(|_| Error::InvariantViolation("room ceiling lock"))?
            .clone();
        Ok(ScopedRead {
            vault: self.vault,
            actor_key: owner_key,
            audience: self.audience.clone(),
            peer_reads: self.peer_reads.clone(),
            audience_cache: Mutex::new(Default::default()),
            room_ceiling: Mutex::new(room_ceiling),
            room_ceilings_built: AtomicUsize::new(0),
            session_view: self.session_view,
            claim_status: self.claim_status,
            recall_authority: Mutex::new(None),
            room_peer: self.room_peer,
            own_owner_authority: false,
            records_cover: self.records_cover.clone(),
        })
    }
}
