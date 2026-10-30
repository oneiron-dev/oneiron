//! A custody request's permits in pieces: their writer and their fold (FIX
//! 11866).
//!
//! A custody request whose permits outgrow one sync frame carries their
//! commitment ([`CustodyPermitPieces`]) in their place, and its signer writes
//! the permits ahead of it as numbered [`CustodyPermitPiece`] rows, so every
//! piece is in the request's causal past and folds before it. A piece is
//! valid when its signer is the key its family names (the carrier's install
//! key, or for the owner's kit push an Ed25519 anchor key) and its sequence
//! moves on; it has no effect alone, and the fold keeps it by its signer,
//! commitment and place.
//!
//! The request reads its permits only from the pieces its own signer
//! signed of its commitment at its parents, every place once, each run
//! starting where the one before it ended, joined and hashing to the
//! commitment ([`joined_request`]). The fold keeps the request with the
//! permits joined, so every reader of its permits (permit checks, executor
//! selection, carrier release, recipient lists, a transition's pieces) reads
//! the whole set as it reads an inline one. A request whose pieces do not
//! join at its parents is valid without effect, as one on a revision it did
//! not see is: a missing piece holds it back only while the row is not here,
//! as any row whose parents are not here waits.
//!
//! The writer stages the pieces in the request's own transaction
//! ([`Vault::stage_custody_permit_pieces_in_txn`]) after any frontier join
//! and before the request, which then takes its sequence and parents from
//! the fold read back. Permits that fit one row keep today's inline path and
//! bytes.

use ed25519_dalek::SigningKey;

use super::*;
use crate::error::Result;
use crate::{TimeRange, Vault};

/// A staged piece did not fold here; nothing was written.
const PIECE_NOT_FOLDED: &str =
    "a custody request's permit piece did not fold here; nothing was written";

/// The key a kept piece is found under: its signer, its commitment and its
/// place.
pub(super) type PermitPieceKey = ([u8; 32], CustodyPermitPieces, u32);

/// The signer of a piece of the owner's kit push: an Ed25519 key whose
/// sequence moves on, as the kit request's own (`kit_custody`); the request
/// then reads only its own signer's pieces, under its pinned root's rule.
fn kit_signer(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
) -> std::result::Result<[u8; 32], AuthorityFoldIssue> {
    let AuthorityKey::Ed25519(key) = entry.signer_key() else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    if state
        .seqs
        .get(entry.signer_key())
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    Ok(*key)
}

/// The `CustodyPermitPiece` transition: its signer is the install key some
/// chain of its carrier names, or with no carrier an Ed25519 key, and its
/// sequence moves on, else it is invalid. It is kept by its signer,
/// commitment and place, and moves no other state; of two pieces one signer
/// signed for one place, the lesser stands on every replica.
pub(super) fn apply_permit_piece(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    piece: &CustodyPermitPiece,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    let key = match piece.carrier {
        Some(carrier) => install_signer(
            &Standing::new(state, pin, counted),
            state,
            entry,
            carrier,
            hash,
        )?,
        None => kit_signer(state, entry, hash)?,
    };
    if keep_piece(
        &mut state.owner_work.permit_pieces,
        (key, piece.commitment, piece.index),
        &Arc::new(piece.clone()),
    ) {
        // A set verified before this piece changed it is judged again.
        state
            .owner_work
            .verified_permit_sets
            .remove(&(key, piece.commitment));
    }
    Ok(())
}

/// Keeps `piece` under `key`, or the lesser of it and the piece kept there.
/// True when the piece kept under `key` changed.
pub(super) fn keep_piece(
    pieces: &mut BTreeMap<PermitPieceKey, Arc<CustodyPermitPiece>>,
    key: PermitPieceKey,
    piece: &Arc<CustodyPermitPiece>,
) -> bool {
    match pieces.entry(key) {
        std::collections::btree_map::Entry::Occupied(mut held) => {
            if **piece < **held.get() {
                held.insert(Arc::clone(piece));
                true
            } else {
                false
            }
        }
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(Arc::clone(piece));
            true
        }
    }
}

/// One permit set's kept join ([`keep_joined`], FIX 12139).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct JoinedPermitSet {
    /// The kept request's signed entry: what its supersede prunes the join
    /// by (FIX 12140).
    request: AuthorityEntryHash,
    /// The request as the fold keeps it: the `Arc` the fold's requests hold.
    body: Arc<OwnerWorkRequest>,
}

/// A request as the fold keeps it ([`joined_request`]): as signed when its
/// permits ride inline, else with its permits joined, shared.
pub(super) enum KeptRequest<'r> {
    Signed(&'r OwnerWorkRequest),
    Joined(Arc<OwnerWorkRequest>),
}

impl KeptRequest<'_> {
    /// The body the fold keeps: a copy of an inline request, the joined one
    /// itself.
    pub(super) fn into_shared(self) -> Arc<OwnerWorkRequest> {
        match self {
            Self::Signed(request) => Arc::new(request.clone()),
            Self::Joined(joined) => joined,
        }
    }
}

impl std::ops::Deref for KeptRequest<'_> {
    type Target = OwnerWorkRequest;

    fn deref(&self) -> &OwnerWorkRequest {
        match self {
            Self::Signed(request) => request,
            Self::Joined(joined) => joined,
        }
    }
}

/// Whether `joined`, a request kept with its permits joined, is `request`
/// as signed: every field the same but the permits, which `request` carries
/// in pieces. Each field is named, so a field added later is compared too.
fn joins_as(request: &OwnerWorkRequest, joined: &OwnerWorkRequest) -> bool {
    let OwnerWorkRequest {
        carrier,
        act,
        executor,
        work,
        privacy_basis,
    } = request;
    let (
        OwnerWorkBody::Custody {
            change,
            generation,
            input,
            holder,
            recipients: _,
            pieces,
            authority,
        },
        OwnerWorkBody::Custody {
            change: joined_change,
            generation: joined_generation,
            input: joined_input,
            holder: joined_holder,
            recipients: _,
            pieces: joined_pieces,
            authority: joined_authority,
        },
    ) = (work, &joined.work)
    else {
        return false;
    };
    (carrier, act, executor, privacy_basis)
        == (
            &joined.carrier,
            &joined.act,
            &joined.executor,
            &joined.privacy_basis,
        )
        && (change, generation, input, holder, pieces, authority)
            == (
                joined_change,
                joined_generation,
                joined_input,
                joined_holder,
                joined_pieces,
                joined_authority,
            )
}

/// `request` as the fold keeps it, signed by `signer`, at `work`, the state
/// at its parents: itself when its permits ride inline; with its permits
/// joined from its signer's pieces of its commitment when every place is
/// kept, each run starting where the one before it ended, naming the
/// request's own carrier (none for a kit request), and the whole set
/// ascending, without a zero digest and hashing to the commitment
/// ([`OwnerWorkRequest::validate`]). `None` when they do not join.
///
/// A set a kept request already joined here ([`keep_joined`]) hands that
/// request's `Arc` out to a join of the same request, copying no permit
/// (FIX 12139); a join of another request on the set copies its permits and
/// skips their hash (FIX 12014). The first join still verifies.
pub(super) fn joined_request<'r>(
    work: &OwnerWorkState,
    signer: &[u8; 32],
    request: &'r OwnerWorkRequest,
) -> Option<KeptRequest<'r>> {
    let OwnerWorkBody::Custody {
        pieces: Some(commitment),
        ..
    } = &request.work
    else {
        return Some(KeptRequest::Signed(request));
    };
    let verified = work.verified_permit_sets.get(&(*signer, *commitment));
    if let Some(joined) = verified.filter(|joined| joins_as(request, &joined.body)) {
        return Some(KeptRequest::Joined(Arc::clone(&joined.body)));
    }
    let carrier = request.kit_root().is_none().then_some(request.carrier);
    let mut permits = Vec::new();
    for index in 0..commitment.pieces {
        let piece = work.permit_pieces.get(&(*signer, *commitment, index))?;
        if piece.carrier != carrier || usize::try_from(piece.first).ok()? != permits.len() {
            return None;
        }
        permits.extend_from_slice(&piece.permits);
    }
    let mut joined = request.clone();
    if let OwnerWorkBody::Custody { recipients, .. } = &mut joined.work {
        *recipients = permits;
    }
    if verified.is_none() {
        joined.validate().ok()?;
    }
    Some(KeptRequest::Joined(Arc::new(joined)))
}

/// Keeps `body`, the request signed as entry `request` by `signer` and kept
/// by the fold, as its permit set's join when its permits ride in pieces
/// (FIX 12139): the same `Arc` the fold's requests hold, so it costs no
/// permit. A later join of the same request hands it out
/// ([`joined_request`]); the latest kept on a set stands.
pub(super) fn keep_joined(
    work: &mut OwnerWorkState,
    (signer, request): ([u8; 32], AuthorityEntryHash),
    body: &Arc<OwnerWorkRequest>,
) {
    if let OwnerWorkBody::Custody {
        pieces: Some(commitment),
        ..
    } = &body.work
    {
        let joined = JoinedPermitSet {
            request,
            body: Arc::clone(body),
        };
        work.verified_permit_sets
            .insert((signer, *commitment), joined);
    }
}

/// Drops each kept join whose request a newer request on its secret
/// superseded, or whose secret an admitted revoke names (FIX 12140): where
/// the fold records the supersede or the revoke, a request's landing and a
/// merge. The memo is a cache: a pruned set joins and verifies again on its
/// next join, and nothing is refused for it.
pub(super) fn prune_joined(work: &mut OwnerWorkState) {
    let OwnerWorkState {
        verified_permit_sets,
        heads,
        revoked,
        ..
    } = work;
    verified_permit_sets.retain(|_, joined| {
        let secret = joined.body.act.target;
        !revoked.contains(&secret)
            && !heads
                .get(&(OwnerWorkKind::Custody, secret))
                .is_some_and(|held| held.superseded.contains(&joined.request))
    });
}

impl Vault {
    /// Writes the permits of the custody request `work` as piece rows in
    /// `txn` when they outgrow one row (FIX 11866): runs of
    /// [`custody_permit_piece_len`] permits, each signed by `signing`, the
    /// key that signs the request (the install key of `carrier`, or with no
    /// carrier the anchor of a kit request's root), at the sequences the
    /// request would take, the first naming `fold`'s main-log heads and each
    /// later one the piece before it, so every piece is in the request's
    /// causal past. The pieces land in one put; `work` then carries their
    /// commitment in place of its permits, and the fold read back is
    /// returned, for the request's sequence and parents. `None` when the
    /// permits ride inline, or when `fold`'s heads are more than one entry
    /// names: today's path and bytes, nothing written.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] when a piece did not
    /// fold valid here; signing, store-door and storage errors. A caller's
    /// transaction that fails after this aborts the pieces with the request.
    pub(crate) fn stage_custody_permit_pieces_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        (carrier, signing): (Option<EntityId>, &SigningKey),
        work: &mut OwnerWorkBody,
    ) -> Result<Option<AuthorityView>> {
        let OwnerWorkBody::Custody {
            recipients, pieces, ..
        } = work
        else {
            return Ok(None);
        };
        let Some(run) = custody_permit_piece_len(self.limit_watch(), recipients) else {
            return Ok(None);
        };
        let mut parents = fold.owner_work_parents();
        if parents.len() > MAX_PARENTS {
            return Ok(None);
        }
        let runs: Vec<&[CustodyRecipientPermit]> = recipients.chunks(run).collect();
        let commitment =
            CustodyPermitPieces::of(recipients, runs.len()).ok_or_else(invalid_authority)?;
        let signer = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
        let mut seq = next_sequence(fold, &signer)?;
        let now = self.instant_in_txn(txn)?.secs();
        let at = TimeRange {
            start: now,
            end: now,
        };
        let mut first = 0_u32;
        let mut rows = Vec::with_capacity(runs.len());
        let mut hashes = Vec::with_capacity(runs.len());
        for (index, run) in (0_u32..).zip(runs) {
            let carried = u32::try_from(run.len()).map_err(|_| invalid_authority())?;
            let piece = CustodyPermitPiece {
                carrier,
                commitment,
                index,
                first,
                permits: run.to_vec(),
            };
            let op = AuthorityOp::CustodyPermitPiece(piece);
            let entry = sign_side_entry(fold, signing, seq, parents, op, now)?;
            let hash = authority_entry_hash(&entry)?;
            seq = seq.checked_add(1).ok_or_else(invalid_authority)?;
            first = first.checked_add(carried).ok_or_else(invalid_authority)?;
            parents = BTreeSet::from([hash]);
            hashes.push(hash);
            rows.push((entry, at, now));
        }
        self.put_authority_log_entries_in_txn(txn, &rows)?;
        let staged = self.authority_view_readonly_in_txn(txn)?;
        if !hashes
            .iter()
            .all(|hash| staged.valid_entries.contains(hash))
        {
            return Err(authority_refused(PIECE_NOT_FOLDED));
        }
        recipients.clear();
        *pieces = Some(commitment);
        Ok(Some(staged))
    }
}
