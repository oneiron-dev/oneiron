//! A custody transition in pieces (CALLS `Phase2 custody pieces request
//! bound`, Engine 10-22 02:2x; FIX 7906, 7951, 7952). A custody change
//! permits any number of recipients, and the transition that enacts it
//! carries the complete permitted set in pieces, each one carrier within the
//! codec's own floors: at most [`MAX_CARRIER_BYTES`] encoded (the 4 MiB a
//! carrier held before pieces, its piece fields beside it) and at most
//! [`MAX_PIECE_VALUES`] sealed values. No total recipient count is refused,
//! nor any value's size: a value too large for one carrier rides in
//! numbered envelopes, each in a piece within the floors, a piece carrying
//! on the value the piece before it ended with (FIX 7953).
//!
//! Every piece signs the commitment to the request's complete set
//! ([`custody_recipient_set`]), the request, generation and input it enacts,
//! and its own place: which piece of how many, and the first permit it
//! carries. A receiver admits a piece only as the run of the request's own
//! permits it names, so no piece stands for a partial set. The executor
//! signs and verifies every piece before it keeps any, and keeps and relays
//! them together; a relay keeps the pieces it has received, the rest owed,
//! and never a partial set in place of the whole.
//!
//! One group verifier, [`CustodyPieces::whole`], decides whether pieces are
//! the whole transition: the executor publishes, a receiver applies, the
//! roster plans from and a restored row serves only such a group. A piece
//! alone has no custody effect.

use ed25519_dalek::{Signer, SigningKey};
use oneiron_crypto::HybridPublicKey;

use super::super::types::SecretCustodyStatus;
use super::payload::{
    MAX_CARRIER_BYTES, MAX_PIECE_VALUES, VALUE_ENVELOPE_BYTES, split_value_envelopes,
};
use super::{CustodyTransition, refused};
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, CustodyRecipientPermit, custody_recipient_set,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The magic of the pieces this vault keeps of one record's transition.
const PIECES_MAGIC: &[u8; 4] = b"OCS1";
/// Bytes one sealed value adds to a piece beside its envelope: its permit
/// and the envelope's length.
const VALUE_FRAME_BYTES: usize = 16 + 32 + 32 + 4;

/// What makes two pieces one transition, in the order a later transition
/// replaces an earlier one.
type Identity = (
    (u32, u8),
    u64,
    AuthorityEntryHash,
    [u8; 32],
    Option<[u8; 32]>,
    [u8; 32],
    u32,
    [u8; 32],
);

impl CustodyTransition {
    /// This transition's identity, shared by every piece of it: its order,
    /// signing second, request, set, input, signer, piece count and body.
    pub(super) fn identity(&self) -> Identity {
        (
            self.order(),
            self.signed_at,
            self.request,
            self.set,
            self.input,
            self.signer,
            self.pieces,
            *blake3::hash(&self.body).as_bytes(),
        )
    }

    /// Whether `other` is a piece of the same transition.
    pub(crate) fn same_transition(&self, other: &Self) -> bool {
        self.id == other.id && self.identity() == other.identity()
    }

    /// Whether this piece's place is whole on its own: one of its pieces,
    /// the first piece starting the set, a revoked transition one empty
    /// piece, and a lone piece carrying exactly the set it commits to. A
    /// later piece starts there too only when it carries on the first
    /// value (FIX 7953), which [`CustodyPieces::whole`] decides.
    pub(super) fn place_whole(&self) -> bool {
        let lone = self.pieces == 1;
        let permits: Vec<CustodyRecipientPermit> = self.permits().copied().collect();
        self.piece < self.pieces
            && (self.piece != 0 || self.first == 0)
            && (self.status != SecretCustodyStatus::Revoked || lone)
            && (!lone || self.set == custody_recipient_set(&permits))
    }

    /// Whether this piece is its place in `recipients`, a request's
    /// complete permitted set: it commits to exactly that set, its permits
    /// are the run of it at `first`, and the last piece ends it. A piece
    /// before the last ends it too only when the next carries on its last
    /// value (FIX 7953), which [`CustodyPieces::whole`] decides.
    pub(super) fn piece_of(&self, recipients: &[CustodyRecipientPermit]) -> bool {
        let Ok(start) = usize::try_from(self.first) else {
            return false;
        };
        let Some(end) = start.checked_add(self.permits().count()) else {
            return false;
        };
        let last = self.piece.checked_add(1) == Some(self.pieces);
        self.set == custody_recipient_set(recipients)
            && recipients
                .get(start..end)
                .is_some_and(|run| run.iter().eq(self.permits()))
            && (!last || end == recipients.len())
    }

    /// The custody map key this piece rides under in its window.
    pub(crate) fn row_key(&self) -> String {
        custody_row_key(self.id, self.piece)
    }
}

/// The custody map key piece `piece` of record `id`'s transition rides under:
/// the record's id for the first piece, then the id and the place in
/// fixed-width hex, so keys sort as the pieces do.
pub(crate) fn custody_row_key(id: EntityId, piece: u32) -> String {
    if piece == 0 {
        id.to_hex()
    } else {
        format!("{}.{piece:08x}", id.to_hex())
    }
}

/// The record id and piece a custody map key names, when it is canonical.
pub(crate) fn parse_custody_row_key(key: &str) -> Option<(EntityId, u32)> {
    let (id, piece) = match key.split_once('.') {
        None => (key, 0),
        Some((id, piece)) => (id, u32::from_str_radix(piece, 16).ok()?),
    };
    let id = EntityId::from_hex(id).ok()?;
    (custody_row_key(id, piece) == key).then_some((id, piece))
}

/// Signs `template`'s transition with `signing` for `vault_id`, its `value`
/// sealed to each of `recipients` ascending by machine, in as few pieces as
/// the frame floors allow, and verifies every piece before it returns any.
/// A value too large for a carrier of its own is sealed as numbered
/// envelopes, each sized to ride in a piece within the floors, and a piece
/// that carries on the value the piece before it ended with starts at that
/// value's permit (FIX 7953). No value size is refused; only a record whose
/// body leaves a piece no room for a value is, as before.
pub(super) fn sign_pieces(
    vault_id: &[u8; 32],
    signing: &SigningKey,
    template: CustodyTransition,
    recipients: &[(CustodyRecipientPermit, HybridPublicKey)],
    value: &[u8],
) -> Result<CustodyPieces> {
    let base = template.encode().len();
    let room = MAX_CARRIER_BYTES.saturating_sub(base + VALUE_FRAME_BYTES + VALUE_ENVELOPE_BYTES);
    let binding = template.binding();
    let mut recipients: Vec<&(CustodyRecipientPermit, HybridPublicKey)> =
        recipients.iter().collect();
    recipients.sort_unstable_by_key(|(permit, _)| permit.machine);
    let mut sealed = Vec::with_capacity(recipients.len());
    for (permit, public) in recipients {
        for envelope in split_value_envelopes(vault_id, &binding, permit, public, value, room)? {
            sealed.push((*permit, envelope));
        }
    }
    let mut groups = Vec::new();
    let mut current = Vec::new();
    let mut size = base;
    for (permit, envelope) in sealed {
        let frame = VALUE_FRAME_BYTES + envelope.len();
        if !current.is_empty()
            && (size + frame > MAX_CARRIER_BYTES || current.len() == MAX_PIECE_VALUES)
        {
            groups.push(std::mem::take(&mut current));
            size = base;
        }
        size += frame;
        current.push((permit, envelope));
    }
    // The last piece; a revoked transition's one empty piece.
    groups.push(current);
    let pieces = u32::try_from(groups.len())
        .map_err(|_| refused("the custody transition has too many pieces"))?;
    let mut next = 0_u32;
    let mut last = None;
    let mut signed = Vec::with_capacity(groups.len());
    for (place, group) in (0..pieces).zip(groups) {
        let lead = group.first().map(|(permit, _)| *permit);
        let first = if lead.is_some() && lead == last {
            next - 1
        } else {
            next
        };
        last = group.last().map(|(permit, _)| *permit).or(last);
        let mut piece = CustodyTransition {
            piece: place,
            pieces,
            first,
            sealed: group,
            ..template.clone()
        };
        piece.signature = signing.sign(&piece.transcript(vault_id)).to_bytes();
        if piece.encode().len() > MAX_CARRIER_BYTES {
            return Err(refused(
                "the custody record leaves its carrier no room for a value",
            ));
        }
        piece.verify_signed(vault_id)?;
        let carried = u32::try_from(piece.permits().count())
            .map_err(|_| refused("the custody transition has too many recipients"))?;
        next = first
            .checked_add(carried)
            .ok_or_else(|| refused("the custody transition has too many recipients"))?;
        signed.push(piece);
    }
    let signed = CustodyPieces(signed);
    if !signed.whole() {
        return Err(refused(
            "the custody transition's pieces do not carry its whole set",
        ));
    }
    Ok(signed)
}

/// The pieces this vault keeps of one record's transition, ascending by
/// place, never none: all of them once its executor signed them, or those a
/// relay has received so far, the rest owed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CustodyPieces(Vec<CustodyTransition>);

impl CustodyPieces {
    /// A transition of which one piece is kept.
    pub(super) fn single(piece: CustodyTransition) -> Self {
        Self(vec![piece])
    }

    /// The first piece kept: the transition's identity, record and order.
    pub(crate) fn lead(&self) -> &CustodyTransition {
        &self.0[0]
    }

    pub(crate) fn pieces(&self) -> &[CustodyTransition] {
        &self.0
    }

    pub(crate) fn into_pieces(self) -> Vec<CustodyTransition> {
        self.0
    }

    /// The permits of every piece kept, ascending by machine, once each: a
    /// value carried on from one piece into the next shares its permit.
    pub(crate) fn permits(&self) -> impl Iterator<Item = &CustodyRecipientPermit> + '_ {
        let mut last = None;
        self.0
            .iter()
            .flat_map(CustodyTransition::permits)
            .filter(move |permit| last.replace(*permit) != Some(*permit))
    }

    /// The one group verifier: whether these are every piece of one
    /// transition, its places `0..pieces` once each and in order, each
    /// piece's permits starting where the piece before it ended, or at its
    /// last permit when it carries on that value (FIX 7953), with no gap and
    /// no other overlap, and all their permits, joined, ascending by machine
    /// and exactly the set every piece commits to. Only then is its set
    /// whole here.
    pub(crate) fn whole(&self) -> bool {
        let lead = self.lead();
        if usize::try_from(lead.pieces).ok() != Some(self.0.len()) {
            return false;
        }
        let mut next = 0_usize;
        let mut last = None;
        for (place, piece) in (0_u32..).zip(&self.0) {
            let carried_on = last.is_some() && piece.permits().next() == last;
            let start = if carried_on {
                next.saturating_sub(1)
            } else {
                next
            };
            if piece.piece != place
                || !piece.same_transition(lead)
                || usize::try_from(piece.first).ok() != Some(start)
            {
                return false;
            }
            next = start.saturating_add(piece.permits().count());
            last = piece.permits().last().or(last);
        }
        let permits: Vec<CustodyRecipientPermit> = self.permits().copied().collect();
        permits
            .windows(2)
            .all(|pair| pair[0].machine < pair[1].machine)
            && custody_recipient_set(&permits) == lead.set
    }

    /// Whether these pieces stand under `fold` as one transition: whole
    /// ([`Self::whole`]), and each piece standing on the request it enacts
    /// as its own run of the request's permits
    /// ([`CustodyTransition::verify`]), so together they carry exactly the
    /// request's permitted set. Only such a group has custody effects.
    pub(crate) fn verify(&self, fold: &AuthorityFold) -> Result<()> {
        if !self.whole() {
            return Err(refused("its pieces are not one whole transition"));
        }
        self.0.iter().try_for_each(|piece| piece.verify(fold))
    }

    /// The value sealed to `machine`, opened from the pieces that carry it,
    /// its numbered envelopes joined in order (FIX 7953,
    /// [`CustodyTransition::open_value`]).
    #[cfg(feature = "sync")]
    pub(crate) fn open_value(
        &self,
        vault_id: &[u8; 32],
        machine: EntityId,
        secret: &oneiron_crypto::HybridSecretKey,
    ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        CustodyTransition::open_value(&self.0, vault_id, machine, secret)
    }

    /// The digest an executor's output binding keeps of these pieces.
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for piece in &self.0 {
            hasher.update(&piece.digest());
        }
        *hasher.finalize().as_bytes()
    }

    /// Joins `piece` of the same transition in its place, unless that place
    /// is kept already.
    #[cfg(feature = "sync")]
    fn join(&mut self, piece: &CustodyTransition) {
        if !self.0.iter().any(|held| held.piece == piece.piece) {
            self.0.push(piece.clone());
            self.0.sort_unstable_by_key(|held| held.piece);
        }
    }

    /// These pieces with `piece` of the same transition joined, or `None`
    /// when its place is kept already.
    pub(super) fn with_piece(&self, piece: &CustodyTransition) -> Option<Self> {
        if self.0.iter().any(|held| held.piece == piece.piece) {
            return None;
        }
        let mut pieces = self.0.clone();
        pieces.push(piece.clone());
        pieces.sort_unstable_by_key(|held| held.piece);
        Some(Self(pieces))
    }

    /// The stored row: the magic, the count, then each piece's length and
    /// carrier bytes.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = PIECES_MAGIC.to_vec();
        out.extend_from_slice(&(self.0.len() as u32).to_be_bytes());
        for piece in &self.0 {
            let bytes = piece.encode();
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        out
    }

    /// A stored row read back: pieces of one transition, ascending by
    /// place, each decoded strictly; `None` for anything else.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.strip_prefix(PIECES_MAGIC)?;
        let (count, mut rest) = rest.split_first_chunk::<4>()?;
        let mut pieces = Vec::new();
        for _ in 0..u32::from_be_bytes(*count) {
            let (len, tail) = rest.split_first_chunk::<4>()?;
            let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
            let (piece, tail) = tail.split_at_checked(len)?;
            pieces.push(CustodyTransition::decode(piece).ok()?);
            rest = tail;
        }
        let ordered = pieces
            .windows(2)
            .all(|pair| pair[0].piece < pair[1].piece && pair[0].same_transition(&pair[1]));
        (rest.is_empty() && !pieces.is_empty() && ordered).then_some(Self(pieces))
    }
}

/// The groups `arrived`, pieces this vault judged standing, make with the
/// pieces of the same transition it keeps: each one whole
/// ([`CustodyPieces::whole`]). A group still missing a piece is left out:
/// its pieces are kept, the rest owed, and nothing it carries applies.
#[cfg(feature = "sync")]
pub(crate) fn completed_custody_groups_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    arrived: &[CustodyTransition],
) -> Result<Vec<CustodyPieces>> {
    let mut groups: Vec<CustodyPieces> = Vec::new();
    for piece in arrived {
        if let Some(group) = groups
            .iter_mut()
            .find(|group| group.lead().same_transition(piece))
        {
            group.join(piece);
            continue;
        }
        let held = super::TRANSITIONS
            .get(&vault.store, txn, &crate::side_table::HexId(piece.id))?
            .and_then(|held| CustodyPieces::decode(&held))
            .filter(|held| held.lead().same_transition(piece));
        let mut group = held.unwrap_or_else(|| CustodyPieces(Vec::new()));
        group.join(piece);
        groups.push(group);
    }
    groups.retain(CustodyPieces::whole);
    Ok(groups)
}

/// Keeps `piece`, judged standing as it arrived, beside the pieces of its
/// transition this vault holds, before any custody effect
/// ([`super::remember_custody_transition_in_txn`]). A live piece of a secret
/// an admitted revoke ended settles that revoke here and is not kept, nor is
/// one that no longer stands on `fold`, this transaction's (WILL L04 row
/// 04). Returns whether it kept it.
#[cfg(feature = "sync")]
pub(crate) fn keep_custody_piece_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fold: &AuthorityFold,
    piece: &CustodyTransition,
) -> Result<bool> {
    if piece.status != SecretCustodyStatus::Revoked
        && super::super::control::custody_revoked_in_txn(vault, wtxn, &piece.id)?
    {
        super::super::control::settle_revoked_in_txn(vault, wtxn, &piece.id, piece.signed_at)?;
        return Ok(false);
    }
    if piece.verify(fold).is_err() {
        return Ok(false);
    }
    super::remember_custody_transition_in_txn(vault, wtxn, piece)
}
