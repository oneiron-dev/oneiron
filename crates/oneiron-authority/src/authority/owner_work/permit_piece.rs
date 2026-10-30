//! One numbered piece of a custody request's permit set, and its wire codec
//! (FIX 11866).
//!
//! A custody request whose permits outgrow one row carries their commitment
//! ([`CustodyPermitPieces`]) in their place, and the permits ride in
//! [`CustodyPermitPiece`] rows written ahead of it, in its causal past: each
//! signed by the key that signs the request (the carrier's install key, or
//! the pinned root's anchor for the owner's kit push), each naming the
//! commitment, its own place and the place of its first permit in the set.
//! A piece is main-log metadata with no effect alone: ids and digests only,
//! never a byte of the secret. The fold reads a request's permits only from
//! its signer's pieces of that commitment, every place once, joined in
//! order and hashing to it; until every piece is in the request's causal
//! past the request does not fold, as any row whose parents are not here.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::custody::{
    decode_permit, decode_permit_pieces, decode_u32, permit_pieces_value, permit_value,
};
use super::*;

pub const OP_KIND_CUSTODY_PERMIT_PIECE: &str = "custody_permit_piece";
const PIECE_KEYS: [&str; 6] = [
    OP_KEY_KIND,
    "carrier",
    "commitment",
    "index",
    "first",
    "permits",
];

/// One piece of a custody request's permit set, signed by the request's own
/// signer: the install key of `carrier`, or with no carrier the anchor of
/// the root a kit request names.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct CustodyPermitPiece {
    /// The machine whose install key signs it, as that key signs the
    /// request; `None` for the owner's kit push, which a stored root's anchor
    /// signs.
    pub carrier: Option<EntityId>,
    /// The commitment of the whole set this piece carries a run of.
    pub commitment: CustodyPermitPieces,
    /// Its place: which piece of `commitment.pieces`.
    pub index: u32,
    /// The place in the set of its first permit.
    pub first: u32,
    /// Its run of the set, ascending by machine, one each.
    pub permits: Vec<CustodyRecipientPermit>,
}

impl CustodyPermitPiece {
    /// The place in the set past its last permit; `None` past the wire's
    /// width.
    #[must_use]
    pub fn end(&self) -> Option<u32> {
        u32::try_from(self.permits.len())
            .ok()
            .and_then(|carried| self.first.checked_add(carried))
    }

    /// A commitment of its own shape, a place within it, one permit at
    /// least, ascending by machine and within the set's count, and no
    /// digest zero.
    pub fn validate(&self) -> Result<()> {
        self.commitment.validate()?;
        let ascending = self
            .permits
            .windows(2)
            .all(|pair| pair[0].machine < pair[1].machine);
        let zero = self
            .permits
            .iter()
            .any(|permit| permit.profile == [0; 32] || permit.encryption_key == [0; 32]);
        let within = self.end().is_some_and(|end| end <= self.commitment.count);
        if self.index >= self.commitment.pieces
            || self.permits.is_empty()
            || !ascending
            || zero
            || !within
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// Signed alone by one Ed25519 key: the carrier's install key, or the
    /// anchor of the root a kit request names.
    pub(in crate::authority) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        signed_alone_by_install_key(entry)
    }
}

/// Canonical field order: kind, carrier (nil for a kit request's anchor),
/// commitment (its map: set, count, then pieces, as a request states it),
/// index, first, then permits, each a permit map as a request carries it.
pub(in crate::authority) fn custody_permit_piece_value(piece: &CustodyPermitPiece) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_CUSTODY_PERMIT_PIECE),
        ),
        (
            Value::from("carrier"),
            piece
                .carrier
                .map_or(Value::Nil, |carrier| Value::from(carrier.to_hex())),
        ),
        (
            Value::from("commitment"),
            permit_pieces_value(piece.commitment),
        ),
        (Value::from("index"), Value::from(piece.index)),
        (Value::from("first"), Value::from(piece.first)),
        (
            Value::from("permits"),
            Value::Array(piece.permits.iter().map(permit_value).collect()),
        ),
    ])
}

pub(in crate::authority) fn decode_custody_permit_piece(
    entries: &[(Value, Value)],
) -> Result<AuthorityOp> {
    validate_keys(entries, &PIECE_KEYS)?;
    let Value::Array(permits) = required(entries, "permits")? else {
        return Err(invalid_authority());
    };
    let piece = CustodyPermitPiece {
        carrier: match required(entries, "carrier")? {
            Value::Nil => None,
            value => Some(decode_canonical_id(value)?),
        },
        commitment: decode_permit_pieces(required(entries, "commitment")?)?,
        index: decode_u32(entries, "index")?,
        first: decode_u32(entries, "first")?,
        permits: permits
            .iter()
            .map(decode_permit)
            .collect::<Result<Vec<_>>>()?,
    };
    piece.validate()?;
    Ok(AuthorityOp::CustodyPermitPiece(piece))
}
