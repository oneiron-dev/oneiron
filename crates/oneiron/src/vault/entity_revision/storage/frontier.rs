//! Current-format entries in the shared revision-frontier table.

use super::{RevisionRef, reference};
use crate::EntityId;
use crate::error::{Error, Result};
use loro::Frontiers;

pub(super) enum FrontierEntry<'a> {
    Document(&'a [u8]),
    PhysicalAlias,
    Note {
        slot: EntityId,
        row: RevisionRef,
        frontier: &'a [u8],
    },
}

impl<'a> FrontierEntry<'a> {
    pub(super) fn decode(bytes: &'a [u8]) -> Result<Self> {
        let Some((&kind, value)) = bytes.split_first() else {
            return Err(Error::CorruptedIndex("entity frontier entry"));
        };
        match kind {
            0 => {
                decode_frontier(value)?;
                Ok(Self::Document(value))
            }
            1 if value.is_empty() => Ok(Self::PhysicalAlias),
            2 => {
                let (slot, value) = value
                    .split_at_checked(16)
                    .ok_or(Error::CorruptedIndex("NOTE revision slot"))?;
                let (row, frontier) = value
                    .split_at_checked(16)
                    .ok_or(Error::CorruptedIndex("NOTE revision row"))?;
                let slot = EntityId::from_bytes(
                    slot.try_into()
                        .map_err(|_| Error::CorruptedIndex("NOTE revision slot"))?,
                )
                .map_err(|_| Error::CorruptedIndex("NOTE revision slot"))?;
                let row = RevisionRef(
                    row.try_into()
                        .map_err(|_| Error::CorruptedIndex("NOTE revision row"))?,
                );
                decode_frontier(frontier)?;
                Ok(Self::Note {
                    slot,
                    row,
                    frontier,
                })
            }
            _ => Err(Error::CorruptedIndex("entity frontier kind")),
        }
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        match self {
            Self::Document(frontier) => [b"\0".as_slice(), frontier].concat(),
            Self::PhysicalAlias => vec![1],
            Self::Note {
                slot,
                row,
                frontier,
            } => [
                b"\x02".as_slice(),
                slot.as_bytes().as_slice(),
                row.0.as_slice(),
                frontier,
            ]
            .concat(),
        }
    }

    pub(super) fn document(self) -> Result<&'a [u8]> {
        match self {
            Self::Document(frontier) => Ok(frontier),
            _ => Err(Error::CorruptedIndex("entity document frontier kind")),
        }
    }

    pub(super) fn committed_note(
        self,
        id: &EntityId,
        revision: RevisionRef,
        encoded: &[u8],
    ) -> Result<Option<(EntityId, RevisionRef, &'a [u8])>> {
        let Self::Note {
            slot,
            row,
            frontier,
        } = self
        else {
            return Ok(None);
        };
        if reference(id, encoded) != revision {
            return Err(Error::CorruptedIndex("NOTE frontier reference mismatch"));
        }
        Ok(Some((slot, row, frontier)))
    }
}

pub(super) fn decode_frontier(bytes: &[u8]) -> Result<Frontiers> {
    Frontiers::decode(bytes).map_err(|_| Error::CorruptedIndex("entity frontier"))
}
