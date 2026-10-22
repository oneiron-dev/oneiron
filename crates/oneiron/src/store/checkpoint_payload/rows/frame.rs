//! The bundle framing of an owner's content and of an actor's parts: a
//! version byte, then fixed fields and length-prefixed bytes, every length a
//! u32be. Framing only: the seal and its commitments are KS7-2b's.

use super::super::{OWNER_LEN, Subtype, corrupt};
use super::{ActorPart, Dependency, OwnerRef, OwnerRows, RowDb, RowLocator, RowPart};
use crate::entity_id::EntityId;
use crate::error::Result;

const VERSION: u8 = 1;

const EXACT: u8 = 0;
const NO_ACTOR: u8 = 1;
const ACTOR_KEYED: u8 = 2;

fn db_code(db: RowDb) -> u8 {
    match db {
        RowDb::Entities => 1,
        RowDb::EdgesOut => 2,
        RowDb::EdgesIn => 3,
        RowDb::VaultMeta => 4,
        RowDb::SyncState => 5,
        RowDb::SyncQueue => 6,
    }
}

fn db_of(code: u8) -> Option<RowDb> {
    match code {
        1 => Some(RowDb::Entities),
        2 => Some(RowDb::EdgesOut),
        3 => Some(RowDb::EdgesIn),
        4 => Some(RowDb::VaultMeta),
        5 => Some(RowDb::SyncState),
        6 => Some(RowDb::SyncQueue),
        _ => None,
    }
}

fn put_len(out: &mut Vec<u8>, len: usize) -> Result<()> {
    let len = u32::try_from(len).map_err(|_| corrupt())?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    put_len(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_locator(out: &mut Vec<u8>, at: &RowLocator) -> Result<()> {
    out.push(db_code(at.db));
    put_bytes(out, &at.key)?;
    put_bytes(out, at.path.as_bytes())
}

fn put_owner(out: &mut Vec<u8>, owner: &OwnerRef) {
    out.push(owner.subtype.tag());
    out.extend_from_slice(&owner.owner32);
}

fn put_part(out: &mut Vec<u8>, part: &RowPart) -> Result<()> {
    match part {
        RowPart::Exact { at, value } => {
            out.push(EXACT);
            put_locator(out, at)?;
            put_bytes(out, value)
        }
        RowPart::NoActor { at, value } => {
            out.push(NO_ACTOR);
            put_locator(out, at)?;
            put_bytes(out, value)
        }
        RowPart::ActorKeyed { at } => {
            out.push(ACTOR_KEYED);
            put_locator(out, at)
        }
    }
}

/// Reads framed bytes front to back, refusing a short or malformed frame.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (head, rest) = self.bytes.split_at_checked(len).ok_or_else(corrupt)?;
        self.bytes = rest;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| corrupt())
    }

    fn len(&mut self) -> Result<usize> {
        usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| corrupt())
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.len()?;
        Ok(self.take(len)?.to_vec())
    }

    fn text(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?).map_err(|_| corrupt())
    }

    fn locator(&mut self) -> Result<RowLocator> {
        let db = db_of(self.byte()?).ok_or_else(corrupt)?;
        let key = self.bytes()?;
        let path = self.text()?;
        Ok(RowLocator { db, key, path })
    }

    /// An owner whose bytes past its subtype's width are zero.
    fn owner(&mut self) -> Result<OwnerRef> {
        let subtype = Subtype::from_tag(self.byte()?).ok_or_else(corrupt)?;
        let owner32: [u8; OWNER_LEN] = self.array()?;
        if owner32[subtype.owner_len()..].iter().any(|byte| *byte != 0) {
            return Err(corrupt());
        }
        Ok(OwnerRef { subtype, owner32 })
    }

    fn part(&mut self) -> Result<RowPart> {
        Ok(match self.byte()? {
            EXACT => RowPart::Exact {
                at: self.locator()?,
                value: self.bytes()?,
            },
            NO_ACTOR => RowPart::NoActor {
                at: self.locator()?,
                value: self.bytes()?,
            },
            ACTOR_KEYED => RowPart::ActorKeyed {
                at: self.locator()?,
            },
            _ => return Err(corrupt()),
        })
    }

    fn version(&mut self) -> Result<()> {
        if self.byte()? == VERSION {
            Ok(())
        } else {
            Err(corrupt())
        }
    }

    fn finish(&self) -> Result<()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(corrupt())
        }
    }
}

/// `rows`' content parts that `owns` claims, with their dependencies, framed
/// for the owner's compartment. Actor parts are framed apart
/// ([`frame_actor_parts`]), under each actor's own entity tree.
pub(crate) fn frame_owner(rows: &OwnerRows, owns: impl Fn(&RowLocator) -> bool) -> Result<Vec<u8>> {
    let mut out = vec![VERSION];
    put_owner(&mut out, &rows.owner());
    match rows.occurrence_hint {
        Some(occurrence) => {
            out.push(1);
            out.extend_from_slice(&occurrence);
        }
        None => out.push(0),
    }
    let parts: Vec<&RowPart> = rows.rows.iter().filter(|part| owns(part.at())).collect();
    put_len(&mut out, parts.len())?;
    for part in parts {
        put_part(&mut out, part)?;
    }
    let dependencies: Vec<&Dependency> = rows
        .dependencies
        .iter()
        .filter(|dependency| owns(&dependency.at))
        .collect();
    put_len(&mut out, dependencies.len())?;
    for dependency in dependencies {
        put_locator(&mut out, &dependency.at)?;
        put_owner(&mut out, &dependency.on);
    }
    Ok(out)
}

/// An owner's content as [`frame_owner`] framed it, with no actor parts.
pub(super) fn read_owner(bytes: &[u8]) -> Result<OwnerRows> {
    let mut reader = Reader { bytes };
    reader.version()?;
    let mut rows = OwnerRows::new(reader.owner()?);
    rows.occurrence_hint = match reader.byte()? {
        0 => None,
        1 => Some(reader.array()?),
        _ => return Err(corrupt()),
    };
    for _ in 0..reader.len()? {
        rows.rows.push(reader.part()?);
    }
    for _ in 0..reader.len()? {
        let at = reader.locator()?;
        let on = reader.owner()?;
        rows.dependencies.push(Dependency { at, on });
    }
    reader.finish()?;
    Ok(rows)
}

/// Actor parts framed for their actor's compartment.
pub(crate) fn frame_actor_parts(parts: &[ActorPart]) -> Result<Vec<u8>> {
    let mut out = vec![VERSION];
    put_len(&mut out, parts.len())?;
    for part in parts {
        out.extend_from_slice(part.actor_entity.as_bytes());
        put_locator(&mut out, &part.content_locator)?;
        put_bytes(&mut out, part.field.as_bytes())?;
        put_bytes(&mut out, &part.bytes)?;
    }
    Ok(out)
}

/// Actor parts as [`frame_actor_parts`] framed them.
pub(crate) fn read_actor_parts(bytes: &[u8]) -> Result<Vec<ActorPart>> {
    let mut reader = Reader { bytes };
    reader.version()?;
    let mut parts = Vec::new();
    for _ in 0..reader.len()? {
        let actor_entity = EntityId::from_bytes(reader.array()?)?;
        let content_locator = reader.locator()?;
        let field = reader.text()?;
        let bytes = reader.bytes()?;
        parts.push(ActorPart {
            actor_entity,
            content_locator,
            field,
            bytes,
        });
    }
    reader.finish()?;
    Ok(parts)
}

/// One row's key and value, as an actor-keyed row's actor part holds them.
pub(super) fn frame_row(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(key.len() + value.len() + 8);
    put_bytes(&mut out, key)?;
    put_bytes(&mut out, value)?;
    Ok(out)
}

/// A row's key and value as [`frame_row`] framed them.
pub(super) fn read_row(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut reader = Reader { bytes };
    let key = reader.bytes()?;
    let value = reader.bytes()?;
    reader.finish()?;
    Ok((key, value))
}
