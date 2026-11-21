//! Each seal's value as the minted pass left it, kept whole in custody with
//! its handle taking its place.

use heed::RwTxn;
use rmpv::Value;
use zeroize::Zeroizing;

use super::super::super::secret_scan_error;
use super::super::body::{BodyForm, body_tree, encode_body};
use super::super::side_row::SidePart;
use super::super::wipe::{PlanValues, replace_wiped};
use super::super::{Found, HANDLE_OPEN, Masker, op_record, part_at};
use super::claim_bodies::unnamed;
use super::{Seal, SealIn, put_handle_at, value_bytes};
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_record::CustodyWrite;
use crate::session_overlay::SessionOverlay;
use crate::store::known_value_index::KnownValues;

/// Writes each seal the plan chose into `ops`, as the minted pass left
/// them: each sealed value goes to custody as one record, or keeps the
/// handle of the record that holds it whole (`known`, or a seal of this
/// batch), and its handle takes its place. Seals apply in the plan's order,
/// so a value that holds an earlier seal holds that seal's handle. Each
/// record is stamped `at`.
pub(in crate::batch::secret_scan::mask) fn mint_seals(
    write: &CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    ops: &mut [BatchOp],
    seals: Vec<Seal>,
    known: Option<&KnownValues>,
    at: u64,
) -> Result<()> {
    let mut sealed = PlanValues::<String>::default();
    for seal in seals {
        let op = ops.get_mut(seal.index).ok_or_else(unnamed)?;
        let record = op_record(op).ok_or_else(unnamed)?;
        let mut sealer = Sealer {
            door: Some(SealDoor::Vault(write, at)),
            known,
            sealed: &mut sealed,
            record,
            reason: seal.reason,
        };
        match (seal.at, op) {
            (SealIn::Text, BatchOp::Text { fields, .. }) => {
                let (name, text) = fields.get_mut(seal.member).ok_or_else(unnamed)?;
                sealer.seal_text(wtxn, &format!("text:{name}"), text)?;
            }
            (SealIn::Body(path), BatchOp::Put { data, .. }) => {
                sealer.seal_body(wtxn, "body", data, path)?;
            }
            (SealIn::Value(path), BatchOp::ClaimCandidate { candidate, .. }) => {
                let value = candidate
                    .values_mut()
                    .nth(seal.member)
                    .ok_or_else(unnamed)?;
                sealer.seal_value(wtxn, "claim", value, BodyForm::MessagePack, &path)?;
            }
            _ => return Err(unnamed()),
        }
    }
    Ok(())
}

/// Writes each seal [`plan_part_seals`](super::plan_part_seals) chose into
/// `parts`, as the minted pass left them, as [`mint_seals`] writes an op's,
/// each under its part's record and place in `origins`. Each sealed value
/// goes to custody through `door`: a vault's door mints it as one record
/// stamped with its time, and
/// an off-record room keeps it in the room's own custody
/// (ROOM-LOCAL-CUSTODY). Or it keeps the handle of the record that holds it
/// whole (`known`, or `sealed`: the values this writer sealed before, which
/// each new seal joins). With no door a value custody does not hold whole
/// refuses the write with its seal's reason.
pub(in crate::batch::secret_scan::mask) fn mint_part_seals(
    door: Option<SealDoor<'_, '_>>,
    wtxn: &mut RwTxn<'_>,
    parts: &mut [SidePart],
    origins: &[(EntityId, &str)],
    seals: Vec<Seal>,
    known: Option<&KnownValues>,
    sealed: &mut PlanValues<String>,
) -> Result<()> {
    for seal in seals {
        let (part, (record, place)) = parts
            .get_mut(seal.index)
            .zip(origins.get(seal.index))
            .ok_or_else(unnamed)?;
        let mut sealer = Sealer {
            door,
            known,
            sealed: &mut *sealed,
            record: *record,
            reason: seal.reason,
        };
        match (seal.at, part) {
            (SealIn::Text, SidePart::Text(text)) => sealer.seal_text(wtxn, place, text)?,
            (SealIn::Body(path), SidePart::Body(data)) => {
                sealer.seal_body(wtxn, place, data, path)?;
            }
            (SealIn::Value(path), SidePart::Value(value)) => {
                sealer.seal_value(wtxn, place, value, BodyForm::MessagePack, &path)?;
            }
            _ => return Err(unnamed()),
        }
    }
    Ok(())
}

/// Where a sealed value is kept: base custody through a vault's door, with
/// the time its record is stamped, or an off-record room's own custody, in
/// memory only (ROOM-LOCAL-CUSTODY; the lead's ruling of 21 Nov).
#[derive(Clone, Copy)]
pub(in crate::batch::secret_scan::mask) enum SealDoor<'a, 'w> {
    Vault(&'a CustodyWrite<'w>, u64),
    Room(&'a SessionOverlay),
}

/// One seal's custody write: the door its value goes through (none for a
/// writer whose target holds no custody door), the values custody already
/// holds, the values sealed so far with their handles, and the record and
/// reason its value is minted under.
struct Sealer<'a, 'w> {
    door: Option<SealDoor<'a, 'w>>,
    known: Option<&'a KnownValues>,
    sealed: &'a mut PlanValues<String>,
    record: EntityId,
    reason: &'static str,
}

impl Sealer<'_, '_> {
    /// The handle `value`, sealed whole from the record at `place`, takes.
    fn handle(&mut self, wtxn: &mut RwTxn<'_>, place: &str, value: &[u8]) -> Result<String> {
        if let Some(handle) = self.sealed.get(value) {
            return Ok(handle.clone());
        }
        let handle = match self.door {
            Some(SealDoor::Vault(write, at)) => seal_value_in_txn(
                write,
                wtxn,
                self.known,
                self.record,
                place,
                value,
                self.reason,
                at,
            )?,
            // A room keeps a fresh value in its own custody, and a value
            // base custody already holds whole keeps that record's handle,
            // as the plan's own values do (ROOM-LOCAL-CUSTODY).
            Some(SealDoor::Room(room)) => match held_whole(self.known, value) {
                Some(handle) => handle,
                None => room.keep_room_secret(value, self.reason)?,
            },
            // With no door nothing is minted (FIX 6647): only a value
            // custody already holds whole takes a handle.
            None => held_whole(self.known, value).ok_or_else(|| secret_scan_error(self.reason))?,
        };
        self.sealed.insert(value.to_vec(), handle.clone());
        Ok(handle)
    }

    /// `text`, sealed whole from `place`: it keeps its handle as
    /// `[secret sc12]`.
    fn seal_text(&mut self, wtxn: &mut RwTxn<'_>, place: &str, text: &mut String) -> Result<()> {
        let handle = self.handle(wtxn, place, text.as_bytes())?;
        replace_wiped(text, format!("{HANDLE_OPEN}{handle}]"));
        Ok(())
    }

    /// The value at `path` in the body `data` decodes to sealed, or with no
    /// path the whole body, which keeps its handle as `[secret sc12]`.
    fn seal_body(
        &mut self,
        wtxn: &mut RwTxn<'_>,
        place: &str,
        data: &mut Vec<u8>,
        path: Option<Vec<usize>>,
    ) -> Result<()> {
        let Some(path) = path else {
            let handle = self.handle(wtxn, place, data.as_slice())?;
            replace_wiped(data, format!("{HANDLE_OPEN}{handle}]").into_bytes());
            return Ok(());
        };
        let (mut tree, form) = body_tree(data).ok_or(Error::InvariantViolation(
            "a sealed body no longer decodes as its plan read it",
        ))?;
        self.seal_value(wtxn, place, &mut tree.0, form, &path)?;
        replace_wiped(data, encode_body(&tree.0, form)?);
        Ok(())
    }

    /// The value at `path` in `tree`, held as its bytes in `form`
    /// (`value_bytes`), sealed: its handle takes its place whole.
    fn seal_value(
        &mut self,
        wtxn: &mut RwTxn<'_>,
        place: &str,
        tree: &mut Value,
        form: BodyForm,
        path: &[usize],
    ) -> Result<()> {
        let value = part_at(tree, path)
            .map(|part| value_bytes(&*part, form))
            .ok_or_else(unnamed)??;
        let handle = self.handle(wtxn, place, &value)?;
        put_handle_at(tree, path, &handle)
    }
}

/// The handle of the custody record `known` says holds `value` whole.
fn held_whole(known: Option<&KnownValues>, value: &[u8]) -> Option<String> {
    known.and_then(|known| match known.spans(value).as_slice() {
        [whole] if whole.span == (0..value.len()) => Some(whole.handle.to_owned()),
        _ => None,
    })
}

/// The handle `value`, sealed whole from `record` at `place`, takes: that of
/// the custody record `known` says holds it whole, else a new active
/// record's, minted in `wtxn` with its mask origin and the owner's
/// found-key notice, as the plan's own values are.
#[expect(
    clippy::too_many_arguments,
    reason = "one custody write: its door, its known values, the value, its origin and its time"
)]
pub(in crate::batch::secret_scan::mask) fn seal_value_in_txn(
    write: &CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    known: Option<&KnownValues>,
    record: EntityId,
    place: &str,
    value: &[u8],
    reason: &'static str,
    at: u64,
) -> Result<String> {
    if let Some(handle) = held_whole(known, value) {
        return Ok(handle);
    }
    let mut plan = Masker::default();
    plan.found.push(Found {
        value: Zeroizing::new(value.to_vec()),
        reason,
        record,
        place: place.to_owned(),
    });
    let minted = plan.mint(write, wtxn, at)?;
    minted
        .get(value)
        .map(|(handle, _)| handle.clone())
        .ok_or(Error::InvariantViolation(
            "a sealed value's custody record has no handle",
        ))
}
