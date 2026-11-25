//! One unit claim as the unit doors answer it (`vault.arms.units.reserve`, `.cancel`).

use serde::{Deserialize, Serialize};

use crate::gpu_line::{ClaimKey, ClaimState, Draw, UnitClaim, UnitEnd, UnitPurpose, claim_in_txn};
use crate::{EntityId, Vault};

/// One unit claim as the doors answer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnitView {
    /// The claim's id, fixed at the reservation: also its GPU job's id.
    pub job: EntityId,
    pub arm: EntityId,
    pub rung: u8,
    pub unit_key: String,
    pub attempt: u16,
    pub purpose: UnitPurpose,
    /// `claimed` (no job yet), `started` or `ended`.
    pub state: String,
    /// How it ended: `settled`, `released: <reason>`, `box_lost` or `written_off`; `None`
    /// while it is open.
    pub end: Option<String>,
    /// The machine's limit for the unit's job: its reserved seconds.
    pub maximum_secs: u64,
    /// Where its seconds come from, in draw order.
    pub draws: Vec<Draw>,
    /// The seconds the period's allocation has left with this claim in it; `None` when this
    /// call wrote no new claim.
    pub room_left_secs: Option<u64>,
    /// True when the door answered a claim it had already written.
    #[serde(default)]
    pub replayed: bool,
}

impl UnitView {
    pub(super) fn of(claim: &UnitClaim, room_left_secs: Option<u64>, replayed: bool) -> Self {
        let (state, end) = match &claim.state {
            ClaimState::Claimed => ("claimed", None),
            ClaimState::Started => ("started", None),
            ClaimState::Ended(terminal) => ("ended", Some(end_named(&terminal.end))),
        };
        Self {
            job: claim.id,
            arm: claim.arm,
            rung: claim.rung,
            unit_key: claim.unit_key.clone(),
            attempt: claim.attempt,
            purpose: claim.purpose,
            state: state.to_owned(),
            end,
            maximum_secs: claim.reserved_secs,
            draws: claim.draws.clone(),
            room_left_secs,
            replayed,
        }
    }

    /// This view with its claim's state and end as they stand now in `vault`, after the door
    /// acted on the unit's job (its start, its cancel); the room and the replay stay the door's.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn current(self, vault: &Vault) -> crate::Result<Self> {
        let key = ClaimKey::of(self.arm, self.rung, &self.unit_key, self.attempt);
        let txn = vault.store.env.read_txn()?;
        Ok(match claim_in_txn(vault, &txn, &key)? {
            Some(claim) => Self::of(&claim, self.room_left_secs, self.replayed),
            None => self,
        })
    }
}

fn end_named(end: &UnitEnd) -> String {
    match end {
        UnitEnd::Settled => "settled".to_owned(),
        UnitEnd::Released(reason) => format!("released: {reason}"),
        UnitEnd::BoxLost => "box_lost".to_owned(),
        UnitEnd::WrittenOff { .. } => "written_off".to_owned(),
    }
}
