//! `vault.receipts`'s page as UniFFI crosses it (FIX 10186): the receipts
//! as [`FacadeReceipt`] records, the `after` the next page takes, and who
//! made each receipt's change.

use std::collections::HashMap;

use oneiron::context_board::{ActorAttribution, ActorAttributionKind};
use oneiron::task_verb::sdk;

use crate::codec::Lift;
use crate::dto::FacadeReceipt;
use crate::error::OneironError;

/// What a native page knows of the actor behind one receipt: a person the
/// reader reads, human or agent, or no one it can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FacadeActorAttributionKind {
    Human,
    Agent,
    Unknown,
}

/// Who made one receipt's change, as this reader may name them: the
/// person's PERSON id, `pr` handle, name and kind exactly as
/// `vault.people.list` shows them to this reader, or `unknown` and nothing
/// else for an actor the reader cannot name.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FacadeActorAttribution {
    pub kind: FacadeActorAttributionKind,
    /// The PERSON entity the actor speaks as.
    pub person: Option<String>,
    /// `pr<n>`.
    pub handle: Option<String>,
    pub name: Option<String>,
}

/// One page of governance receipts, newest first.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct FacadeReceiptPage {
    pub receipts: Vec<FacadeReceipt>,
    /// The next page's `after`; none once no older receipt is left.
    pub next_after: Option<String>,
    /// The receipts this page could hold: the limit, or the page size when
    /// the limit asked for more.
    pub effective_limit: u64,
    /// The limit was past the page size and this page was served at it;
    /// `next_after` continues to the rest.
    pub limit_clamped: bool,
    /// Who made each receipt's change, keyed by the `actor_ref` it names:
    /// one entry per actor on the page, `unknown` for one the reader
    /// cannot name.
    pub actors: HashMap<String, FacadeActorAttribution>,
}

impl Lift<ActorAttributionKind> for FacadeActorAttributionKind {
    fn lift(value: ActorAttributionKind) -> Result<Self, OneironError> {
        Ok(match value {
            ActorAttributionKind::Human => Self::Human,
            ActorAttributionKind::Agent => Self::Agent,
            ActorAttributionKind::Unknown => Self::Unknown,
        })
    }
}

impl Lift<ActorAttribution> for FacadeActorAttribution {
    fn lift(value: ActorAttribution) -> Result<Self, OneironError> {
        Ok(Self {
            kind: FacadeActorAttributionKind::lift(value.kind)?,
            person: value.person,
            handle: value.handle,
            name: value.name,
        })
    }
}

impl Lift<sdk::VaultReceiptsPage> for FacadeReceiptPage {
    fn lift(value: sdk::VaultReceiptsPage) -> Result<Self, OneironError> {
        Ok(Self {
            receipts: Lift::lift(value.receipts)?,
            next_after: value.next_after,
            effective_limit: u64::try_from(value.effective_limit).unwrap_or(u64::MAX),
            limit_clamped: value.limit_clamped,
            actors: value
                .actors
                .into_iter()
                .map(|(actor, attribution)| {
                    FacadeActorAttribution::lift(attribution).map(|lifted| (actor, lifted))
                })
                .collect::<Result<HashMap<_, _>, _>>()?,
        })
    }
}
