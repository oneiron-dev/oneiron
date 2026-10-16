//! OF-235: shareable inspection state and its handle link.
//!
//! An [`InspectionState`] locates what an inspector shows: one entity or one
//! claim. Its [`InspectionHandle`] is a short, bounded, canonical token a host
//! may put in a link. The token is a locator and nothing more: it carries no
//! read key, no backing token, no approval and no body, so passing it on
//! grants nothing. Decoding one yields untrusted locator data; every open is
//! a fresh point read under the viewer's own [`ScopedRead`], where a target
//! the viewer cannot read and a target that does not exist look the same.
//!
//! The engine keeps no URL, history, navigation index or peek, sheet, rail
//! and page trail: those are the host's. A host wraps the token in its own
//! link and owns Back.

use serde::{Deserialize, Serialize};

use super::{
    GeneratedUiRender, LensBackingTargetKind, LensHostBackingRef, LensReadHandle, LensRenderFrame,
};
use crate::Vault;
use crate::claim::{PointRead, ReadRow, ScopedRead, ScopedReadReceipt, ScopedReadResult};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::EntityView;
use crate::registry::ENTITY_TYPE_CLAIM;

/// The version tag every inspection handle starts with.
pub const INSPECTION_HANDLE_VERSION: &str = "i1";
/// An inspection handle's exact length: version, kind, 32-hex id.
pub const INSPECTION_HANDLE_LEN: usize = INSPECTION_HANDLE_VERSION.len() + 1 + 32;

/// What an inspector shows: one entity or one claim, by id. Locator data
/// only; it proves nothing about who may read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionState {
    pub target_ref: EntityId,
    pub target_kind: LensBackingTargetKind,
}

impl InspectionState {
    /// The state a host-minted backing row locates.
    #[must_use]
    pub fn of_backing_ref(backing: &LensHostBackingRef) -> Self {
        Self {
            target_ref: *backing.target().entity_id(),
            target_kind: backing.target().kind(),
        }
    }

    /// This state's handle.
    #[must_use]
    pub fn handle(&self) -> InspectionHandle {
        encode_inspection_handle(self)
    }
}

/// The link token for one [`InspectionState`]: `i1`, `e` (entity) or `c`
/// (claim), then the target's 32-hex id. Opaque to callers; only
/// [`decode_inspection_handle`] reads it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct InspectionHandle(String);

impl InspectionHandle {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for InspectionHandle {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        decode_inspection_handle(&value)?;
        Ok(Self(value))
    }
}

impl From<InspectionHandle> for String {
    fn from(handle: InspectionHandle) -> Self {
        handle.0
    }
}

impl std::fmt::Display for InspectionHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

const fn kind_tag(kind: LensBackingTargetKind) -> char {
    match kind {
        LensBackingTargetKind::Entity => 'e',
        LensBackingTargetKind::Claim => 'c',
    }
}

/// The one canonical handle of `state`. Pure.
#[must_use]
pub fn encode_inspection_handle(state: &InspectionState) -> InspectionHandle {
    InspectionHandle(format!(
        "{INSPECTION_HANDLE_VERSION}{}{}",
        kind_tag(state.target_kind),
        state.target_ref.to_hex()
    ))
}

/// The state a handle names, untrusted. Pure and bounded: anything but the
/// one canonical spelling of a state is refused, before any read.
pub fn decode_inspection_handle(handle: &str) -> Result<InspectionState> {
    let malformed = || Error::InvalidConfig("not an inspection handle".to_owned());
    if handle.len() != INSPECTION_HANDLE_LEN {
        return Err(malformed());
    }
    let rest = handle
        .strip_prefix(INSPECTION_HANDLE_VERSION)
        .ok_or_else(malformed)?;
    let (tag, id) = rest.split_at_checked(1).ok_or_else(malformed)?;
    let target_kind = match tag {
        "e" => LensBackingTargetKind::Entity,
        "c" => LensBackingTargetKind::Claim,
        _ => return Err(malformed()),
    };
    let target_ref = EntityId::from_hex(id).map_err(|_| malformed())?;
    let state = InspectionState {
        target_ref,
        target_kind,
    };
    if encode_inspection_handle(&state).as_str() != handle {
        return Err(malformed());
    }
    Ok(state)
}

/// `vault.inspection.resolve`'s input: a handle a host took from a link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectionResolveRequest {
    pub handle: String,
}

/// `vault.inspection.resolve`'s answer: the state the handle names and, when
/// the caller may read it now, the item. `None` is a target that is missing,
/// unreadable to this caller, or not of the handle's kind; the receipt does
/// not say which.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InspectionResolved {
    pub state: InspectionState,
    pub handle: InspectionHandle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<EntityView>,
    pub narrowing: ScopedReadReceipt,
}

fn kind_admits(kind: LensBackingTargetKind, entity_type: u8) -> bool {
    match kind {
        LensBackingTargetKind::Claim => entity_type == ENTITY_TYPE_CLAIM,
        LensBackingTargetKind::Entity => entity_type != ENTITY_TYPE_CLAIM,
    }
}

impl LensRenderFrame {
    /// The shareable state of a read handle this frame issued, re-proved
    /// against the current render first: a handle the frame no longer
    /// issues yields no state.
    pub fn inspection_state(
        &self,
        read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        handle: &LensReadHandle,
    ) -> Result<InspectionState> {
        let backing = self.resolve_read_handle(read, render, handle)?;
        Ok(InspectionState::of_backing_ref(&backing))
    }
}

impl Vault {
    /// Opens `state` for the viewer `read` reads as: one fresh point read
    /// of the live row. The row comes back only with its body, inside the
    /// read's grants and of the state's kind. A withheld target adds no
    /// count to the receipt, so unreadable and missing are the same `None`.
    pub fn inspect_state(
        &self,
        read: &ScopedRead<'_>,
        state: &InspectionState,
    ) -> Result<ScopedReadResult<Option<ReadRow>>> {
        self.inspect_state_projected(read, state, |_, row| Ok::<_, Error>(row))
    }

    /// [`Self::inspect_state`], projecting the admitted row inside the
    /// read's own snapshot.
    pub(crate) fn inspect_state_projected<T, E: From<Error>>(
        &self,
        read: &ScopedRead<'_>,
        state: &InspectionState,
        project: impl FnOnce(&heed::RoTxn<'_>, Option<ReadRow>) -> std::result::Result<T, E>,
    ) -> std::result::Result<ScopedReadResult<T>, E> {
        if !std::ptr::eq(read.vault(), self) {
            return Err(Error::InvalidConfig(
                "an inspection reads through this vault's own scoped read".to_owned(),
            )
            .into());
        }
        let target = state.target_ref;
        let kind = state.target_kind;
        read.read_projected_opaque(
            &[PointRead::id(target)],
            None,
            |_, id| Ok(*id == target),
            |txn, rows| {
                let row = rows
                    .into_iter()
                    .next()
                    .flatten()
                    .filter(|row| row.body.is_some() && kind_admits(kind, row.entity_type));
                project(txn, row)
            },
        )
    }
}
