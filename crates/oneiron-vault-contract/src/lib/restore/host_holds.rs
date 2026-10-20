//! The host-order legal holds a cold managed restore carries from its
//! source (FIX 1485, FIX 6598).
//!
//! A host order's holds are runtime rows no image carries, so a vault a
//! cold restore lands has none of its source's. The supervisor reads the
//! source vault's whole host-order family over the source's ctl
//! (`host_order_holds`), under its reap freeze and before the control
//! plane's fence, a page at a time, and hands it to the restoring engine on
//! its input pipe ([`ManagedRestoreHostHolds`]), bound to the attempt and
//! the source. The engine installs it in place of the restored vault's,
//! whole, before the restore is kept, and its receipt says where the family
//! came from, or that it is not known ([`RestoreHostHoldsStatus`]). Not
//! known never fails a restore.
//!
//! A family's bytes are the engine's own serialization, opaque here: this
//! crate names no hold row. They are host-only: never logged, never in a
//! receipt, never an owner's to read.
//!
//! Pages: each answer exports the family again, whole, in one read, and
//! names BLAKE3 of all its bytes (`family_id`). A page is the next run of
//! those bytes from a byte offset, as lowercase hex, sized so the answer
//! fits a ctl line, and the next page's cursor names its offset and the
//! family's id. A cursor that names another id answers `export_changed`:
//! the supervisor starts again from the first page and never splices two
//! families. No family is kept between pages, and none is cut short.

use serde::{Deserialize, Serialize};

use super::facts::ManagedRestoreIdentity;
use super::framing::line_room;
use super::plan::{ManagedRestorePlan, RestoreSourceExpectation};
use crate::CtlResponse;

/// The source vault a host-order family is read from: the engine vault id
/// its data key is bound to, and the registry's id for it (`--vault-name`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHoldsSource {
    #[serde(with = "super::hex::array")]
    pub engine_vault_id: [u8; 32],
    pub registry_id: String,
}

impl HostHoldsSource {
    /// The source a restore plan's `source` names.
    #[must_use]
    pub fn of(expected: &RestoreSourceExpectation) -> Self {
        Self {
            engine_vault_id: expected.engine_vault_id,
            registry_id: expected.registry_id.clone(),
        }
    }
}

/// Bytes of a host-order family, as lowercase hex on the wire. Its `Debug`
/// names only how many there are.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostHoldsBytes(#[serde(with = "super::hex::bytes")] pub Vec<u8>);

impl HostHoldsBytes {
    /// BLAKE3 of the bytes: a whole family's id.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        *blake3::hash(&self.0).as_bytes()
    }
}

impl std::fmt::Debug for HostHoldsBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HostHoldsBytes({} bytes)", self.0.len())
    }
}

/// The source's host-order family on the input pipe
/// ([`ManagedRestoreInput::host_holds`](super::ManagedRestoreInput::host_holds)):
/// the whole family `host_order_holds` exported, reassembled, for the
/// attempt `identity` names (the plan's own) from the source `source` names
/// (the plan's `source.engine_vault_id` and `source.registry_id`).
/// `family_id` is BLAKE3 of `family`'s exact bytes. The engine refuses one
/// that names another attempt or source, whose bytes are not its id's, or
/// that is not one family, as an invalid input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRestoreHostHolds {
    pub identity: ManagedRestoreIdentity,
    pub source: HostHoldsSource,
    #[serde(with = "super::hex::array")]
    pub family_id: [u8; 32],
    pub family: HostHoldsBytes,
}

impl ManagedRestoreHostHolds {
    /// Why it is not bound to `plan`, if it is not: another attempt, another
    /// source, or bytes that are not `family_id`'s.
    pub fn check(&self, plan: &ManagedRestorePlan) -> Result<(), &'static str> {
        if self.identity != ManagedRestoreIdentity::of(&plan.request) {
            return Err("its host_holds names another attempt");
        }
        if self.source != HostHoldsSource::of(&plan.source) {
            return Err("its host_holds names another source");
        }
        if self.family.id() != self.family_id {
            return Err("its host_holds family is not its family_id's bytes");
        }
        Ok(())
    }
}

/// Where a continuation page of `host_order_holds` starts: the byte offset
/// into the family, and the id of the family the pages before it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHoldsCursor {
    pub offset: u64,
    #[serde(with = "super::hex::array")]
    pub family_id: [u8; 32],
}

/// Why a source vault answered no page of its host-order family. Never an
/// empty family: the supervisor hands no family for it, and the restore it
/// feeds goes on, `host_holds_unknown`, never refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostOrderHoldsNotProven {
    /// The vault is not frozen for reap: `prepare_reap` comes first.
    NotFrozen,
    /// Frozen, and a write, the lease drain or a sync session may still be
    /// live, as `prepare_reap` judges it: asked again later.
    NotQuiescent,
    /// `source` does not name this vault.
    SourceMismatch,
    /// The family did not read.
    ReadFailed,
    /// The family did not serialize.
    SerializationFailed,
    /// The family is not the one the cursor's pages came from: the
    /// supervisor starts again from the first page.
    ExportChanged,
    /// The cursor is at or past the family's end.
    CursorInvalid,
}

/// The answer to `host_order_holds`
/// ([`CtlRequest::HostOrderHolds`](crate::CtlRequest::HostOrderHolds)): a
/// page of the family, or why there is none. Only every page of one
/// `family_id` read back, in order, with BLAKE3 of the reassembled bytes
/// equal to it, is the family: anything else, an unknown state, a refusal,
/// EOF or no answer is not, and never an empty family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostOrderHoldsExport {
    /// `data` is the family's bytes from `offset`; the family is
    /// `family_bytes` long, and `next_cursor` is the page to ask for next,
    /// `null` once this page reaches the end.
    Exported {
        identity: ManagedRestoreIdentity,
        source: HostHoldsSource,
        #[serde(with = "super::hex::array")]
        family_id: [u8; 32],
        family_bytes: u64,
        offset: u64,
        data: HostHoldsBytes,
        next_cursor: Option<HostHoldsCursor>,
    },
    /// No page, and why.
    NotProven {
        identity: ManagedRestoreIdentity,
        source: HostHoldsSource,
        reason: HostOrderHoldsNotProven,
    },
}

impl HostOrderHoldsExport {
    /// The page of `family`, the family's bytes as they were just exported,
    /// at `cursor` (its start for none), sized so the whole answer fits a
    /// ctl line: `export_changed` for a cursor that names another family,
    /// `cursor_invalid` for one at or past this one's end.
    pub fn page(
        identity: &ManagedRestoreIdentity,
        source: &HostHoldsSource,
        family: &[u8],
        cursor: Option<&HostHoldsCursor>,
    ) -> anyhow::Result<Self> {
        let family_id = *blake3::hash(family).as_bytes();
        let not_proven = |reason| Self::NotProven {
            identity: identity.clone(),
            source: source.clone(),
            reason,
        };
        let start = match cursor {
            None => 0,
            Some(cursor) if cursor.family_id != family_id => {
                return Ok(not_proven(HostOrderHoldsNotProven::ExportChanged));
            }
            Some(cursor) => match usize::try_from(cursor.offset) {
                Ok(start) if start < family.len() => start,
                _ => return Ok(not_proven(HostOrderHoldsNotProven::CursorInvalid)),
            },
        };
        let page = |data: &[u8], next_cursor| Self::Exported {
            identity: identity.clone(),
            source: source.clone(),
            family_id,
            family_bytes: family.len() as u64,
            offset: start as u64,
            data: HostHoldsBytes(data.to_vec()),
            next_cursor,
        };
        let widest = HostHoldsCursor {
            offset: u64::MAX,
            family_id,
        };
        let room = line_room(&CtlResponse::HostOrderHolds {
            host_order_holds: page(&[], Some(widest)),
        })?;
        let end = family.len().min(start.saturating_add(room));
        let next_cursor = (end < family.len()).then_some(HostHoldsCursor {
            offset: end as u64,
            family_id,
        });
        Ok(page(&family[start..end], next_cursor))
    }

    /// Whether every answer naming `identity` and `source` fits a ctl line
    /// with room for family bytes: the request's codec bound.
    #[must_use]
    pub fn fits(identity: &ManagedRestoreIdentity, source: &HostHoldsSource) -> bool {
        let widest = HostHoldsCursor {
            offset: u64::MAX,
            family_id: [0; 32],
        };
        line_room(&CtlResponse::HostOrderHolds {
            host_order_holds: Self::Exported {
                identity: identity.clone(),
                source: source.clone(),
                family_id: widest.family_id,
                family_bytes: u64::MAX,
                offset: u64::MAX,
                data: HostHoldsBytes(Vec::new()),
                next_cursor: Some(widest),
            },
        })
        .is_ok()
    }

    /// Checks an `exported` page's shape: that its offset, length and next
    /// cursor agree with the family's length and id and move forward. The
    /// supervisor checks the reassembled bytes against `family_id` itself.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Self::Exported {
            family_id,
            family_bytes,
            offset,
            data,
            next_cursor,
            ..
        } = self
        {
            let end = offset
                .checked_add(data.0.len() as u64)
                .filter(|end| end <= family_bytes)
                .ok_or_else(|| anyhow::anyhow!("a host-order holds page runs past its family"))?;
            anyhow::ensure!(
                !data.0.is_empty() || *family_bytes == 0,
                "a host-order holds page carries bytes unless its family has none"
            );
            anyhow::ensure!(
                match next_cursor {
                    Some(next) => {
                        next.offset == end && next.family_id == *family_id && end < *family_bytes
                    }
                    None => end == *family_bytes,
                },
                "a host-order holds page's next cursor does not follow it"
            );
        }
        Ok(())
    }
}

/// Where a restored vault's host-order legal holds came from, as its
/// receipt says: nothing of any hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreHostHoldsStatus {
    /// The source's family on the input pipe, installed whole.
    InstalledFromPipe,
    /// The family the artifact carries, installed whole, where the input
    /// pipe carried none.
    InstalledFromArtifact,
    /// Neither: whether the source stood under a host order is not known
    /// here. The restore goes on and the vault serves; the supervisor
    /// alerts. Never a failure.
    HostHoldsUnknown,
}
