//! Borrowed published spill bytes for the HOST's exact live-session capture.

use std::io::{self, Read};
use std::sync::Arc;

use super::registry::{
    OffRecordSessionEntry, live_session_entry, session_entry_state, vet_off_record_session_ref,
};
use crate::code_run::CodeRunRawOutput;
use crate::compaction::output::OutputRef;
use crate::error::OffRecordError;
use crate::session_overlay::{OverlayKeyspace, OverlaySnapshot, SnapshotMergeRow};
use crate::store::result_body_rows::{RAW_OUTPUTS, STORED_FILE, split_row};
use crate::store::{BODY_KEYS, BodyDir, BodyFile};
use crate::vault::VaultId;
use crate::{EntityId, Error, Result, Vault};

/// Source identity, not authority to request a capture. The instance is the
/// shell minted once at entry, not the reusable registry key or its clock.
pub(crate) struct LiveSessionSpillIdentity {
    source_vault: VaultId,
    session_ref: String,
    instance: EntityId,
}

impl LiveSessionSpillIdentity {
    pub(crate) fn source_vault(&self) -> VaultId {
        self.source_vault
    }

    pub(crate) fn session_ref(&self) -> &str {
        &self.session_ref
    }

    pub(crate) fn instance(&self) -> EntityId {
        self.instance
    }
}

/// A final overlay snapshot and its existing body directory. Constructed only
/// by close, after the covered instance has stopped installing segments.
pub(crate) struct PublishedSessionSpill {
    identity: LiveSessionSpillIdentity,
    snapshot: OverlaySnapshot,
    dir: BodyDir,
    bodies: Vec<PublishedBody>,
}

struct PublishedBody {
    raw_key: Vec<u8>,
    raw_file_row: Vec<u8>,
    reference: OutputRef,
}

impl PublishedSessionSpill {
    pub(crate) fn identity(&self) -> &LiveSessionSpillIdentity {
        &self.identity
    }

    pub(crate) fn body_count(&self) -> usize {
        self.bodies.len()
    }

    /// The output is a native digest/length reference, NOT an occurrence's
    /// path, kind, completion or preview. No file key leaves this getter.
    pub(crate) fn for_each_published_body(
        &self,
        mut visit: impl FnMut(&[u8], &[u8], &CodeRunRawOutput, &mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        for body in &self.bodies {
            let reference = &body.reference;
            let key = self.snapshot.staged_value(
                OverlayKeyspace::VaultMeta,
                &BODY_KEYS.key_bytes(&reference.hash),
            );
            let key = key.map(|bytes| BODY_KEYS.decode_value(bytes)).transpose()?;
            if self.dir.sealed.is_some()
                && key.as_ref().is_none_or(|key| key.is_vault() || key.inline)
            {
                return Err(Error::CorruptedIndex("off-record published body key"));
            }
            let mut file = self
                .dir
                .open_reader(&reference.hash, reference.byte_len, key.as_ref())?
                .ok_or(Error::CorruptedIndex("off-record published body missing"))?;
            let mut reader = CheckedBody {
                file: &mut file,
                digest: blake3::Hasher::new(),
                read: 0,
            };
            let output = CodeRunRawOutput::of_ref(*reference);
            visit(&body.raw_key, &body.raw_file_row, &output, &mut reader)?;
            if reader.read != reference.byte_len
                || reader.digest.finalize().as_bytes() != &reference.hash
            {
                return Err(Error::CorruptedIndex("off-record captured body changed"));
            }
        }
        Ok(())
    }
}

struct CheckedBody<'file> {
    file: &'file mut BodyFile,
    digest: blake3::Hasher,
    read: u64,
}

impl Read for CheckedBody<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.file.read(out)?;
        self.read = self
            .read
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("off-record captured body length overflow"))?;
        self.digest.update(&out[..read]);
        Ok(read)
    }
}

/// This says nothing about unfinished writers or their written `.tmp` bytes.
/// In particular NoPublishedSpill must never acknowledge a whole hold order.
pub(super) enum PublishedSpillOutcome {
    NoPublishedSpill,
    CapturedPublishedSpill,
}

impl Vault {
    /// The HOST-only registry insertion runs under the lock close uses to
    /// publish `closing`, so an admitted request cannot miss close's batch.
    pub(crate) fn with_live_spill_target<T>(
        &self,
        session_ref: &str,
        instance: EntityId,
        register: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        vet_off_record_session_ref(session_ref)?;
        let entry = live_session_entry(&self.store, session_ref)?;
        let state = session_entry_state(&entry)?;
        if state.gone || state.overlay_shell != instance {
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionNotFound {
                session_ref: session_ref.to_owned(),
            }));
        }
        if state.record.closing {
            return Err(Error::OffRecord(OffRecordError::OffRecordSessionClosing {
                session_ref: session_ref.to_owned(),
            }));
        }
        register()
    }
}

pub(super) fn with_closing_published_spill(
    vault: &Vault,
    session_ref: &str,
    entry: &Arc<OffRecordSessionEntry>,
    instance: EntityId,
    capture: impl FnOnce(&PublishedSessionSpill) -> Result<()>,
) -> Result<PublishedSpillOutcome> {
    {
        let state = session_entry_state(entry)?;
        if state.gone || state.overlay_shell != instance || !state.record.closing {
            return Err(Error::InvariantViolation(
                "live spill capture target changed",
            ));
        }
    }
    let _custody = vault.store.gate_custody_read_guard()?;
    entry.overlay.seal_writes()?;
    let snapshot = entry.overlay.snapshot()?;
    let rows = snapshot.merge_plan(OverlayKeyspace::VaultMeta, |key| {
        key.starts_with(RAW_OUTPUTS.decl().prefix)
            && snapshot
                .staged_value(OverlayKeyspace::VaultMeta, key)
                .is_some_and(|value| matches!(split_row(value), Some((STORED_FILE, _))))
    });
    let mut bodies = Vec::new();
    for row in rows.rows {
        if let SnapshotMergeRow::Single {
            key,
            value: Some(value),
        } = row
        {
            let (hash, byte_len) = crate::code_run::code_run_body_file_of_row(&key, &value)
                .ok_or(Error::CorruptedIndex("off-record published body row"))?;
            bodies.push(PublishedBody {
                raw_key: key,
                raw_file_row: value,
                reference: OutputRef { hash, byte_len },
            });
        }
    }
    if bodies.is_empty() {
        return Ok(PublishedSpillOutcome::NoPublishedSpill);
    }
    let dir = vault
        .store
        .session_body_dir(session_ref, false)?
        .ok_or(Error::CorruptedIndex(
            "off-record published body directory missing",
        ))?;
    let source = PublishedSessionSpill {
        identity: LiveSessionSpillIdentity {
            source_vault: vault.vault_id(),
            session_ref: session_ref.to_owned(),
            instance,
        },
        snapshot,
        dir,
        bodies,
    };
    // The collector returns only after its actual durable, exact ACK. This
    // source and its snapshot lease drop before ordinary overlay close.
    capture(&source)?;
    Ok(PublishedSpillOutcome::CapturedPublishedSpill)
}
