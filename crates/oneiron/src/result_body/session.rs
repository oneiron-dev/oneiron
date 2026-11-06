//! Released session bodies. Each session owns a separate body directory;
//! its collector changes only that overlay and never retires vault custody.

use std::sync::Arc;

use super::files::{sync_dir, unlink_session_digest};
use super::{RAW_OUTPUT_ROWS, ResultBodyCollectReport, raw_output_handle, unowned_mark_key};
use crate::provenance::body::digest_is_held_in_txn;
use crate::session_overlay::{OverlayKeyspace, SessionOverlay, SnapshotMergeRow};
use crate::side_table::SideKey;
use crate::store::owned_body::BODY_RELEASED;
use crate::store::{BODY_KEYS, SessionStoreView};
use crate::{Result, Vault};

impl Vault {
    /// The existing collector retries pinned and shared session releases too.
    /// A room that cannot take a segment is left to its close, as in the
    /// actor sweep; one room's failure never prevents canonical collection.
    pub(super) fn collect_released_session_bodies(&self, limit: usize) -> ResultBodyCollectReport {
        let mut report = ResultBodyCollectReport::default();
        let mut remaining = limit;
        for (session_ref, overlay) in self.store.off_record_sessions.live_overlay_bindings() {
            if remaining == 0 {
                break;
            }
            match self.collect_one_session(&session_ref, &overlay, remaining, &mut report) {
                Ok(seen) => remaining = remaining.saturating_sub(seen),
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    "released room bodies left for the next collector pass or room close"
                ),
            }
        }
        report
    }

    fn collect_one_session(
        &self,
        session_ref: &str,
        overlay: &Arc<SessionOverlay>,
        limit: usize,
        report: &mut ResultBodyCollectReport,
    ) -> Result<usize> {
        let (segment, taken, seen) = self.with_write_txn_grouped(|txn| {
            let segment = overlay.install_txn_segment()?;
            let view = self.store.session_view(overlay.clone())?;
            let prefix = BODY_RELEASED.decl().prefix;
            let snapshot = overlay.snapshot()?;
            let plan =
                snapshot.merge_plan(OverlayKeyspace::VaultMeta, |key| key.starts_with(prefix));
            let digests: Vec<[u8; 32]> = plan
                .rows
                .into_iter()
                .filter_map(|row| match row {
                    SnapshotMergeRow::Single {
                        key,
                        value: Some(_),
                    } => key
                        .strip_prefix(prefix)
                        .and_then(<[u8; 32] as SideKey>::decode_key),
                    _ => None,
                })
                .take(limit)
                .collect();
            let mut taken = Vec::new();
            for digest in &digests {
                let retired = self
                    .result_body_pins
                    .unless_pinned(digest, || -> Result<bool> {
                        if self.session_digest_held(&view, txn, digest)? {
                            report.held += 1;
                            return Ok(false);
                        }
                        RAW_OUTPUT_ROWS.delete(&view, txn, &raw_output_handle(digest))?;
                        crate::code_run::drop_code_run_result_marks_in_txn(
                            &view,
                            txn,
                            &unowned_mark_key(digest)?,
                        )?;
                        Ok(true)
                    });
                match retired {
                    Some(Ok(true)) => taken.push(*digest),
                    Some(Ok(false)) => {}
                    Some(Err(error)) => return Err(error),
                    None => report.pinned += 1,
                }
            }
            Ok((segment, taken, digests.len()))
        })?;
        // No unlink before BOTH the base writer and this overlay segment
        // committed. The key and release row stay as retry metadata.
        segment.commit()?;
        if taken.is_empty() {
            return Ok(seen);
        }
        let dir = self.store.session_body_dir(session_ref, false)?;
        let segment = self.with_write_txn_grouped(|txn| {
            let segment = overlay.install_txn_segment()?;
            let view = self.store.session_view(overlay.clone())?;
            for digest in &taken {
                let handle = raw_output_handle(digest);
                if RAW_OUTPUT_ROWS.contains(&view, txn, &handle)?
                    || self.session_digest_held(&view, txn, digest)?
                {
                    report.held += 1;
                    continue;
                }
                let removed = self
                    .result_body_pins
                    .unless_pinned(digest, || -> Result<()> {
                        let key = BODY_KEYS
                            .get(&view, txn, digest)?
                            .filter(|key| !key.is_vault());
                        if let Some(dir) = &dir {
                            unlink_session_digest(dir, digest)?;
                            sync_dir(dir)?;
                        }
                        if key.is_some() {
                            BODY_KEYS.delete(&view, txn, digest)?;
                            report.keys_retired += 1;
                        }
                        BODY_RELEASED.delete(&view, txn, digest)?;
                        report.collected += 1;
                        Ok(())
                    });
                match removed {
                    Some(result) => result?,
                    None => report.pinned += 1,
                }
            }
            Ok(segment)
        })?;
        segment.commit()?;
        Ok(seen)
    }

    /// Composed holders plus canonical references: an overlay shadow never
    /// makes another owner's base copy cease to be a live reference. A raw
    /// row's independent hold also survives an occurrence's release.
    fn session_digest_held(
        &self,
        view: &SessionStoreView<'_>,
        txn: &heed::RoTxn<'_>,
        digest: &[u8; 32],
    ) -> Result<bool> {
        Ok(digest_is_held_in_txn(view, txn, digest)?
            || digest_is_held_in_txn(&self.store, txn, digest)?
            || crate::code_run::code_run_body_held_in_txn(view, txn, digest)?
            || RAW_OUTPUT_ROWS.contains(&self.store, txn, &raw_output_handle(digest))?)
    }
}
