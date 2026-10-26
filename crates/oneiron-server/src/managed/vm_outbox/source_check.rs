//! A put the other end refused as `digest_mismatch` (FIX 11075): its bytes
//! did not hash, on arrival, to the digest the transfer named. Damage in
//! transit passes, so the put is not dropped for good: its set goes again at
//! the pacing of a deferral, with no clock or cap of its own, and that next
//! paced look reads this end's file again whole, hashes it, and sends it
//! again while it still hashes to the digest recorded for it, even where
//! that is the agreed version: the put that named it did not arrive whole.
//! The status stands until that put is recorded as sent, so a look whose set
//! does not go reads it again at the next. A file that no longer hashes to
//! it, unchanged since, is damaged here: its record keeps a typed
//! [`SourceStatus::SourceDigestMismatch`], and none of it is sent until the
//! member changes.

use super::Carrier;
use super::local::FileStamp;
use super::store::{MemberRecord, SourceStatus, Version};
use oneiron_vault_contract::vm_outbox::{
    VmOutboxDescriptor, VmOutboxKind, VmOutboxOperation, VmOutboxOutcome, VmOutboxRefusal,
};
use std::time::Instant;

/// How a scan takes a member this end originates, by its source status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SourceScan {
    /// As any member: its cached digest stands while its stamp does.
    Cached,
    /// Its file is read again whole and hashed, its cached digest aside.
    Reread,
    /// Not at all: its set's pacing is not due yet, or its file is damaged.
    Skip,
}

/// Whether the other end's `outcome` sends its set again at the set's
/// pacing: a deferral, or a put whose bytes did not hash to its digest on
/// arrival.
pub(super) fn paces(outcome: &VmOutboxOutcome) -> bool {
    matches!(
        outcome,
        VmOutboxOutcome::Deferred { .. }
            | VmOutboxOutcome::Refused {
                code: VmOutboxRefusal::DigestMismatch,
                ..
            }
    )
}

/// Records in `record` a refusal `code` of `transfer` that is a put whose
/// bytes did not hash to its digest on arrival: the set's next paced look
/// reads the file again. `false`, and nothing recorded, for any other.
pub(super) fn recheck(
    record: &mut MemberRecord,
    transfer: &VmOutboxDescriptor,
    code: VmOutboxRefusal,
) -> bool {
    let damaged =
        code == VmOutboxRefusal::DigestMismatch && transfer.operation == VmOutboxOperation::Put;
    if damaged {
        record.source = Some(SourceStatus::Recheck {
            blake3: transfer.blake3.clone(),
        });
    }
    damaged
}

/// Whether `version` of a file is the put the other end refused as
/// `digest_mismatch`, read again and still hashing to its digest: it goes
/// again even where it is the agreed version or a refused change.
pub(super) fn resends(record: &MemberRecord, version: &Version) -> bool {
    matches!(
        &record.source,
        Some(SourceStatus::Recheck { blake3 }) if *blake3 == version.blake3
    )
}

impl Carrier {
    /// How `kind`'s scan at `now` takes the member of `set` whose record is
    /// `record`, its file listed at `stamp`, by that record's source status.
    /// A damaged status the member changed past is cleared in `record`,
    /// which the scan writes.
    pub(super) fn source_scan(
        &self,
        kind: VmOutboxKind,
        set: &str,
        stamp: FileStamp,
        record: &mut MemberRecord,
        now: Instant,
    ) -> SourceScan {
        let scan = match &record.source {
            None => return SourceScan::Cached,
            Some(SourceStatus::SourceDigestMismatch { stamp: damaged, .. }) => {
                (*damaged == stamp).then_some(SourceScan::Skip)
            }
            // Read again once its set's pacing is due, changed since or not:
            // a file changed back to the refused bytes still sends them.
            Some(SourceStatus::Recheck { .. }) => Some(
                if self
                    .paced
                    .get(&(kind, set.to_owned()))
                    .is_some_and(|(at, _)| *at > now)
                {
                    SourceScan::Skip
                } else {
                    SourceScan::Reread
                },
            ),
        };
        // The member changed since: it goes as any change.
        scan.unwrap_or_else(|| {
            record.source = None;
            SourceScan::Cached
        })
    }

    /// Whether `member`'s file, read again at `stamp` as `version`, goes:
    /// one that still hashes to the digest the refused put named keeps its
    /// status and goes again ([`resends`]), and one changed since that
    /// digest was recorded has its status cleared and goes as any change.
    /// One unchanged that no longer hashes to it is damaged here: `record`
    /// keeps that, typed, and it does not go.
    pub(super) fn source_goes(
        &self,
        kind: VmOutboxKind,
        member: &str,
        record: &mut MemberRecord,
        stamp: FileStamp,
        version: &Version,
    ) -> bool {
        let recorded = match record.source.take() {
            Some(SourceStatus::Recheck { blake3 }) => blake3,
            other => {
                record.source = other;
                return true;
            }
        };
        if version.blake3 == recorded {
            record.source = Some(SourceStatus::Recheck { blake3: recorded });
            return true;
        }
        let unchanged = record
            .cached
            .as_ref()
            .is_some_and(|cached| cached.stamp == stamp && cached.version.blake3 == recorded);
        if !unchanged {
            return true;
        }
        tracing::warn!(
            reason = "vm_outbox_source_digest_mismatch",
            side = ?self.side,
            %kind,
            member,
            %recorded,
            read = %version.blake3,
            "an outbox member's file no longer hashes to its recorded digest; \
             it is not sent again until it changes"
        );
        record.source = Some(SourceStatus::SourceDigestMismatch {
            stamp,
            recorded,
            read: version.blake3.clone(),
        });
        false
    }
}
