//! The e-sign delivery outbox (OF-415, FIX 3577): the seam that hands each
//! authorized `esign.delivery` intent to the host's sender as a file. The
//! intents are the vault's own. A row reaches that queue only after OF-327
//! let it through: the e-sign command's gate for an invitation, a reminder
//! or a void, the email send's for a promoted notice. This worker sends
//! nothing, and adds no authority of its own: the signing link an invitation
//! or a reminder carries is minted by the vault, under the send's authority
//! as it stands at export (FIX 5238 option 3).
//!
//! It runs only for `--esign-delivery-outbox-dir`. Each tick, under the
//! directory's `.lock`, it removes the temporaries a stop left mid-write,
//! reads the sender's acks and settles each one that echoes a current lease,
//! reclaims this kind's expired leases and retires their envelopes, then
//! claims the ready intents and writes each one's envelope:
//!
//! - `esign-delivery-<key>.json`, where `key` is the lower-hex BLAKE3 of
//!   `esign.delivery\0` and the intent's dedupe key. It carries
//!   `schema_version` 2, `kind`, `channel` ("email"), `dedupe_key`,
//!   `attempt_id` (32 lower-hex), `lease_owner`, `attempt_count`,
//!   `leased_at` and `lease_expires_at` (Unix seconds), `payload`, the
//!   queued e-sign notice copied byte for byte, `signing_link`, and
//!   `payload_sha256`, the lower-hex SHA-256 of the content delivered: the
//!   payload's bytes as the file holds them and, with a link, a NUL, its
//!   `url`, a NUL and its `hard_expires_at` as 8 big-endian bytes.
//! - `signing_link` is null for every notice but an invitation or a
//!   reminder. Those carry a fresh signing URL and its hard expiry,
//!   `{"url": "<base>/sign#<capability>", "hard_expires_at": <Unix
//!   seconds>}`: minted for this delivery, valid until the document's
//!   deadline, and never revoked by a later delivery, reminder or ack. The
//!   sender delivers that URL as given and keeps no copy of it once its
//!   send is retired. The base is `oauth_resource_indicator`; without a
//!   valid https one, or without the send's authority, the delivery stays
//!   queued and unexported, its reason logged. So does one whose document
//!   has an event awaiting its owner's answer (`document_awaits_owner`) or
//!   whose trail no longer reads (`document_unreadable`), on its own: the
//!   other deliveries are still claimed and written (FIX 6423).
//! - The sender answers with `esign-delivery-<key>.ack.json`. It carries
//!   `schema_version` 2, the envelope's `dedupe_key`, `attempt_id`,
//!   `lease_owner`, `attempt_count` and `payload_sha256`, a `status` of
//!   "ok" or "failed", and a `reason` (null for ok, a nonempty code for
//!   failed).
//! - Once an ok completes an intent, the vault answers with
//!   `esign-delivery-<key>.done.json`, its completion receipt
//!   ([`oneiron_vault_contract::esign_delivery`], FIX 5306): `schema_version`
//!   1, `kind`, `state` ("completed"), and the completed lease's
//!   `dedupe_key`, `attempt_id`, `lease_owner`, `attempt_count` and the
//!   envelope's `payload_sha256`.
//!
//! An ok completes the intent: its envelope goes, its receipt is written,
//! and its ack goes last. The sender removes the receipt once it has retired
//! its record of the send; until then no newer envelope is written under
//! that key, and that lease waits. A failed one goes back to the queue as
//! the same intent, its reason kept beside the earlier ones, and is tried
//! again a minute later. With no ack the lease stands until it expires; then
//! the intent is queued again, and its next claim replaces the envelope. An
//! ack that does not echo the current lease, its link included, settles
//! nothing. An invitation or reminder whose document or recipient ended
//! before its export settles unsent, its typed reason (`document_ended`,
//! `recipient_ended`) kept on the failed intent as the owner's receipt
//! (FIX 6363); it is checked before any base, directory or slot check could
//! hold it, and no envelope, ack or receipt is written for it. Nothing else
//! here fails an intent, so none is ever dropped. Both
//! sides write a file whole: a private temporary sibling, synced, renamed,
//! then the directory synced. The directory is 0700 and every file 0600: a
//! link is written only while no other user may enter it.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use oneiron::Vault;
use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases,
    CompleteAttempt, RequeueAttempt,
};
use oneiron::blob_artifact::esign::{EsignCapability, EsignDeliveryEndReason, EsignDeliveryMint};
use oneiron_vault_contract::esign_delivery::{
    ESIGN_DELIVERY_FILE_PREFIX as FILE_PREFIX, ESIGN_DELIVERY_KIND as DELIVERY_KIND,
    ESIGN_DELIVERY_LEASE_OWNER as LEASE_OWNER,
};

use self::files::{
    read_if_present, remove_if_present, remove_if_unchanged, sync_dir, write_atomic,
};
use self::signing_links::{SigningLink, delivered_digest};
use self::wire::{
    Ack, AckStatus, Export, FileRole, ack_binds, envelope_bytes, export, hex, parse_ack,
    parse_fence, parse_name,
};
use crate::server::{HousekeepingAdmission, SyncServer};

mod completion;
mod files;
mod signing_links;
mod wire;

/// How often the outbox runs.
const POLL: Duration = Duration::from_secs(15);
/// How long an exported intent waits for its ack before it is queued again.
const LEASE_SECS: u64 = 300;
/// How long an intent its sender failed waits before its next try.
const RETRY_DELAY_SECS: u64 = 60;
/// The version of the envelope and the ack.
const SCHEMA_VERSION: u32 = 2;
/// The channel an e-sign intent is delivered on.
const CHANNEL: &str = "email";
const ENVELOPE_SUFFIX: &str = ".json";
const ACK_SUFFIX: &str = ".ack.json";
/// Held for a tick, so two publishers never share the directory.
const LOCK_FILE: &str = ".lock";

/// Starts the outbox on `dir`. Each tick runs only while `admit` gives a
/// guard (a managed vault frozen for reap exports nothing), and holds it to
/// the tick's end, its file writes included.
pub(crate) fn spawn(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
    dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    let signing_base =
        signing_links::signing_base(server.config.oauth_resource_indicator.as_deref());
    if let Err(reason) = signing_base {
        tracing::warn!(reason, "esign invitations and reminders wait unexported");
    }
    let weak = Arc::downgrade(&server);
    drop(server);
    tracing::info!(dir = %dir.display(), "esign delivery outbox runs");
    let outbox = Arc::new(Outbox { dir, signing_base });
    tokio::spawn(async move {
        let mut every = tokio::time::interval(POLL);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // A stop may have come between a claim and its envelope's write.
        let mut recover = true;
        loop {
            every.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            let Some(pass) = admit() else {
                continue;
            };
            let outbox = Arc::clone(&outbox);
            let ran = tokio::task::spawn_blocking(move || {
                let _pass = pass;
                outbox.tick(server.vault(), recover)
            })
            .await;
            recover = match ran {
                Ok(Ok(pending)) => pending,
                Ok(Err(error)) => {
                    tracing::warn!(
                        error = %format!("{error:#}"),
                        "esign delivery outbox pass failed; it runs again next tick"
                    );
                    true
                }
                Err(error) => {
                    tracing::warn!(%error, "esign delivery outbox pass stopped");
                    true
                }
            };
        }
    })
}

struct Outbox {
    dir: PathBuf,
    /// The https base signing links are built on, or why there is none.
    signing_base: Result<String, &'static str>,
}

/// What an invitation's or reminder's envelope came to.
enum LinkedEnvelope {
    /// The envelope, a link minted for this lease in it.
    Ready(Vec<u8>),
    /// No link can be minted now, for this reason; the lease waits.
    Held(&'static str),
    /// The delivery's document or recipient ended: it settled unsent.
    Settled(EsignDeliveryEndReason),
}

/// What writing one lease's envelope came to, least pressing first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Published {
    /// Written, already written, or left unexported (not an e-sign notice).
    Done,
    /// Its slot still holds a completion the sender has not taken, or its
    /// link cannot be minted yet: the lease stays leased and unwritten.
    Held,
    /// The write failed.
    Failed,
}

impl Outbox {
    /// One tick: temporaries, acks, reclaim, then envelopes. `Ok(true)` when
    /// an envelope could not be written or waits, so the next tick writes
    /// the leases it holds first; after a failed write it claims no more
    /// until those are written.
    fn tick(&self, vault: &Vault, recover: bool) -> anyhow::Result<bool> {
        let Some(_lock) = files::lock(&self.dir)? else {
            return Ok(recover);
        };
        // Under the lock no write is in flight: a temporary is a stop's.
        if files::remove_orphan_temps(&self.dir)
            .with_context(|| format!("clear the outbox {}", self.dir.display()))?
        {
            sync_dir(&self.dir).with_context(|| format!("sync {}", self.dir.display()))?;
        }
        let queue = AttemptQueue::new(vault);
        // The sender's acks settle their leases first, and the files of
        // intents no longer leased here go.
        self.settle_acks(vault, &queue)?;
        self.retire_envelopes(&queue)?;
        // This kind's leases that waited out their ack go back to the queue;
        // no other kind's lease is touched.
        let reclaimed = queue.cleanup_kind_leases(
            DELIVERY_KIND,
            CleanupAttemptLeases {
                now: unix_now(),
                lease_timeout_secs: LEASE_SECS,
            },
        )?;
        if let Some(report) = reclaimed.filter(|report| report.stale_requeued > 0) {
            tracing::info!(
                requeued = report.stale_requeued,
                "esign deliveries no ack answered are queued again"
            );
            // Their envelopes name ended leases: they go before any
            // republish, so no sender acts on one.
            self.retire_envelopes(&queue)?;
        }
        let mut pending = Published::Done;
        if recover {
            pending = self.publish_leased(vault, &queue)?;
            if pending == Published::Failed {
                return Ok(true);
            }
        }
        Ok(pending.max(self.claim_ready(vault, &queue)?) != Published::Done)
    }

    /// Settles every ack that echoes a current lease and clears the files of
    /// tries already settled.
    fn settle_acks(&self, vault: &Vault, queue: &AttemptQueue<'_>) -> anyhow::Result<()> {
        let (acks, _) = self
            .listing()
            .with_context(|| format!("read the outbox {}", self.dir.display()))?;
        let mut changed = false;
        for stem in &acks {
            match self.settle_ack(vault, queue, stem) {
                Ok(cleared) => changed |= cleared,
                Err(error) => tracing::warn!(
                    error = %format!("{error:#}"),
                    %stem,
                    "esign delivery ack not settled; it is read again next tick"
                ),
            }
        }
        if changed {
            sync_dir(&self.dir).with_context(|| format!("sync {}", self.dir.display()))?;
        }
        Ok(())
    }

    /// Removes the envelopes of leases that ended (settled, queued again or
    /// paused), so no sender acts on one.
    fn retire_envelopes(&self, queue: &AttemptQueue<'_>) -> anyhow::Result<()> {
        let (_, envelopes) = self
            .listing()
            .with_context(|| format!("read the outbox {}", self.dir.display()))?;
        let mut changed = false;
        for stem in &envelopes {
            match self.retire_envelope(queue, stem) {
                Ok(cleared) => changed |= cleared,
                Err(error) => tracing::warn!(
                    error = %format!("{error:#}"),
                    %stem,
                    "esign delivery envelope not reconciled; it is read again next tick"
                ),
            }
        }
        if changed {
            sync_dir(&self.dir).with_context(|| format!("sync {}", self.dir.display()))?;
        }
        Ok(())
    }

    /// The stems of the acks and the envelopes in the directory.
    fn listing(&self) -> io::Result<(BTreeSet<String>, BTreeSet<String>)> {
        let mut acks = BTreeSet::new();
        let mut envelopes = BTreeSet::new();
        for entry in fs::read_dir(&self.dir)? {
            let name = entry?.file_name();
            match name.to_str().and_then(parse_name) {
                Some((stem, FileRole::Ack)) => {
                    acks.insert(stem);
                }
                Some((stem, FileRole::Envelope)) => {
                    envelopes.insert(stem);
                }
                None => {}
            }
        }
        Ok((acks, envelopes))
    }

    /// Settles the lease one ack answers, when it echoes that lease, and
    /// clears the files of a try already settled. `Ok(true)` when a file
    /// went.
    fn settle_ack(
        &self,
        vault: &Vault,
        queue: &AttemptQueue<'_>,
        stem: &str,
    ) -> anyhow::Result<bool> {
        let path = self.ack_path(stem);
        let Some(bytes) = read_if_present(&path)? else {
            return Ok(false);
        };
        let Some((ack, id)) = parse_ack(&bytes) else {
            tracing::warn!(%stem, "esign delivery ack is malformed; it settles nothing");
            return Ok(false);
        };
        // A row this vault does not hold is not this outbox's to judge.
        let Some(row) = queue.get(id)? else {
            return Ok(false);
        };
        if row.kind != DELIVERY_KIND {
            return Ok(false);
        }
        let bound = binds(vault, &ack, &row, stem)?;
        if row.state == AttemptState::Leased {
            // An older lease's answer, or one that does not echo this lease,
            // leaves it standing.
            if !bound || row.lease_owner.as_deref() != Some(LEASE_OWNER) {
                return Ok(false);
            }
            settle(queue, &row, &ack)?;
            tracing::info!(
                attempt = %ack.attempt_id,
                status = ack.status.as_str(),
                "esign delivery settled by its ack"
            );
        } else if !row.state.is_terminal() {
            // Queued again or paused: its next claim retires this ack.
            return Ok(false);
        }
        // An ok that completed this try, now or before a stop that left its
        // ack, hands the slot to the sender through its completion receipt.
        let completed = matches!(row.state, AttemptState::Leased | AttemptState::Completed);
        if bound && ack.status == AckStatus::Ok && completed {
            return self.hand_off(vault, stem, &row, &path, &bytes);
        }
        // Settled, now or before a stop that left its files: they go only
        // after the commit, the envelope first, and only the ones naming
        // this try. An ack naming a settled try can never settle anything.
        if bound {
            self.remove_envelope_of(stem, &row)?;
        }
        remove_if_unchanged(&path, &bytes)?;
        Ok(true)
    }

    /// Removes an envelope whose lease ended (settled, queued again or
    /// paused), so no sender acts on it. `Ok(true)` when it went.
    fn retire_envelope(&self, queue: &AttemptQueue<'_>, stem: &str) -> anyhow::Result<bool> {
        let path = self.envelope_path(stem);
        let Some(bytes) = read_if_present(&path)? else {
            return Ok(false);
        };
        let Some((fence, id)) = parse_fence(&bytes) else {
            return Ok(false);
        };
        let Some(row) = queue.get(id)? else {
            return Ok(false);
        };
        let current = row.state == AttemptState::Leased
            && row.lease_owner.as_deref() == Some(LEASE_OWNER)
            && row.attempt_count == fence.attempt_count;
        if row.kind != DELIVERY_KIND || current {
            return Ok(false);
        }
        Ok(remove_if_unchanged(&path, &bytes)?)
    }

    /// Removes `stem`'s envelope when it names `row`'s settled lease, not a
    /// later try of the same intent.
    fn remove_envelope_of(&self, stem: &str, row: &AttemptRecord) -> io::Result<()> {
        let path = self.envelope_path(stem);
        let Some(bytes) = read_if_present(&path)? else {
            return Ok(());
        };
        let names_row = parse_fence(&bytes)
            .is_some_and(|(fence, id)| id == row.id && fence.attempt_count == row.attempt_count);
        if names_row {
            remove_if_unchanged(&path, &bytes)?;
        }
        Ok(())
    }

    /// Writes the envelope of every lease this outbox holds, after a stop, a
    /// failed write or a held slot: the most pressing outcome of them all.
    fn publish_leased(
        &self,
        vault: &Vault,
        queue: &AttemptQueue<'_>,
    ) -> oneiron::Result<Published> {
        let mut outcome = Published::Done;
        for row in queue.list()? {
            if row.kind == DELIVERY_KIND
                && row.state == AttemptState::Leased
                && row.lease_owner.as_deref() == Some(LEASE_OWNER)
            {
                outcome = outcome.max(self.publish_logged(vault, queue, &row));
            }
        }
        Ok(outcome)
    }

    /// Claims every ready intent and writes its envelope. One that could not
    /// be written stays leased, and claiming stops; one that waits stays
    /// leased and unwritten, and claiming goes on.
    fn claim_ready(&self, vault: &Vault, queue: &AttemptQueue<'_>) -> oneiron::Result<Published> {
        let mut outcome = Published::Done;
        loop {
            let claimed = queue.claim_kind(
                DELIVERY_KIND,
                ClaimAttempt {
                    lease_owner: LEASE_OWNER.to_owned(),
                    now: unix_now(),
                },
            )?;
            let ClaimOutcome::Claimed(row) = claimed else {
                return Ok(outcome);
            };
            outcome = outcome.max(self.publish_logged(vault, queue, &row));
            if outcome == Published::Failed {
                return Ok(outcome);
            }
        }
    }

    fn publish_logged(
        &self,
        vault: &Vault,
        queue: &AttemptQueue<'_>,
        row: &AttemptRecord,
    ) -> Published {
        match self.publish(vault, queue, row) {
            Ok(published) => published,
            Err(error) => {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    attempt = %hex(row.id.as_bytes()),
                    "esign delivery envelope not written; the next tick writes it"
                );
                Published::Failed
            }
        }
    }

    /// Writes `row`'s envelope for its current lease, unless the file
    /// already holds it or its slot still holds a completion the sender has
    /// not taken. An invitation or a reminder reuses the envelope this lease
    /// already wrote whole; otherwise, behind that slot guard, the vault
    /// mints its link, or holds it with the reason. A row that is not an
    /// e-sign notice with a dedupe key is left leased and unexported, never
    /// dropped.
    fn publish(
        &self,
        vault: &Vault,
        queue: &AttemptQueue<'_>,
        row: &AttemptRecord,
    ) -> anyhow::Result<Published> {
        let Some(export) = export(row) else {
            tracing::warn!(
                attempt = %hex(row.id.as_bytes()),
                "esign delivery is not an e-sign notice with a dedupe key; it stays queued, unexported"
            );
            return Ok(Published::Done);
        };
        let path = self.envelope_path(&export.stem);
        let written = read_if_present(&path)?;
        let unlinked = if export.carries_link {
            if let (Some(bytes), Some(delivered)) = (&written, vault.esign_delivery_digest(row)?)
                && signing_links::holds_lease(bytes, row, &delivered)
            {
                return Ok(Published::Done);
            }
            // An ended document or recipient settles it before a missing
            // base, an open directory or an untaken slot could hold it.
            if let Some(reason) =
                vault.settle_esign_delivery_if_ended(row.id, LEASE_OWNER, row.attempt_count)?
            {
                return Ok(self.settled(row, &export, reason));
            }
            None
        } else {
            let bytes = envelope_bytes(row, &export, None)?;
            if written.as_deref() == Some(bytes.as_slice()) {
                return Ok(Published::Done);
            }
            Some(bytes)
        };
        if self.holds_slot(vault, queue, &export.stem)? {
            tracing::debug!(
                attempt = %hex(row.id.as_bytes()),
                stem = %export.stem,
                "esign delivery waits: its slot holds a completion the sender has not taken"
            );
            return Ok(Published::Held);
        }
        let bytes = match unlinked {
            Some(bytes) => bytes,
            None => match self.linked_envelope(vault, row, &export)? {
                LinkedEnvelope::Ready(bytes) => bytes,
                LinkedEnvelope::Held(reason) => {
                    tracing::warn!(
                        attempt = %hex(row.id.as_bytes()),
                        stem = %export.stem,
                        reason,
                        "esign delivery waits unexported for its signing link"
                    );
                    return Ok(Published::Held);
                }
                LinkedEnvelope::Settled(reason) => return Ok(self.settled(row, &export, reason)),
            },
        };
        // The sender has not seen this lease, so an ack beside it answers an
        // older one.
        remove_if_present(&self.ack_path(&export.stem))?;
        write_atomic(&self.dir, &path, &bytes)
            .with_context(|| format!("write {}", path.display()))?;
        tracing::info!(
            attempt = %hex(row.id.as_bytes()),
            stem = %export.stem,
            "esign delivery written to its outbox"
        );
        Ok(Published::Done)
    }

    /// The envelope of an invitation or reminder with a link the vault
    /// minted for this lease, why none can be minted now, or the end its
    /// delivery settled on under the mint's writer.
    fn linked_envelope(
        &self,
        vault: &Vault,
        row: &AttemptRecord,
        export: &Export<'_>,
    ) -> anyhow::Result<LinkedEnvelope> {
        let base = match &self.signing_base {
            Ok(base) => base.as_str(),
            Err(reason) => return Ok(LinkedEnvelope::Held(*reason)),
        };
        if !files::is_private(&self.dir).with_context(|| format!("stat {}", self.dir.display()))? {
            return Ok(LinkedEnvelope::Held(
                "the outbox directory admits other users; links are written only to a 0700 one",
            ));
        }
        let deliver = |capability: &EsignCapability, hard_expires_at: u64| {
            delivered_digest(
                export.payload,
                Some(&SigningLink::new(base, capability, hard_expires_at)),
            )
        };
        let minted =
            vault.mint_esign_delivery_link(row.id, LEASE_OWNER, row.attempt_count, &deliver)?;
        let link = match minted {
            EsignDeliveryMint::Minted(link) => link,
            EsignDeliveryMint::Held(reason) => return Ok(LinkedEnvelope::Held(reason)),
            // FIX 6423: its document keeps this one delivery waiting, logged
            // with its typed reason; the other leases go on.
            EsignDeliveryMint::Waits(wait) => return Ok(LinkedEnvelope::Held(wait.code())),
            EsignDeliveryMint::Settled(reason) => return Ok(LinkedEnvelope::Settled(reason)),
        };
        let link = SigningLink::new(base, &link.capability, link.hard_expires_at);
        Ok(LinkedEnvelope::Ready(envelope_bytes(
            row,
            export,
            Some(&link),
        )?))
    }

    /// `row`'s lease settled unsent for `reason`: only an envelope naming
    /// that lease goes, and one that cannot go now is retired next tick
    /// with the other ended leases' files. No ack or receipt is written.
    fn settled(
        &self,
        row: &AttemptRecord,
        export: &Export<'_>,
        reason: EsignDeliveryEndReason,
    ) -> Published {
        tracing::info!(
            attempt = %hex(row.id.as_bytes()),
            stem = %export.stem,
            reason = reason.code(),
            "esign delivery settled unsent: its document or recipient ended"
        );
        if let Err(error) = self
            .remove_envelope_of(&export.stem, row)
            .and_then(|()| sync_dir(&self.dir))
        {
            tracing::warn!(
                %error,
                stem = %export.stem,
                "a settled esign delivery's envelope stays; the next tick retires it"
            );
        }
        Published::Done
    }

    fn envelope_path(&self, stem: &str) -> PathBuf {
        self.dir.join(format!("{stem}{ENVELOPE_SUFFIX}"))
    }

    fn ack_path(&self, stem: &str) -> PathBuf {
        self.dir.join(format!("{stem}{ACK_SUFFIX}"))
    }
}

/// The digest of the content `row`'s current lease delivered: its notice's
/// bytes alone, or the digest the vault recorded with the link it minted
/// for that lease. `None` before a link was minted for it.
fn delivered(
    vault: &Vault,
    row: &AttemptRecord,
    export: &Export<'_>,
) -> oneiron::Result<Option<String>> {
    if export.carries_link {
        vault.esign_delivery_digest(row)
    } else {
        Ok(Some(hex(&delivered_digest(export.payload, None))))
    }
}

/// Whether `ack` echoes `row`'s lease whole, the content it delivered
/// included.
fn binds(vault: &Vault, ack: &Ack, row: &AttemptRecord, stem: &str) -> oneiron::Result<bool> {
    let Some(export) = export(row) else {
        return Ok(false);
    };
    Ok(delivered(vault, row, &export)?
        .is_some_and(|delivered| ack_binds(ack, row, &export, stem, &delivered)))
}

/// Completes the intent on an ok. On a failed ack, the same intent goes back
/// to the queue [`RETRY_DELAY_SECS`] later with its reason kept beside the
/// earlier ones (FIX 5240): no new row per try, never a terminal failure.
fn settle(queue: &AttemptQueue<'_>, row: &AttemptRecord, ack: &Ack) -> oneiron::Result<()> {
    let now = unix_now();
    match ack.status {
        AckStatus::Ok => {
            queue.complete(CompleteAttempt {
                id: row.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: row.attempt_count,
                now,
            })?;
        }
        AckStatus::Failed => {
            queue.requeue(RequeueAttempt {
                id: row.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: row.attempt_count,
                reason: ack.reason.clone().unwrap_or_default(),
                due_at: now.saturating_add(RETRY_DELAY_SECS),
            })?;
        }
    }
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
