//! The outbox's periodic tick. Each tick, under the directory's lock: the
//! intake's receipts, reconciliation, purges and controls
//! (`Vault::publisher_training_upkeep`), then, once per offer pace, an offer
//! pass (`Vault::offer_conversation_training`) when the gate lets offers be
//! written at all.
//!
//! Offers wait for the vault's admission (a managed vault frozen for reap
//! writes no offer and no row). Withdrawals do not wait on it: a tick
//! without admission still writes every control the vault already holds,
//! records nothing, and leaves recording them to the next admitted tick, so
//! what reaches `controls/` stays shippable from a cold vault.
//!
//! On a self-hosted vault with its shipper on, each tick first gives the
//! intake's descriptor (`descriptor`) its turn, admitted or not: when one is
//! due it is fetched with no lock held and installed under the outbox's
//! lock, before the tick reads the keys.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::feedback_redaction::OneironerFilter;
use crate::server::{HousekeepingAdmission, SyncServer};

use super::descriptor::Descriptor;
use super::outbox::Outbox;
use super::{OFFER_POLL, POLL, Placement, intake_receipt_key, offer_gate};

/// Starts the outbox on `dir`, with the self-host shipper's `descriptor`
/// when the shipper is on.
pub(super) fn spawn(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
    dir: PathBuf,
    placement: Placement,
    descriptor: Option<Arc<Descriptor>>,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(&server);
    drop(server);
    tracing::info!(dir = %dir.display(), "publisher training outbox runs");
    let dir = Arc::new(dir);
    tokio::spawn(async move {
        let mut every = tokio::time::interval(POLL);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_offers: Option<Instant> = None;
        loop {
            every.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            let pass = admit();
            let offers_due =
                pass.is_some() && last_offers.is_none_or(|at| at.elapsed() >= OFFER_POLL);
            if offers_due {
                last_offers = Some(Instant::now());
            }
            let dir = Arc::clone(&dir);
            let descriptor = descriptor.clone();
            let ran = tokio::task::spawn_blocking(move || {
                let admitted = pass.is_some();
                let _pass = pass;
                tick(
                    &server,
                    &dir,
                    placement,
                    descriptor.as_deref(),
                    admitted,
                    offers_due,
                )
            })
            .await;
            match ran {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(
                    error = %format!("{error:#}"),
                    "publisher training outbox pass failed; it runs again next tick"
                ),
                Err(error) => tracing::warn!(%error, "publisher training outbox pass stopped"),
            }
        }
    })
}

/// One tick, with the self-host shipper's `descriptor` when the shipper is
/// on.
fn tick(
    server: &SyncServer,
    dir: &Path,
    placement: Placement,
    descriptor: Option<&Descriptor>,
    admitted: bool,
    offers_due: bool,
) -> anyhow::Result<()> {
    if let Some(descriptor) = descriptor {
        descriptor.upkeep(dir);
    }
    let Some(outbox) = Outbox::open(dir)? else {
        return Ok(());
    };
    let vault = server.vault();
    if !admitted {
        vault.spool_training_controls(&outbox, false)?;
        return Ok(());
    }
    let receipt_key = match intake_receipt_key(dir) {
        Ok(key) => Some(key),
        Err(reason) => {
            tracing::debug!(%reason, "publisher training receipts are not applied");
            None
        }
    };
    let upkeep = vault.publisher_training_upkeep(&outbox, receipt_key.as_ref())?;
    for file in &upkeep.receipts_refused {
        tracing::warn!(
            %file,
            "a publisher training receipt is not the intake's for one of this vault's scopes; it \
             stays unapplied"
        );
    }
    if upkeep.controls_recorded + upkeep.controls_written + upkeep.receipts_applied > 0 {
        tracing::info!(
            recorded = upkeep.controls_recorded,
            written = upkeep.controls_written,
            receipts = upkeep.receipts_applied,
            purged = upkeep.offers_purged,
            "publisher training outbox reconciled"
        );
    }
    if !offers_due {
        return Ok(());
    }
    let intake = match offer_gate(dir, placement, descriptor.is_some()) {
        Ok(intake) => intake,
        Err(reason) => {
            tracing::info!(
                %reason,
                "publisher training offers are not written; withdrawals still are"
            );
            return Ok(());
        }
    };
    let filter = OneironerFilter::of_server(server);
    let pass =
        vault.offer_conversation_training(&outbox, &filter, &intake, OFFER_POLL.as_secs())?;
    if let Some(reason) = &pass.unavailable {
        tracing::info!(%reason, "a publisher training offer pass stopped early");
    }
    if !pass.published.is_empty() || !pass.withheld.is_empty() {
        tracing::info!(
            published = pass.published.len(),
            withheld = pass.withheld.len(),
            "publisher training offers released"
        );
    }
    Ok(())
}
