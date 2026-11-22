//! A published weave period's inbox notice, born from the rows its period
//! reads (RECIPIENT-NOTICE-READ-BY-ANY-READER, owner half; Engine ANSWER
//! 21 Nov 06:28: "the owner reads a member's notice body exactly when he
//! can read the sources it came from"). The birth names each row a reopen
//! of the period reads before it serves ([`report_sources`]), so the notice
//! reads to a reader of every one of them, as the period does: the vault's
//! owner reads a member's period notice only when he reads its sources. A
//! period that reads no row stays a plain notice, and so does the owner's
//! due notice of a period not yet rendered.

use super::{WeaveDigestReader, WeaveReport, report_sources};
use crate::edge::EdgeActorClass;
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::{EntityId, Result, Vault, WriteActor};

/// The door that publishes a weave period, named in its notice's birth.
const WEAVE_PERIOD_PUBLISH_DOOR: &str = "weave.digest.publish";

impl WeaveDigestReader {
    /// The reader as the writer of its period's notice: its own read
    /// renders the period, or, for an owner, his own recorded schedule.
    fn notice_writer(self) -> WriteActor {
        let class = match self {
            Self::Agent(_) => EdgeActorClass::Agent,
            Self::Person(_) | Self::Owner(_) | Self::Admin(_) => EdgeActorClass::Human,
        };
        WriteActor::new(self.id(), class)
    }
}

impl Vault {
    /// Records `reader`'s notice of its period `scheduled_for`, published
    /// with `report`, in `txn`: born from the rows the period reads, or
    /// plain when it reads none. Recording it again finds its row.
    ///
    /// # Errors
    ///
    /// A report row whose ref does not decode, and storage failures.
    pub(super) fn record_weave_period_notice_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        reader: WeaveDigestReader,
        scheduled_for: u64,
        report: &WeaveReport,
        now: u64,
    ) -> Result<EntityId> {
        let event = reader.notification(scheduled_for, now);
        let sources: Vec<EntityId> = report_sources(report)?.into_iter().collect();
        match RowBirth::written(
            reader.notice_writer(),
            MadeByClass::Concluded,
            WEAVE_PERIOD_PUBLISH_DOOR,
            &sources,
            &[],
            now,
        ) {
            Some(birth) => self.record_derived_notification_in_txn(txn, &event, &birth),
            None => self.record_notification_in_txn(txn, &event),
        }
    }
}
