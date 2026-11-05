//! Core half of `store::key_custody::recovery::takeover`: its store-layer items live in `oneiron_store::key_custody::recovery::takeover` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::key_custody::recovery::takeover::*;

use super::{
    AnchorAdvance, AnchorStore, CustodyLanding, CustodyPosition, R, Rejected, anchor_record,
    anchored_position, because,
};
use crate::error::Error;
use crate::store::Store;

impl CustodyLanding {
    /// The advance this landing's takeover publishes, read once every
    /// private step is done: the landed custody's final position in `store`,
    /// the restored vault's, at the takeover epoch, tagged under that epoch's
    /// control. `None` where admission read no anchor record (none is
    /// configured), which advances nothing.
    pub(crate) fn prepare_takeover(
        &self,
        store: &Store,
    ) -> std::result::Result<Option<PreparedTakeover>, Rejected> {
        let Some(read) = &self.admitted.anchor else {
            return Ok(None);
        };
        let (taken, control) = self.admitted.taken_over()?;
        let current = anchored_position(read).map_err(because(R::AnchorInvalid))?;
        if !current.same_lineage(&taken) {
            return Err(Rejected::new(
                R::CustodyLineageMismatch,
                super::refused("the custody anchor record is another vault's".into()),
            ));
        }
        let local = landed_position(store)?;
        if !local.same_lineage(&taken) || local.epoch != taken.epoch || local.seq < taken.seq {
            return Err(Rejected::new(
                R::CustodyLandingFailed,
                super::refused("the restored vault's custody is not the one it landed".into()),
            ));
        }
        Ok(Some(PreparedTakeover {
            expected: *blake3::hash(read).as_bytes(),
            record: anchor_record(&local, &control),
        }))
    }

    /// Publishes `prepared` to `anchor`, the restore's last fallible step,
    /// the landed custody armed to stay first. The anchor moved since
    /// admission: refused, definitively, and disarmed. The advance failed:
    /// it may have happened, so the landing stays.
    pub(crate) fn publish_takeover(
        &mut self,
        anchor: &dyn AnchorStore,
        prepared: &PreparedTakeover,
    ) -> std::result::Result<(), TakeoverRefusal> {
        self.preserved = true;
        match anchor.advance(Some(prepared.expected), &prepared.record) {
            Ok(AnchorAdvance::Advanced) => Ok(()),
            Ok(AnchorAdvance::Moved) => {
                self.preserved = false;
                Err(TakeoverRefusal::Definitive(Rejected::new(
                    R::AnchorMoved,
                    super::refused(
                        "this vault's custody moved on while the restore ran; run the restore \
                         again"
                            .into(),
                    ),
                )))
            }
            Err(error) => Err(TakeoverRefusal::Uncertain(Rejected::new(
                R::AnchorUnavailable,
                error,
            ))),
        }
    }
}

/// The local custody position of the vault open on `store`: the landed
/// custody's journal, after every step journaled there.
fn landed_position(store: &Store) -> std::result::Result<CustodyPosition, Rejected> {
    let custody = store.core.key_custody.local().ok_or_else(|| {
        Rejected::new(
            R::CustodyLandingFailed,
            Error::InvalidConfig("the restored vault holds no local custody".into()),
        )
    })?;
    custody
        .journal()
        .and_then(|journal| journal.position())
        .map_err(Rejected::from)
}
