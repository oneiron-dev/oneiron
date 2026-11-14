//! The read-shape arm family's vault doors (ARCH-0051 #decision-r9-bench):
//! the host picks and stamps the shape a run reads through when the run
//! wakes, and records the model units it settled when it ends; the owner
//! reads and pins the picks through the retrieval policy verbs.

use rand::Rng;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::error::Result;
use crate::llm::ModelId;
use crate::store::{ReadShape, ReadShapePick, ReadShapePins, ReadShapePosterior, ReadShapeStamp};

impl Vault {
    /// Picks the shape `model`'s next run reads through: the owner's pin,
    /// else the exploration share while the model has too little mount
    /// evidence, else a Thompson draw over the model's evidence, then every
    /// model's, else the seeded verbs. Writes nothing.
    ///
    /// # Errors
    ///
    /// Storage errors; [`crate::Error::CorruptedIndex`] on an undecodable
    /// posterior or pin row.
    pub fn pick_read_shape<R: Rng + ?Sized>(
        &self,
        model: &ModelId,
        rng: &mut R,
    ) -> Result<ReadShapePick> {
        self.store.pick_read_shape(model, rng)
    }

    /// Stamps `attempt` with `pick` for `model` unless it already holds a
    /// stamp, and returns the stamp in force: a re-leased attempt keeps the
    /// shape its first wake picked.
    ///
    /// # Errors
    ///
    /// [`crate::Error::InvalidConfig`] for an unknown attempt, or a model
    /// other than the attempt's executor stamp or its earlier read-shape stamp.
    pub fn stamp_read_shape(
        &self,
        attempt: AttemptId,
        model: &ModelId,
        pick: ReadShapePick,
    ) -> Result<ReadShapeStamp> {
        self.store.stamp_read_shape(attempt, model, pick)
    }

    /// The read-shape stamp `attempt` holds, if its run woke under one.
    ///
    /// # Errors
    ///
    /// Storage errors; [`crate::Error::CorruptedIndex`] on an undecodable row.
    pub fn read_shape_stamp(&self, attempt: AttemptId) -> Result<Option<ReadShapeStamp>> {
        self.store.read_shape_stamp(attempt)
    }

    /// Records the model units `attempt`'s run settled, for the token cost
    /// term of its read-shape reward. A later, larger total replaces it.
    ///
    /// # Errors
    ///
    /// [`crate::Error::InvalidConfig`] when the attempt holds no stamp.
    pub fn record_read_shape_units(&self, attempt: AttemptId, units: u64) -> Result<()> {
        self.store.record_read_shape_units(attempt, units)
    }

    /// The read-shape posterior as the last sleep rebuilt it.
    ///
    /// # Errors
    ///
    /// Storage errors; [`crate::Error::CorruptedIndex`] on an undecodable row.
    pub fn read_shape_posterior(&self) -> Result<ReadShapePosterior> {
        self.store.read_shape_posterior()
    }

    /// The owner's read-shape pins, one per model.
    ///
    /// # Errors
    ///
    /// Storage errors; [`crate::Error::CorruptedIndex`] on an undecodable row.
    pub fn read_shape_pins(&self) -> Result<ReadShapePins> {
        self.store.read_shape_pins()
    }

    /// Pins `model` to `shape`, or clears its pin when `shape` is absent.
    ///
    /// # Errors
    ///
    /// Storage errors; [`crate::Error::ConcurrentWrite`] inside an active
    /// write transaction.
    pub fn put_read_shape_pin(
        &self,
        model: &ModelId,
        shape: Option<ReadShape>,
    ) -> Result<ReadShapePins> {
        self.store.put_read_shape_pin(model, shape)
    }
}
