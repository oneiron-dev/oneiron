//! The frozen bodies of one Linear mirror operation, kept as body occurrences
//! of the TASK it mirrors (FIX 8609, 8610).
//!
//! The host freezes the exact GraphQL request before the gate and, once the
//! tracker answers, its response. Both bytes live here, in the vault's own
//! `bodies/` under the TASK's body custody, a file each whatever their size,
//! never in the host's journal: that keeps only content-free refs and the
//! delivery state. The TASK is checked live in the writer that publishes, so
//! an erase that commits first leaves nothing published after it. Erasing the
//! TASK releases both occurrences with its other bodies; a later read finds
//! them [`LinearBody::Erased`], and nothing reads, resends or rebuilds them.
//! No row here syncs or exports.

use std::io::{Read, Write};

use crate::Vault;
use crate::entity_id::EntityId;

use super::model::LinearSyncResult;

/// The domain of a body occurrence's id. Parts: the operation id, then the
/// body's role.
#[cfg(unix)]
const BODY_OCCURRENCE: &[u8] = b"oneiron:linear-mirror-body:v1";

/// Which frozen body of one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearBodyRole {
    /// The exact GraphQL request, frozen before the gate.
    Request,
    /// The tracker's answer to a delivered mutation.
    Response,
}

#[cfg(unix)]
impl LinearBodyRole {
    const fn tag(self) -> &'static [u8] {
        match self {
            Self::Request => b"request",
            Self::Response => b"response",
        }
    }
}

/// What a TASK's custody holds of one operation's body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinearBody<T> {
    /// The body, read while its TASK lives.
    Held(T),
    /// The TASK lives and holds no such body.
    Absent,
    /// The TASK was erased or deleted, and its bodies with it.
    Erased,
}

#[cfg(unix)]
impl<T> LinearBody<T> {
    fn map<U>(self, f: impl FnOnce(T) -> U) -> LinearBody<U> {
        match self {
            Self::Held(value) => LinearBody::Held(f(value)),
            Self::Absent => LinearBody::Absent,
            Self::Erased => LinearBody::Erased,
        }
    }
}

/// What freezing one body did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearFreeze {
    /// The TASK holds the body: these bytes, now or already.
    Frozen,
    /// The TASK already holds other bytes under this operation and role.
    Other,
    /// The TASK was erased or deleted: nothing was kept.
    Erased,
}

/// The occurrence one operation's body is kept under.
#[cfg(unix)]
fn occurrence(operation_id: &[u8; 32], role: LinearBodyRole) -> crate::error::Result<EntityId> {
    EntityId::derive(BODY_OCCURRENCE, &[operation_id.as_slice(), role.tag()])
}

#[cfg(unix)]
mod held {
    use std::io::Write;

    use heed::RoTxn;

    use super::LinearBody;
    use crate::entity_id::EntityId;
    use crate::error::Result;
    use crate::provenance::body::{BodyRef, owned_body_in_txn};
    use crate::registry::ENTITY_TYPE_TASK;
    use crate::store::{BodySink, ManifestDbs};

    /// Whether `task` is a live TASK in `txn`'s snapshot.
    pub(super) fn task_lives_in(
        store: &impl ManifestDbs,
        txn: &RoTxn<'_>,
        task: &EntityId,
    ) -> Result<bool> {
        Ok(
            crate::vault::live_entity_row_in_txn(store, txn, task)?.live_type()
                == Some(ENTITY_TYPE_TASK),
        )
    }

    /// The complete body `task` keeps under `occurrence` in `txn`'s snapshot.
    pub(super) fn body_in(
        store: &impl ManifestDbs,
        txn: &RoTxn<'_>,
        task: &EntityId,
        occurrence: &EntityId,
    ) -> Result<LinearBody<BodyRef>> {
        if !task_lives_in(store, txn, task)? {
            return Ok(LinearBody::Erased);
        }
        Ok(match owned_body_in_txn(store, txn, task, occurrence)? {
            Some(owned) => match owned.state {
                crate::provenance::body::BodyState::Complete { body } => LinearBody::Held(body),
                crate::provenance::body::BodyState::Incomplete { .. } => LinearBody::Absent,
            },
            None => LinearBody::Absent,
        })
    }

    /// What a freeze streams into its sink, a frame at a time.
    pub(super) struct SinkWriter<'a>(pub(super) &'a mut BodySink);

    impl Write for SinkWriter<'_> {
        fn write(&mut self, frame: &[u8]) -> std::io::Result<usize> {
            self.0
                .write(frame)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            Ok(frame.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(unix)]
impl Vault {
    /// Freezes the bytes `write` streams as `task`'s `role` body of
    /// `operation_id`: a file in the vault's `bodies/`, whatever its size,
    /// published as the TASK's body occurrence in the writer that checks the
    /// TASK still lives. The same bytes again are [`LinearFreeze::Frozen`];
    /// other bytes under the same operation and role are
    /// [`LinearFreeze::Other`], and keep the first.
    ///
    /// # Errors
    ///
    /// The writer's own failure, and storage errors. Only the disk the body
    /// is written to bounds it.
    pub fn linear_freeze_body(
        &self,
        task: EntityId,
        operation_id: &[u8; 32],
        role: LinearBodyRole,
        write: impl FnOnce(&mut dyn Write) -> std::io::Result<()>,
    ) -> LinearSyncResult<LinearFreeze> {
        use crate::error::Error;
        use crate::provenance::body::{
            BodyLocation, BodyRef, BodyState, OwnedBody, owned_body_in_txn, publish_body_in_txn,
        };
        let occurrence = occurrence(operation_id, role)?;
        // A TASK already gone keeps no byte of the call.
        {
            let rtxn = self.store.env.read_txn().map_err(Error::from)?;
            if !held::task_lives_in(&self.store, &rtxn, &task)? {
                return Ok(LinearFreeze::Erased);
            }
        }
        let mut sink =
            crate::store::BodySink::new(self.store.body_dir()?, 0, Some(self.store.body_mint()?));
        write(&mut held::SinkWriter(&mut sink)).map_err(Error::from)?;
        let (facts, sunk, _pin) = sink.finish_pinned(0, |digest| self.pin_result_body(digest))?;
        let crate::store::SunkBody::File { key, .. } = sunk else {
            return Err(Error::InvariantViolation("a Linear mirror body is empty").into());
        };
        let body = OwnedBody {
            owner: task,
            occurrence,
            state: BodyState::Complete {
                body: BodyRef {
                    blake3: facts.digest,
                    bytes: facts.len,
                    location: BodyLocation::File,
                },
            },
            result: None,
        };
        let dir = self.store.body_dir()?;
        let mut wtxn = self.store.env.write_txn().map_err(Error::from)?;
        // Checked in the writer that publishes: an erase that committed
        // first leaves nothing published after it.
        if !held::task_lives_in(&self.store, &wtxn, &task)? {
            return Ok(LinearFreeze::Erased);
        }
        if let Some(prior) = owned_body_in_txn(&self.store, &wtxn, &task, &occurrence)?
            && prior.state.is_complete()
            && prior != body
        {
            return Ok(LinearFreeze::Other);
        }
        if let Some(key) = &key {
            crate::store::bind_body_key_in_txn(&self.store, &mut wtxn, &dir, key)?;
        }
        publish_body_in_txn(&self.store, &mut wtxn, &body)?;
        wtxn.commit().map_err(Error::from)?;
        Ok(LinearFreeze::Frozen)
    }

    /// The length of `task`'s `role` body of `operation_id`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn linear_body_len(
        &self,
        task: EntityId,
        operation_id: &[u8; 32],
        role: LinearBodyRole,
    ) -> LinearSyncResult<LinearBody<u64>> {
        self.linear_body_ref(task, operation_id, role)
            .map(|body| body.map(|body| body.bytes))
    }

    /// The BLAKE3 digest of `task`'s `role` body of `operation_id`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn linear_body_digest(
        &self,
        task: EntityId,
        operation_id: &[u8; 32],
        role: LinearBodyRole,
    ) -> LinearSyncResult<LinearBody<[u8; 32]>> {
        self.linear_body_ref(task, operation_id, role)
            .map(|body| body.map(|body| body.blake3))
    }

    fn linear_body_ref(
        &self,
        task: EntityId,
        operation_id: &[u8; 32],
        role: LinearBodyRole,
    ) -> LinearSyncResult<LinearBody<crate::provenance::body::BodyRef>> {
        let occurrence = occurrence(operation_id, role)?;
        let rtxn = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        Ok(held::body_in(&self.store, &rtxn, &task, &occurrence)?)
    }

    /// Reads `task`'s `role` body of `operation_id` through `read`, its
    /// whole bytes as they were frozen, while the TASK lives. No transaction
    /// is open while `read` runs; the body stays pinned until it returns.
    ///
    /// # Errors
    ///
    /// `read`'s own failure, a body file that does not open, and storage
    /// errors.
    pub fn linear_read_body<R>(
        &self,
        task: EntityId,
        operation_id: &[u8; 32],
        role: LinearBodyRole,
        read: impl FnOnce(&mut dyn Read) -> LinearSyncResult<R>,
    ) -> LinearSyncResult<LinearBody<R>> {
        use crate::error::Error;
        let occurrence = occurrence(operation_id, role)?;
        let _custody = self.store.gate_custody_read_guard()?;
        let _pin = self.pin_all_result_bodies();
        let (body, key) = {
            let rtxn = self.store.env.read_txn().map_err(Error::from)?;
            match held::body_in(&self.store, &rtxn, &task, &occurrence)? {
                LinearBody::Held(body) => {
                    let key = crate::store::body_key_row_in_txn(&self.store, &rtxn, &body.blake3)?;
                    (body, key)
                }
                LinearBody::Absent => return Ok(LinearBody::Absent),
                LinearBody::Erased => return Ok(LinearBody::Erased),
            }
        };
        let mut file = self
            .store
            .body_dir()?
            .open_reader(&body.blake3, body.bytes, key.as_ref())?
            .ok_or(Error::CorruptedIndex("linear mirror body file"))?;
        read(&mut file).map(LinearBody::Held)
    }
}

/// A host without the vault's body store keeps no Linear body: the store is
/// the custody the bytes need.
#[cfg(not(unix))]
impl Vault {
    /// See the unix build.
    ///
    /// # Errors
    ///
    /// Always: this build has no body store.
    pub fn linear_freeze_body(
        &self,
        _task: EntityId,
        _operation_id: &[u8; 32],
        _role: LinearBodyRole,
        _write: impl FnOnce(&mut dyn Write) -> std::io::Result<()>,
    ) -> LinearSyncResult<LinearFreeze> {
        Err(no_body_store())
    }

    /// See the unix build.
    ///
    /// # Errors
    ///
    /// Always: this build has no body store.
    pub fn linear_body_len(
        &self,
        _task: EntityId,
        _operation_id: &[u8; 32],
        _role: LinearBodyRole,
    ) -> LinearSyncResult<LinearBody<u64>> {
        Err(no_body_store())
    }

    /// See the unix build.
    ///
    /// # Errors
    ///
    /// Always: this build has no body store.
    pub fn linear_body_digest(
        &self,
        _task: EntityId,
        _operation_id: &[u8; 32],
        _role: LinearBodyRole,
    ) -> LinearSyncResult<LinearBody<[u8; 32]>> {
        Err(no_body_store())
    }

    /// See the unix build.
    ///
    /// # Errors
    ///
    /// Always: this build has no body store.
    pub fn linear_read_body<R>(
        &self,
        _task: EntityId,
        _operation_id: &[u8; 32],
        _role: LinearBodyRole,
        _read: impl FnOnce(&mut dyn Read) -> LinearSyncResult<R>,
    ) -> LinearSyncResult<LinearBody<R>> {
        Err(no_body_store())
    }
}

#[cfg(not(unix))]
fn no_body_store() -> super::model::LinearSyncError {
    super::model::LinearSyncError::Store(crate::error::Error::InvalidConfig(
        "Linear mirror bodies need the vault's body store".to_owned(),
    ))
}
