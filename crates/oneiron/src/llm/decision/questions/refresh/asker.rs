//! FIX 1588: a standing question's work is written under the class its asker
//! authenticated as when it wrote the question's version, never under one read off its
//! principal's entity type. An agent slip's question is answered as the agent it was
//! asked by; a person's as the person.

use super::super::records::QuestionRecord;
use super::super::store::{QUESTION_VERSION, VersionKey};
use crate::{EntityId, Result, Vault, WriteActor};

/// `record`'s principal as the writer of its own question's work, under the class the
/// version keeps. A version that keeps none, one stored before the class was kept,
/// writes as [`super::principal_actor`] reads its principal, as it did.
pub(crate) fn standing_asker(vault: &Vault, record: &QuestionRecord) -> Result<WriteActor> {
    match record.asker_class {
        Some(class) => Ok(WriteActor::new(record.principal, class.into())),
        None => super::principal_actor(vault, record.principal),
    }
}

/// The pump's `runner` for `record`: the principal itself writes under the class the
/// version keeps; any other holder on the responsible-role chain (the owner a question
/// whose principal is gone climbs to) under its own.
fn standing_runner(record: &QuestionRecord, runner: WriteActor) -> WriteActor {
    match record.asker_class {
        Some(class) if runner.entity_ref() == record.principal => {
            WriteActor::new(record.principal, class.into())
        }
        _ => runner,
    }
}

/// The writer an artifact wake of `question` at `version` asks as: that version's own
/// asker when it is `principal`'s standing question, else `principal` as
/// [`super::principal_actor`] reads it (a one-off ask keeps no question version).
pub(crate) fn standing_asker_for_question(
    vault: &Vault,
    question: EntityId,
    version: u32,
    principal: EntityId,
) -> Result<WriteActor> {
    let record = {
        let txn = vault.store.env.read_txn()?;
        let key = VersionKey {
            id: question,
            version,
        };
        QUESTION_VERSION.get(&vault.store, &txn, &key)?
    };
    match record {
        Some(record) if record.principal == principal => standing_asker(vault, &record),
        _ => super::principal_actor(vault, principal),
    }
}

/// Who writes one refresh: a caller's own writer, as it authenticated, or the pump's
/// runner, bound to the exact record the refresh loads ([`standing_runner`]).
#[derive(Clone, Copy)]
pub(super) enum RefreshWriter {
    Caller(WriteActor),
    Runner(WriteActor),
}

impl RefreshWriter {
    /// The writer of `record`'s refresh.
    pub(super) fn for_record(self, record: &QuestionRecord) -> WriteActor {
        match self {
            Self::Caller(actor) => actor,
            Self::Runner(runner) => standing_runner(record, runner),
        }
    }

    /// The actor the refresh's source reads run as: the caller, or the runner as the
    /// pump chose it. A read keeps the admission it had before the class was kept,
    /// since an agent class reads no wider than a person's.
    pub(super) fn reader(self) -> WriteActor {
        match self {
            Self::Caller(actor) | Self::Runner(actor) => actor,
        }
    }
}
