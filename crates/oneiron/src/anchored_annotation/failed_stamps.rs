//! The body-anchor sweep's memo of failed stamps (FIX 12276, FIX 12326).
//!
//! A comment whose stamp failed with every read in hand (a Word paragraph
//! that reads otherwise in the body, a deck id that names no single node at
//! its version's frontier) fails the same way until something the stamp
//! reads moves: the thread's head claim, the body's head frontier or the
//! newest export. The memo holds those for each such thread, so a pass that
//! finds them unchanged skips the thread before it reads any body or
//! version. It lives in this process only and changes no stored row: a
//! restart stamps each thread once more.

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use super::model::AnnotationThread;
use crate::entity_id::EntityId;

/// Failed stamps the memo holds, across this process's vaults; past it the
/// oldest is dropped, and its thread is stamped once more on its next pass.
const FAILED_STAMP_MEMO_CAP: usize = 4096;

/// A thread of an artifact, in the vault of this store id.
type ThreadKey = ([u8; 32], EntityId, EntityId);

/// What a stamp depends on: the thread's head claim, the body's head
/// frontier and the newest export's version.
type StampInputs = (EntityId, Vec<u8>, Option<u64>);

#[derive(Default)]
struct Memo {
    failed: HashMap<ThreadKey, StampInputs>,
    /// The threads in the order they were first remembered, oldest first.
    order: VecDeque<ThreadKey>,
}

static FAILED_STAMPS: LazyLock<Mutex<Memo>> = LazyLock::new(Mutex::default);

/// One thread's stamp, by the inputs it reads.
pub(super) struct FailedStampKey {
    thread: ThreadKey,
    inputs: StampInputs,
}

impl FailedStampKey {
    pub(super) fn new(
        vault: [u8; 32],
        artifact: &EntityId,
        thread: &AnnotationThread,
        body_head: &[u8],
        latest_export: Option<u64>,
    ) -> Self {
        Self {
            thread: (vault, *artifact, thread.thread_id),
            inputs: (thread.head_claim_id, body_head.to_vec(), latest_export),
        }
    }

    /// Whether this thread's stamp already failed on these same inputs.
    pub(super) fn failed_before(&self) -> bool {
        lock().failed.get(&self.thread) == Some(&self.inputs)
    }

    /// Remembers that the stamp failed on these inputs.
    pub(super) fn remember(self) {
        let mut memo = lock();
        if memo.failed.insert(self.thread, self.inputs).is_none() {
            memo.order.push_back(self.thread);
        }
        while memo.failed.len() > FAILED_STAMP_MEMO_CAP {
            let Some(oldest) = memo.order.pop_front() else {
                break;
            };
            memo.failed.remove(&oldest);
        }
    }
}

fn lock() -> MutexGuard<'static, Memo> {
    FAILED_STAMPS.lock().unwrap_or_else(PoisonError::into_inner)
}
