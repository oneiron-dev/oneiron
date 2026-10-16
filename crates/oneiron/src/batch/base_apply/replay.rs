use super::*;

// Holds promotion's independent journal clone until apply completes. The
// iterator retains every unconsumed op on early return; per-op payloads that
// move into match arms get a Zeroizing owner at the point of consumption.
pub(super) struct ReplayOps {
    pub(super) ops: Vec<BatchOp>,
    pub(super) replay: bool,
}

impl Drop for ReplayOps {
    fn drop(&mut self) {
        if self.replay {
            for op in &mut self.ops {
                crate::session_overlay::zeroize_batch_op_payload(op);
            }
        }
    }
}

impl std::ops::Deref for ReplayOps {
    type Target = Vec<BatchOp>;
    fn deref(&self) -> &Self::Target {
        &self.ops
    }
}

pub(super) struct ReplayIter {
    pub(super) remaining: std::vec::IntoIter<BatchOp>,
    pub(super) replay: bool,
}

impl Iterator for ReplayIter {
    type Item = BatchOp;
    fn next(&mut self) -> Option<Self::Item> {
        self.remaining.next()
    }
}

impl Drop for ReplayIter {
    fn drop(&mut self) {
        if self.replay {
            for op in self.remaining.as_mut_slice() {
                crate::session_overlay::zeroize_batch_op_payload(op);
            }
        }
    }
}
