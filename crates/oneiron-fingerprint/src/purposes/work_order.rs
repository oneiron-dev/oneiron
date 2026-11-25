//! Purposes of work orders (`crates/oneiron/src/work_order`, pass 34 row Q1).

purposes! {
    /// The job id of a work order's attempt (`work_order/record.rs`, `attempt_job_id`; pass
    /// 34, 1.1): the fingerprint's first 16 bytes. Parts: the order's 16-byte id, then the
    /// attempt number as 2 big-endian bytes. A second pass of the loop after a crash makes the
    /// same id, so the built start finds its own job and never makes another.
    ATTEMPT_JOB_ID = "oneiron.work_order.attempt_job_id.v1";
    /// The code-run wait id of a wait on a work order (`work_order/wait.rs`, `order_wait_id`;
    /// pass 34, 14.2): the fingerprint's first 16 bytes. Parts: the order's 16-byte id, then
    /// one byte for the milestone (1 = the first started attempt, 2 = the terminal state).
    /// Every run that waits on the same order and milestone parks on the same wait, which the
    /// order's writer settles once.
    WAIT_ID = "oneiron.work_order.wait_id.v1";
}

legacy_purposes! {}
