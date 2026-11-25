//! Purposes of work orders (`crates/oneiron/src/work_order`, pass 34 row Q1).

purposes! {
    /// The job id of a work order's attempt (`work_order/record.rs`, `attempt_job_id`; pass
    /// 34, 1.1): the fingerprint's first 16 bytes. Parts: the order's 16-byte id, then the
    /// attempt number as 2 big-endian bytes. A second pass of the loop after a crash makes the
    /// same id, so the built start finds its own job and never makes another.
    ATTEMPT_JOB_ID = "oneiron.work_order.attempt_job_id.v1";
}

legacy_purposes! {}
