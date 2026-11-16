//! Door for `tests/comm_thread_member_claim_reads.rs` (L6-23, ARCH-0057
//! membership-history scans): the claim reads the comm projector's
//! thread-membership fold made on the calling thread.

/// The claim reads the thread-membership fold made on this thread since the
/// last call, which resets the tally to zero.
pub fn take_thread_member_claim_reads() -> usize {
    crate::comm::take_thread_member_claim_reads()
}
