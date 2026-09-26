//! Pure settle decisions; the host owns the one-transaction consume-once write.

/// Compare a retained proposal to the head read inside the settle transaction.
/// A changed hash OR version is stale: neither may silently overwrite a peer.
#[must_use]
pub fn proposal_is_stale(
    head_version: u64,
    head_hash: &[u8; 32],
    base_version: Option<u64>,
    base_hash: &[u8; 32],
) -> bool {
    head_hash != base_hash || base_version.is_some_and(|version| version != head_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn either_head_change_strands_the_proposal() {
        assert!(!proposal_is_stale(3, &[1; 32], Some(3), &[1; 32]));
        assert!(!proposal_is_stale(3, &[1; 32], None, &[1; 32]));
        assert!(proposal_is_stale(3, &[1; 32], Some(2), &[1; 32]));
        assert!(proposal_is_stale(3, &[1; 32], Some(3), &[2; 32]));
    }
}
