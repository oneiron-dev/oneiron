// Declared `vault_meta` tables whose prefix starts with `c`, in prefix order.

side_tables! {
    /// EVENT entity awaiting calendar-origin claim reconciliation after entity/claim/edge replay
    /// settled. Key: id16 (EVENT entity id).
    SYNC_CALENDAR_ORIGIN_PENDING: VaultMeta b"calendar_origin_pending:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The vault's last sealed checkpoint: its sequence and signed commitment's
    /// BLAKE3, which the next one names as predecessor (OF-570 (e)). Key: ().
    CHECKPOINT_CHAIN_HEAD: VaultMeta b"checkpoint_chain:head:v1" Named
        // Restore class: A restore never rolls the checkpoint chain back.
        [restore: live] [family: structure] [tier: canonical];
    /// One courtesy deletion ask a former peer sent, filed for the owner's review with the owner's
    /// answer once given (OF-273). Key: bytes32(pact) + bytes16(nonce).
    COOPERATIVE_DELETION_INCOMING: VaultMeta b"cooperative_deletion:incoming:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The sender's delivery record for one courtesy deletion ask to one recipient: request id,
    /// connection id, pseudonymous recipient id, status and timestamps only (OF-273). Key:
    /// bytes16(nonce) + bytes32(recipient pseudonym).
    COOPERATIVE_DELETION_NOTICE: VaultMeta b"cooperative_deletion:notice:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// One signed ReRoot row of a pact's former peer, kept because it extends the walk from the
    /// key the pact pinned to the root that peer's courtesy asks and answers now carry (FIX 3014).
    /// Key: bytes32(pact) + hash32(authority entry).
    COOPERATIVE_DELETION_SUCCESSION: VaultMeta b"cooperative_deletion:succession:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
