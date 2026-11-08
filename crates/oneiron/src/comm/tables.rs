//! The side tables `comm` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Monotonic little-endian sequence counter stamped onto comm event/gate/receipt records. Key:
    /// ().
    COMM_EVENT_SEQUENCE: VaultMeta b"comm.event_sequence.v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Node-local shortcut cache mapping a hashed party key to the canonical comm-owned PERSON id
    /// that synced truth currently names for it; repaired from synced truth on a stale or missing
    /// hit. Key: bytes32 (sha256 of party_key).
    COMM_PARTY_INDEX: VaultMeta b"comm.party.v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A durable send receipt the comm projector's import skipped, written when it first warned
    /// about it: the reason and when. Node-local. Key: id16 (the receipt's TASK).
    COMM_SKIPPED_SEND_RECEIPT: VaultMeta b"comm.skipped_send_receipt.v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
