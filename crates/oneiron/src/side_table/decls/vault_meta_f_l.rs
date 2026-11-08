// Declared `vault_meta` tables whose prefix starts with `f` to `l`, in prefix order.

side_tables! {
    /// The owner's confidence scale for claims one federation peer sends, this device's local
    /// truth (OF-149). Key: id16(peer principal).
    FEDERATION_PEER_CONFIDENCE: VaultMeta b"federation:peer_confidence:v1:" Named;
    /// This node's place in the vault's home-state lineage: the newest generation it froze or
    /// adopted, a home move its election recorded, and why a move carried nothing (FIX 5661).
    /// Key: ().
    HOME_HANDOFF_HEAD: VaultMeta b"home:handoff:head:v1" Named Engine;
    /// One part of a home handoff's sealed bytes, kept by the source. Key: id32 (handoff) + u32be
    /// (part index).
    HOME_HANDOFF_PART: VaultMeta b"home:handoff:part:v1:" Named Ciphertext;
    /// The signed ack of one home handoff: the one this node signed as its target, or the one its
    /// target returned. Key: id32 (handoff).
    HOME_HANDOFF_RECEIPT: VaultMeta b"home:handoff:receipt:v1:" Named Engine;
    /// One home handoff's status on this node, with its signed header. Key: id32 (handoff).
    HOME_HANDOFF_TRANSFER: VaultMeta b"home:handoff:transfer:v1:" Named Engine;
}
