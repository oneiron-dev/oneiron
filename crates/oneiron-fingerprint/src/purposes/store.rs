//! Legacy store digests that existing rows, files and acks hold.
//!
//! Code-tree inventories, critical-confirm bindings, erasable-key
//! incarnations, custody drain identities, owner-answer items, row-birth
//! hashes, session spill directory names and skill source carrier ids retain
//! their exact bytes through the K door (K, PLAN-UC-04 stage 7).

purposes! {}

legacy_purposes! {
    /// Code-tree inventory: the tag; the document count as u64-BE; per
    /// document in path order, its path and its named MessagePack frontier,
    /// each after its u64-BE byte length, then its mode as u32-BE; the blob
    /// count as u64-BE; per blob in path order, its path and Git object id,
    /// each after its u64-BE byte length, then its 32-byte content hash, its
    /// size as u64-BE and its mode as u32-BE. A blob-only inventory writes a
    /// document count of 0. Stored as a tested revision's inventory_digest and
    /// as an import manifest's inventory digest (hex); both are compared when
    /// read back.
    CODE_TREE_INVENTORY = (Blake3, HashedFirst, "oneiron:code-tree-inventory:v1");

    /// Critical-confirm effect: the tag, the 16-byte claim id, the 16-byte
    /// gate decision id, the diff handle's bytes without a length, the 32-byte
    /// read frontier hash. Stored as the authority log action's effect_digest
    /// and bound into the confirm id.
    CRITICAL_CONFIRM_EFFECT = (Blake3, HashedFirst, "oneiron:critical-confirm:v1");

    /// Critical write confirm id (the tag is `CRITICAL_WRITE_CONFIRM_DOMAIN`):
    /// the tag, the 16-byte gate decision id, the 16-byte claim id, the
    /// 32-byte effect digest, the 32-byte read frontier hash, the 16-byte
    /// nonce, the expiry as u64-BE. Keys CRITICAL_CONFIRM_INDEX, is stored in
    /// the authority log action, and the gate compares it.
    CRITICAL_WRITE_CONFIRM = (Sha256, HashedFirst, "oneiron/authority/critical-write-confirm/v1");

    /// Custody drain ack digest: the ack's MessagePack bytes, no length or
    /// hashed tag (the tag is a registry name only). Its hex is stored as the
    /// drain's ack_digest in the target set history.
    CUSTODY_DRAIN_ACK = (Blake3, NotHashed, "oneiron.store.custody_drain_ack.v1");

    /// Custody drain operation: derive-key over the 96-byte custody position,
    /// the set revision as u64-BE, then the target id's UTF-8 without a
    /// length. Stored in the drain fence and the ticket; the member's ack must
    /// name it.
    CUSTODY_DRAIN_OPERATION = (Blake3, DeriveKeyContext, "oneiron/custody-drain/operation/v1");

    /// Custody drain origin: derive-key over the position's 32-byte vault id,
    /// then its 16-byte namespace. Its hex is sent in the drain ack and
    /// compared with the one rebuilt from the ticket.
    CUSTODY_DRAIN_ORIGIN = (Blake3, DeriveKeyContext, "oneiron/custody-drain/origin/v1");

    /// Drafter artifact key incarnation: derive-key over the 16-byte artifact
    /// id. Stored in the erasable key's ref row and compared on unseal.
    DRAFTER_INCARNATION = (Blake3, DeriveKeyContext, "oneiron/drafter-artifact/erasable-incarnation/v1");

    /// Grant-scope key incarnation: derive-key over the 32-byte pact id, then
    /// the epoch as u64-BE. Stored in the erasable key's ref row and compared
    /// on unseal.
    GRANT_INCARNATION = (Blake3, DeriveKeyContext, "oneiron/grant-scope/erasable-incarnation/v1");

    /// Row-birth input hash: derive-key over each part as its u64-LE byte
    /// length, then its bytes; lowercase hex. Stored as a birth's content_hash
    /// in ROW_BIRTH.
    MADE_BY_CONTENT = (Blake3, DeriveKeyContext, "oneiron made_by content_hash v1");

    /// Owner-answer item: the tag, then the diff handle's bytes without a
    /// length. Stored as an owner-answer obligation's item and compared with
    /// the answered item's hash.
    OWNER_ANSWER_ITEM = (Blake3, HashedFirst, "oneiron:owner-answer-item:v1");

    /// Session spill directory: the session reference's UTF-8, no length or
    /// hashed tag (the tag is a registry name only); lowercase hex. Names an
    /// off-record session's body directory on disk, which later reads and the
    /// removal open by that name.
    SESSION_SPILL_DIR = (Blake3, NotHashed, "oneiron.store.session_spill_dir.v1");

    /// Skill source carrier id: the tag, NUL-terminated and with no length
    /// before it; the 16-byte holder id; the 32-byte skill content hash. The
    /// first 16 bytes are the carrier's EntityId, stored as the row id and
    /// compared when the source is read.
    SKILL_SOURCE_CARRIER = (Sha256, HashedFirst, "oneiron.hub-source.asset.v1\0");

    /// Write-door params hash: SHA-256 of no bytes (a write door takes no
    /// render parameters; the tag is a registry name only); lowercase hex.
    /// Stored as a birth's process params_hash in ROW_BIRTH.
    WRITE_DOOR_PARAMS = (Sha256, NotHashed, "oneiron.store.write_door_params.v1");
}
