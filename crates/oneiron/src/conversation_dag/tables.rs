//! The side tables `conversation_dag` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Transient in-txn permit binding a legacy ChildOf-append record id to the conversation it may
    /// append to. Key: id16.
    CONVERSATION_DAG_APPEND_PERMIT: VaultMeta b"conversation_dag:append_in_txn:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Append-only pin of a DAG record's body hash (kind, occurred range, body) so a replay cannot
    /// rewrite an existing record's content. Key: id16.
    CONVERSATION_DAG_BODY_PIN: VaultMeta b"conversation_dag:body_pin:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-record pointer marking a DAG record canonical (points to its successor), or absent for
    /// terminal. Key: id16.
    CONVERSATION_DAG_CANONICAL: VaultMeta b"conversation_dag:canonical:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Single-byte `[1]` reverse Parent witness kept when a DAG record is purged, by parent then
    /// child. Key: id16 (parent) + id16 (child).
    CONVERSATION_DAG_ERASED_CHILD: VaultMeta b"conversation_dag:erased_child:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// SpawnedBy anchor (id16) of a session whose anchoring DAG record was purged. Key: id16
    /// (session).
    CONVERSATION_DAG_ERASED_SPAWN: VaultMeta b"conversation_dag:erased_spawn:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Content-free topology pin (room, parent, session, thread flag, PERSON author) of a soft- or
    /// hard-erased DAG record. Key: id16 (record).
    CONVERSATION_DAG_ERASED_TOPOLOGY: VaultMeta b"conversation_dag:erased_topology:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Per-conversation pointer to the current local-head DAG record id. Key: id16.
    CONVERSATION_DAG_LOCAL_HEAD: VaultMeta b"conversation_dag:local_head:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Single-byte [1] marker that a conversation has adopted the DAG record model. Key: id16.
    CONVERSATION_DAG_MIGRATED: VaultMeta b"conversation_dag:migrated:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Durable room (id16) of a room TURN, kept after its ChildOf edge is deleted or purged. Key:
    /// id16 (TURN).
    CONVERSATION_DAG_ROOM_OWNER: VaultMeta b"conversation_dag:room_owner:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Cached thread projection of a trunk: `[1]`, root id16, reply count u64be, last reply at
    /// u64be. Key: id16 (trunk).
    CONVERSATION_DAG_THREAD_META: VaultMeta b"conversation_dag:thread_meta:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Single-byte `[1]` marker that a trunk's cached thread projection is stale. Key: id16.
    CONVERSATION_DAG_THREAD_META_DIRTY: VaultMeta b"conversation_dag:thread_meta_dirty:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
}
