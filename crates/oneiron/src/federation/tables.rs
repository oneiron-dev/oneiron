//! The side tables `federation` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A record one federation pact delivered here at one consent epoch (FIX 321), written in the
    /// transaction that materialized it. Local to this vault: never replicated or exported. Value:
    /// the world the record sits in (16 raw bytes; empty for base reality). Key: hex64 (pact id)
    /// ":" hex16 (epoch) ":" hex32 (record id).
    FEDERATION_DELIVERED_RECORD: SyncState b"feddelivered:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A federated `FacetOf` stamp sent ahead of its source row, held out of the window document
    /// until the same sender's birth of the row has applied here. Local to this vault: never
    /// replicated or exported. Value: when it was held (u64 big-endian), the grant it was held
    /// under (a flag byte, then its 16 raw bytes when set), then the stamp's edge value.
    /// Key: hex32 (source) hex32 (facet) then the sender's lane.
    FEDERATION_PARKED_FACET_STAMP: SyncState b"fedpark:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// What one sender's lane holds in `FEDERATION_PARKED_FACET_STAMP`: its rows, then their
    /// bytes (u64 big-endian each), so the per-sender caps read one row. Key: the sender's lane.
    FEDERATION_PARKED_FACET_LANE: SyncState b"fedparklane:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The content-free receipt of a held `FacetOf` stamp that retired (FIX 8890): why (1 past its
    /// wait, 2 its grant or staged receipt ended), when it was held and when it retired (u64
    /// big-endian each), then the grant it was held under (a flag byte, then its 16 raw bytes when
    /// set). Key: as `FEDERATION_PARKED_FACET_STAMP`.
    FEDERATION_PARKED_FACET_RECEIPT: SyncState b"fedparkreceipt:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// First-wins stamp recording that a foreign world's federated content stopped refreshing after a
    /// terminal pact transition. Key: hex32 (world id).
    FEDERATION_STALE: SyncState b"fedstale:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Registers a foreign world as content delivered by one federation pact, scanned when the pact
    /// goes terminal. Key: hex64 (pact id) ":" hex32 (world id).
    FEDERATION_WORLD_REGISTRATION: SyncState b"fedworld:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The actor bound to the active content write transaction, deleted before commit. Key: ().
    FEDERATION_ACTOR_CONTENT_INFLIGHT: VaultMeta b"federation:actor-content:inflight:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Every agent a signed owner-agent Grant mint of the authority log has ever named, revoked
    /// Grants included (Engine RULING PAIR-GRANT-DESIGN Q2 = A): written as each authority-log
    /// row is staged, never removed, rebuilt from the log at open and after a restore. One posting
    /// per signed mint, so a reader counts a posting only while the authority fold counts its mint.
    /// Key: id16 (member) + id16 (grant) + hash32 (the mint's entry hash). Value: empty.
    FEDERATION_AGENT_GRANT_MEMBER: VaultMeta b"federation:agent-grant-member:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Schema-version byte gating the agent Grant member index's rebuild from the authority log.
    /// Key: ().
    FEDERATION_AGENT_GRANT_MEMBER_SCHEMA_VERSION: VaultMeta b"federation:agent-grant-member-schema-version" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// A Connect guest's proposal in its pact's review inbox (FIX 3684): the proposer, the world
    /// and record it names, the text update as sent until the owner decides, then the decision.
    /// Never a vault write. Key: id16(grant) + id16(proposal).
    FEDERATION_CONNECT_PROPOSAL: VaultMeta b"federation:connect_proposal:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::federation::erase_connect_proposer_in_txn;
    /// An administrative ruling's admission, kept before the grant row that admitted it was
    /// rewritten or deleted (FIX 8740): the grant and the hash of that row. Immutable. Key: id16
    /// (the ruling).
    FEDERATION_RULING_WITNESS: VaultMeta b"federation:ruling_witness:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The facet a verified Connect origin position names for an imported ASSET or ASSET_TEXT. This
    /// vault holds no edge to the sender's FACET, so the facet is kept here, written beside the
    /// record-scope stamp and retired with it (FIX 22223). Key: id16 (record). Value: id16 (facet).
    SCOPE_ORIGIN_FACET: VaultMeta b"scope:origin_facet:v1:" Named
        // Restore class: A Connect origin facet stands with the stamp it places (FIX 22223).
        [restore: content] [family: unclassified] [tier: canonical];
    /// Record-scope revision counter (u64 little-endian), bumped on every stamp change. Key: ().
    SCOPE_RECORD_REVISION: VaultMeta b"scope:record:revision:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Birth-position scope stamp (kind, birth facet, worlds/facets/bands/audience/sensitivity) for
    /// one stored record, used by scoped read/export/delete. Key: id16.
    SCOPE_RECORD: VaultMeta b"scope:record:v2:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// The facet a source-free ASSET_TEXT was born under, the batch mask or the vault default, written
    /// in its birth transaction beside its `FacetOf` stamp and retired with its record-scope stamp: the
    /// record that the text was born bound to no source (FIX 8741). Key: id16 (text). Value: id16
    /// (facet).
    SCOPE_SOURCE_FREE_TEXT: VaultMeta b"scope:source_free_text:v1:" Named
        // Restore class: A source-free text's birth record stands with its stamp (FIX 8741).
        [restore: content] [family: unclassified] [tier: canonical];
    /// A membership change this install executed with no host issuer to sign it, whose
    /// carrier-signed record it still owes (FIX 12335): the vault, the cause, the person who
    /// executed it, the member it moved, the act, the second it was executed at, the signed-mint
    /// Grants it withdrew and an Owner act's handover, until the pass whose writer the fold counts
    /// the record in. Holds no value, credential or proof. Key: hex32 (receipt id).
    SHARED_ACT_MEMBERSHIP_PENDING: VaultMeta b"shared-act:membership-pending:v1:" Named Engine
        // Restore class: A membership record still owed stands as the live vault owes it: a restore
        // neither drops one nor revives one already signed (FIX 12335).
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::Vault::erase_pending_membership_execution_actor_in_txn;
    /// One proposed shared-act policy change and its live editors' answers (DOOR-129). Key: hex32
    /// (change id).
    SHARED_ACT_POLICY_CHANGE: VaultMeta b"shared-act:policy-change:v1:" Named
        // Restore class: A proposed policy change binds the digest of the rows it was proposed
        // against, so a restore that moves the policy manifest leaves it stale: it stays as the
        // live vault holds it and never blocks a restore.
        [restore: live] [family: unclassified] [tier: canonical];
    /// The record ids an export-first removal's export counted, beside its
    /// receipt (FIX 11886). Key: hex32 (receipt id).
    SHARED_ACT_REMOVAL_EXPORT_RECORDS: VaultMeta b"shared-act:removal-export-records:v1:" Named
        [restore: refuse "shared vault membership"] [family: unclassified] [tier: canonical];
    SHARED_VAULT_CREATION: VaultMeta b"shared-vault:creation:v1" LegacyJson
        [restore: refuse "shared vault membership"] [family: unclassified] [tier: canonical];
    /// The executed delete-the-vault act and its backup retention deadline. Key: ().
    SHARED_VAULT_DELETION: VaultMeta b"shared-vault:deleted:v1" LegacyJson
        [restore: refuse "shared vault membership"] [family: unclassified] [tier: canonical];
}
