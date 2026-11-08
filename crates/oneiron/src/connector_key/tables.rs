//! The side tables `connector_key` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One connector credential slot's issuer binding and issuer change (FIX 988). Key: id16.
    CONNECTOR_CREDENTIAL_BINDING: VaultMeta b"connector.credential_binding.v1/" Named
        [restore: refuse "connector keys"] [family: unclassified] [tier: canonical];
    /// The connector key a stamped slate is bound to (16-byte key id). Key: id16(slate).
    CONNECTOR_GRANT_SLATE_BINDING: VaultMeta b"connector.grant_slate.binding.v1/" Raw
        [restore: refuse "connector keys"] [family: unclassified] [tier: canonical];
    /// A per-grant key's holder narrows of the slate its calls meet (FIX 987). Key: id16(key).
    CONNECTOR_SLATE_HOLDER_NARROW: VaultMeta b"connector.grant_slate.holder_narrow.v1/" Named
        [restore: refuse "connector keys"] [family: unclassified] [tier: canonical]
        => crate::connector_key::erase_holder_narrows_in_txn;
    /// One logical connector call's typed scope exceed and its ruling (FIX 988). Key: id16.
    CONNECTOR_SLATE_SCOPE_SIGNAL: VaultMeta b"connector.grant_slate.scope_signal.v1/" Named
        [restore: refuse "connector keys"] [family: unclassified] [tier: canonical];
    /// Typed per-tool grant slate draft plus any authenticated-owner overrides. Key: id16.
    CONNECTOR_GRANT_SLATE: VaultMeta b"connector.grant_slate.v1/" LegacyJson
        [restore: refuse "connector keys"] [family: unclassified] [tier: canonical]
        => crate::connector_key::erase_grant_slate_holder_narrows_in_txn;
    /// The qualification kit the owner's last successful qualify of a catalog key used, which an
    /// accepted issuer revision's re-run qualifies its dependent rows with (FIX 9304). Key: id16
    /// (catalog key).
    CONNECTOR_QUALIFICATION_KIT: VaultMeta b"connector.qualification_kit.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Idempotent wake-decision record for one connector-event subscription match. Key: hash32.
    CONNECTOR_WAKE_DECISION: VaultMeta b"connector.wake.v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Permanent catalog-name to key-id index; never deleted on key removal. Key: string(catalog
    /// name).
    CONNECTOR_CATALOG_NAME_INDEX: VaultMeta b"connector_catalog/name/v1\0" Raw
        [restore: refuse "connector keys"] [family: unclassified] [tier: canonical];
    /// Lookup index from a normalized connector name to a key id, empty marker value. Key:
    /// string(connector) "\x00" id16.
    CONNECTOR_KEY_CONNECTOR_INDEX: VaultMeta b"connector_key/connector/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// One dispatch batch's normalized input and committed progress (FIX 11058): its effect
    /// channel and size, the dispatches admitted and refused so far, when the windows that paced
    /// the rest open again, and its first and latest accounting samples. Key: id16 +
    /// string(batch_ref).
    CONNECTOR_KEY_DISPATCH_BATCH: VaultMeta b"connector_key/dispatch_batch/v1\0" Named Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// Rotation-generation log entry naming the custody ref a connector key pointed at. Key: id16 +
    /// u32be.
    CONNECTOR_KEY_GENERATION_LOG: VaultMeta b"connector_key/generation/v1\0" Raw
        [restore: refuse "connector keys"] [family: unclassified] [tier: canonical];
    /// Logical-send admission evidence row proving one exactly-once Sends debit. Key: id16 +
    /// string(logical_send_ref).
    CONNECTOR_KEY_SEND_ADMIT: VaultMeta b"connector_key/send_admit/v1\0" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Spend-settlement idempotency row for one settlement event id. Key: id16 + string(event_ref).
    CONNECTOR_KEY_SETTLE_EVENT: VaultMeta b"connector_key/settle_event/v1\0" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Live per-row budget usage counters for a connector key (key rows and compiled-charter cap
    /// rows). Key: id16 + u16be.
    CONNECTOR_KEY_USAGE: VaultMeta b"connector_key/usage/v1\0" Raw
        [restore: live] [family: unclassified] [tier: canonical];
}
