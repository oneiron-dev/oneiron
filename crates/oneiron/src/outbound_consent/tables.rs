//! The side tables `outbound_consent` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Best-effort de-duplication lease for one authorized-outbound recovery sweep. Key: ().
    OUTBOUND_AUTHORIZED_RECOVERY_LEASE: VaultMeta b"outbound:authorized_recovery_lease:v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// One connector call held for consent or governance, or waiting on its delivery: the exact
    /// request a resume re-enters with (ONE-2510). An actor's erase drops the actor's rows (FIX
    /// 9159). Key: id16 (call ref).
    OUTBOUND_CONNECTOR_CALL_PENDING: VaultMeta b"outbound:connector_call:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::outbound_consent::erase_connector_call_actor_in_txn;
    /// Who called one connector call a settler answered and acknowledged, and what it calls, so
    /// its status read stays the caller's once the held row is gone (ONE-2510, FIX 2279). Key:
    /// id16 (call ref).
    OUTBOUND_CONNECTOR_CALL_CALLER: VaultMeta b"outbound:connector_call_caller:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
