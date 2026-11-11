// Declared `vault_meta` tables whose prefix starts with `s`, in prefix order.

side_tables! {
    /// Retired digest-bound record-scope stamp. #1224 moved stamps to `scope:record:v2:` and no longer
    /// reads these rows; a vault stamped before it still holds them. Key: id16.
    SCOPE_RECORD_V1: VaultMeta b"scope:record:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// One-time record of the initial membership/policy defaults applied when a shared vault was
    /// created. Key: ().
    /// One Member's request or Admin's proposal to erase a record of a shared vault. Key: hex32
    /// (ask id).
    SHARED_ACT_ERASE_ASK: VaultMeta b"shared-act:erase-ask:v1:" Raw
        [restore: refuse "shared vault membership"] [family: unclassified] [tier: canonical];
    /// One member's notice of a pending shared act. Key: hex32 (member id) ":" hex32 (act id).
    SHARED_ACT_EVENT: VaultMeta b"shared-act:event:v1:" Raw
        [restore: refuse "shared vault membership"] [family: unclassified] [tier: canonical];
    /// One Owner's notice that a waiting shared act matured. Key: hex32 (owner id) ":" hex32 (act
    /// id).
    SHARED_ACT_MATURED: VaultMeta b"shared-act:matured:v1:" Raw
        [restore: refuse "shared vault membership"] [family: unclassified] [tier: canonical];
    /// One recipient's notice of an executed shared act or membership change. Key: hex32 (recipient
    /// id) ":" hex32 (receipt id).
    SHARED_ACT_OUTCOME: VaultMeta b"shared-act:outcome:v1:" Raw
        [restore: refuse "shared vault membership"] [family: unclassified] [tier: canonical];
    /// The execution receipt of one shared act or membership change. Key: hex32 (receipt id).
    SHARED_ACT_RECEIPT: VaultMeta b"shared-act:receipt:v1:" Raw
        [restore: refuse "shared vault membership"] [family: unclassified] [tier: canonical];
    /// A pending shared act awaiting its members' objection window. Key: hex32 (act id).
    SHARED_ACT_RECORD: VaultMeta b"shared-act:record:v1:" Raw
        [restore: refuse "shared vault membership"] [family: unclassified] [tier: canonical];
    /// The key a pending invitation's own slips must bind, as the invitee bound it with an
    /// independent credential of their own or an owner's invitation pairing code (FIX 8745).
    /// Key: hex32 (invitee id) ":" hex32 (invitation id).
    SHARED_VAULT_INVITATION_KEY: VaultMeta b"shared-vault:invitation-key:v1:" Raw
        [restore: refuse "shared vault membership"] [family: unclassified] [tier: canonical];
    /// One invitation of a person into the shared vault, pending until they accept, decline or an
    /// `add_member` holder withdraws it. Key: hex32 (invitee id) ":" hex32 (invitation id).
    SHARED_VAULT_INVITATION: VaultMeta b"shared-vault:invitation:v1:" Raw
        [restore: refuse "shared vault membership"] [family: unclassified] [tier: canonical];
    /// One callable call frozen as a case for the helper gate: its arguments, the answer that passed
    /// its contract, the caller, its source rows, the revision. Key: id16 (skill that ran) + u64be
    /// at + u64be step seq + receipt string.
    SKILL_CALLABLE_CASE: VaultMeta b"skill:callable_case:v1:" Named Authored
        [refs: CALLABLE_CASE_REFS] [accepts: crate::skill::skill_callable_case_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::skill::erase_callable_case_actor_in_txn;
    /// Born-with text a copy from another vault carried for one row: the fields its sharer let
    /// travel (OF-491), prose only, never a ref. Key: id16 (the row).
    SYNC_BORN_WITH_CARRIED: VaultMeta b"sync:born_with:carried:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
