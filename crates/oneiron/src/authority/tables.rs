//! The side tables `authority` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    AUTHLOG_FIRST_SEEN_SIDECAR: SyncState b"authlog:first_seen:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// An OAuth client that may sign in to this vault's `/mcp` (FIX 4902): registered, or known
    /// by its client ID metadata document. Key: hex64 (BLAKE3 of its `client_id`).
    AUTHORITY_OAUTH_CLIENT: SyncState b"authority:oauth-client:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// An OAuth authorization code, until it lapses; never the code itself. Key: hex64 (keyed
    /// hash of the code).
    AUTHORITY_OAUTH_CODE: SyncState b"authority:oauth-code:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// An OAuth token family: the grant, client and resource every token one code minted
    /// stands on, whether it is revoked, and whether its first access slip stood. Key: hex32
    /// (the family id).
    AUTHORITY_OAUTH_FAMILY: SyncState b"authority:oauth-family:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// An OAuth authorization request waiting for, or holding, the owner's answer; its page's
    /// poll secret only as a keyed hash. Key: hex32 (the request id).
    AUTHORITY_OAUTH_REQUEST: SyncState b"authority:oauth-request:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// An OAuth access or refresh token, until it lapses; never the token itself. Key: hex64
    /// (keyed hash of the token).
    AUTHORITY_OAUTH_TOKEN: SyncState b"authority:oauth-token:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The owner recovery root this install pins (its id and anchor key), and the admitter
    /// its machine was mine under before the pin last changed. Local like the machine id:
    /// never synced, and dropped wherever the machine id is. Key: ().
    IDENTITY_PINNED_ROOT: SyncState b"m:pinned_root" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// What this home's root signed for a linked machine's own checkpoint image (FIX 5195): the
    /// image id, the posture and policy it was made under, the attestation and the local second
    /// the machine last asked for it. A reply cache, so a last part whose answer the machine's RPC
    /// timeout lost is answered from it on the machine's next pass; no image bytes, never the
    /// delivery cache or the attestation table. Runtime-tier. Key: the machine's id16 + root key
    /// (suite byte + key bytes).
    AUTHORITY_CHECKPOINT_COUNTERSIGN: VaultMeta b"authority.checkpoint.local.countersign.v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// What a root held here signed for a home's checkpoint head (FIX 5109): the image, the
    /// posture and policy it was made under, where its delivery stands, and the attestation
    /// until the home reports the root accepted. A delivery cache, rebuilt by signing again;
    /// never the attestation table. Runtime-tier. Key: home tag (1 then the home's machine id,
    /// or 0 then zeros for a home that proved none) + root key (suite byte + key bytes).
    AUTHORITY_CHECKPOINT_ROOT_DELIVERY: VaultMeta b"authority.checkpoint.local.root-delivery.v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// One signed authority row a local append kept as evidence instead of storing it, because
    /// the fold with it past the adopted checkpoint image needs history this vault does not hold
    /// (FIX 2989): no held history, admitting nothing; it leaves when a put of it lands. Key:
    /// hash32. Value: the row's canonical signed bytes.
    AUTHORITY_HISTORY_PENDING: VaultMeta b"authority.history.pending.v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// One signed authority row a repair page staged while this vault's history is incomplete
    /// (OF-469): no held history, admitted only when the stage closes the gap. Key: hash32.
    AUTHORITY_HISTORY_STAGE: VaultMeta b"authority.history.stage.v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// One leave-notice delegation's canonical bytes (FIX 7932): a root's signed, purpose-limited
    /// hand-on of leave-notice verification to its ReRoot's successor. Immutable authority
    /// evidence. Key: bytes32 (its digest).
    AUTHORITY_LEAVE_NOTICE_DELEGATION: VaultMeta b"authority:leave-notice-delegation:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// The MACHINE rows by the endpoint key their mesh address names (ARCH-0044 H336, census
    /// L3-28B): one empty row per MACHINE row whose body is a valid address envelope. Key: bytes32
    /// (the endpoint key) + id16 (the MACHINE).
    AUTHORITY_MESH_MACHINE_ENDPOINT_INDEX: VaultMeta b"authority:mesh-machine-endpoint:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Completeness flag of the endpoint index above (u64 version). Key: ().
    AUTHORITY_MESH_MACHINE_ENDPOINT_INDEX_STATE: VaultMeta b"authority:mesh-machine-endpoint-state:v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// An ask guest's FEDERATION_GRANT the owner withdrew: the guest it conferred on and when, so
    /// a repeat revoke reports the first (OF-232). Key: id16 (grant).
    FEDERATION_GUEST_REVOKE: VaultMeta b"federation:guest_revoke:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// Immutable one-time organization-administration power grant (admins and their allowed powers).
    /// Key: hex32 (org_ref).
    ORG_ADMIN_POLICY: VaultMeta b"org.admin.v1." LegacyJson
        [restore: refuse "org admin grants"] [family: unclassified] [tier: canonical];
    /// One holder's delivery of one export-first removal archive: the delivery version it was
    /// last sent and the one it acknowledged, never the archive (FIX 3215, 3396). Key: hex32
    /// (removed person) ":" hex32 (receipt id) ":" hex64 (holder binding key).
    SHARED_ACT_REMOVAL_DELIVERY: VaultMeta b"shared-act:removal-delivery:v1:" Named
        // Restore class: A holder's delivery and ack of a removal archive are facts about bytes
        // that left the vault: a restore stands them as the live vault holds them.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::Vault::erase_removal_archive_actor_in_txn;
    /// An open MFA step-up ceremony (FIX 11694): the person, the exact slip it is bound to, the
    /// ceremony and when it closes. Key: the 32 challenge bytes.
    STEP_UP_CHALLENGE: VaultMeta b"step_up:challenge:v1:" Named
        // Restore class: A person's passkeys, open ceremonies and step-ups stand with the live
        // credentials they protect (FIX 11694).
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::authority::erase_step_up_challenges_actor_in_txn;
    /// A person's enrolled passkey (FIX 11694): credential id, COSE algorithm, public key, RP id,
    /// origin, counter, label and times. Holds no secret. Key: id16 (the person) + SHA-256 (32) of
    /// the credential id.
    STEP_UP_PASSKEY: VaultMeta b"step_up:passkey:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::authority::erase_step_up_passkeys_actor_in_txn;
    /// A completed MFA step-up on one slip (FIX 11694): the person, the factor, the passkey and
    /// when. Key: the 32-byte slip id.
    STEP_UP_RECORD: VaultMeta b"step_up:record:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::authority::erase_step_up_records_actor_in_txn;
    /// Pending authenticator enrollment: the exact slip, sealed seed, key ref and expiry.
    /// Key: person id16 + enrollment id32; never replaces a confirmed enrollment.
    STEP_UP_TOTP_PENDING: VaultMeta b"step_up:totp:pending:v1:" Named Ciphertext
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::authority::erase_step_up_totp_actor_in_txn;
    /// A person's confirmed authenticator: sealed seed, erasable key ref and spent step.
    /// Key: person id16 + enrollment id32. Seed bytes never rest in plaintext.
    STEP_UP_TOTP: VaultMeta b"step_up:totp:v1:" Named Ciphertext
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::authority::erase_step_up_totp_actor_in_txn;
}
