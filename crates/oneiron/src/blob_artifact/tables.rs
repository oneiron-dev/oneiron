//! The side tables `blob_artifact` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Asset refcount marker. Key: bytes32 + id16.
    BLOB_ARTIFACT_ASSET_REF: VaultMeta b"blob_artifact:asset_ref:v1:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Esign machine actor id. Key: ().
    ESIGN_ARTIFACT_ACTOR: VaultMeta b"esign.artifact_actor.v1" Raw
        [restore: refuse "e-sign capabilities"] [family: unclassified] [tier: canonical];
    /// Esign document audit event. Key: id16 + u64be.
    ESIGN_AUDIT: VaultMeta b"esign.audit.v1/" LegacyJson
        [restore: refuse_image_entities "e-sign ceremonies"]
        [family: unclassified]
        [tier: canonical];
    /// Signing capability row. Key: bytes32.
    ESIGN_CAPABILITY_TOKEN: VaultMeta b"esign.capability.v1/" LegacyJson
        [restore: refuse "e-sign capabilities"] [family: unclassified] [tier: canonical];
    /// Esign outbound dispatch marker. Key: bytes32.
    ESIGN_DISPATCH_MARKER: VaultMeta b"esign.dispatch.v1/" Raw
        [restore: refuse "e-sign capabilities"] [family: unclassified] [tier: canonical];
    /// Held automated sign act, one per recipient. Key: hex32/string.
    ESIGN_HELD_SIGNING: VaultMeta b"esign.held_signing.v1/" Named
        [restore: refuse_image_entities "e-sign ceremonies"]
        [family: unclassified]
        [tier: canonical]
        => crate::blob_artifact::esign::erase_held_signing_actor_in_txn;
    /// Signature image byte budget. Key: id16.
    ESIGN_IMAGE_BYTES_BUDGET: VaultMeta b"esign.image_bytes.v1/" Raw
        [restore: refuse_image_entities "e-sign ceremonies"]
        [family: unclassified]
        [tier: canonical];
    /// The send act a signing document's staged notices go out under with no caller (FIX 6219):
    /// the principal the send crossed the gate as, its gate class and the send's intent ref.
    /// Engine-private, never in a notice; no credential. Key: id16 (document).
    ESIGN_NOTICE_SEND_ACT: VaultMeta b"esign.notice_send_act.v1/" Named Engine
        // Restore class: FIX 6219: the send act its notices go out under unattended is authority,
        // so it stays as the live vault holds it (an erase that took it stays done); no image
        // restores one.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::blob_artifact::esign::erase_notice_send_act_actor_in_txn;
    /// Signing principal set owner stamp. Key: ().
    ESIGN_PRINCIPAL_OWNER_STAMP: VaultMeta b"esign.principal.owner_stamp.v1" Raw
        [restore: refuse "e-sign capabilities"] [family: unclassified] [tier: canonical];
    /// Signing principal. Key: hex32.
    ESIGN_PRINCIPAL: VaultMeta b"esign.principal.v1/" LegacyJson
        [restore: refuse "e-sign capabilities"] [family: unclassified] [tier: canonical];
    /// Advisory burst observation for one document/recipient/window. Key: hex32/string/u64be.
    ESIGN_PUBLIC_CHECK: VaultMeta b"esign.public_check.v1/" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Advisory public ceremony rate count, never a signing refusal. Key: document hex32 `/`
    /// recipient (or `all`); value window u64be + count u64be.
    ESIGN_PUBLIC_RATE_V2: VaultMeta b"esign.public_rate.v2/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Recipient live capability index: every digest minted for the recipient, in mint order, as
    /// concatenated 32-byte digests. Key: id16 (document) + string (recipient id).
    ESIGN_RECIPIENT_CAPABILITY_INDEX: VaultMeta b"esign.recipient_capability.v1/" Raw
        [restore: refuse "e-sign capabilities"] [family: unclassified] [tier: canonical];
    /// Completed seal attempt result. Key: id16.
    ESIGN_SEAL_RESULT: VaultMeta b"esign.seal_result.v1/" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Sealed document manifest. Key: id16.
    ESIGN_SEALED_DOCUMENT: VaultMeta b"esign.sealed.v1/" LegacyJson
        [restore: refuse_image_entities "e-sign ceremonies"]
        [family: unclassified]
        [tier: canonical];
    /// Signature image ownership marker. Key: id16 + string + string.
    ESIGN_SIGNATURE_IMAGE_BINDING: VaultMeta b"esign.signature_image.v1/" Raw
        [restore: refuse_image_entities "e-sign ceremonies"]
        [family: unclassified]
        [tier: canonical];
}
