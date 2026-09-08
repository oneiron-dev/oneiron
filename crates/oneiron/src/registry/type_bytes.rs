//! Entity type bytes: every statically allocated `ENTITY_TYPE_*` constant.

/// Byte 0 is the ARCH-0003 semantic CLAIM type byte, not a StructuralKind.
pub const ENTITY_TYPE_CLAIM: u8 = 0;

pub const ENTITY_TYPE_TURN: u8 = 1;

pub const ENTITY_TYPE_SESSION: u8 = 2;

pub const ENTITY_TYPE_MESSAGE: u8 = 3;

pub const ENTITY_TYPE_PERSON: u8 = 4;

pub const ENTITY_TYPE_RELATIONSHIP: u8 = 5;

pub const ENTITY_TYPE_EVENT: u8 = 6;

pub const ENTITY_TYPE_SKILL: u8 = 7;

pub const ENTITY_TYPE_SUMMARY: u8 = 8;

pub const ENTITY_TYPE_PLACE: u8 = 9;

pub const ENTITY_TYPE_ASSET_TEXT: u8 = 10;

pub const ENTITY_TYPE_CONVERSATION: u8 = 11;

pub const ENTITY_TYPE_ORG: u8 = 12;

pub const ENTITY_TYPE_FACET: u8 = 13;

pub const ENTITY_TYPE_WORLD: u8 = 14;

pub const ENTITY_TYPE_ASSET: u8 = 15;

pub const ENTITY_TYPE_NOTIFICATION: u8 = 16;

/// OF-334 AgentDefinition entity (AGENT-1, ONE-1443). A saved, host-agnostic
/// composition record (skills / connectors / code-mode MCPs / model tier /
/// scope / optional prompt) with structural CRUD and an update gate — SKILL's
/// shape, so it is a CORE StructuralKind. Short-ID prefix `ag`.
pub const ENTITY_TYPE_AGENT_DEF: u8 = 17;

pub const ENTITY_TYPE_TASK_LIST: u8 = 100;

pub const ENTITY_TYPE_TASK: u8 = 101;

pub const ENTITY_TYPE_MACHINE: u8 = 102;

pub const ENTITY_TYPE_CODE_ARTIFACT: u8 = 103;

pub const ENTITY_TYPE_CODE_SYMBOL: u8 = 104;

/// OF-368 D1 (ARTL-1) versioned blob artifact for foreign binary (office)
/// files. Rides the OF-320 artifact model: append-only version chain in
/// `vault_meta`, content-addressed ASSET bytes, `blob.version` LEDGER claim
/// per version. A blob artifact is not a code artifact — kind = shape
/// (DEC-0005 §7), so CODE_ARTIFACT reuse was rejected.
pub const ENTITY_TYPE_BLOB_ARTIFACT: u8 = 105;

/// ARCH-0032 NOTE primitive (OF-330, ONE-1377): the cross-product
/// working-thought entity, landed with the single `opinion/take` kind so an
/// actor can record an attributed opinion BESIDE a neutral ARCH-0003 CLAIM
/// instead of editing it. Pack-registered in the compiled-product zone; bodies
/// ride the pinned `crate::note::NOTE_BODY_KEYS` ABI.
pub const ENTITY_TYPE_NOTE: u8 = 106;

/// ARCH-0069 S1/S2 secret custody (SECRET-01, ONE-1919): the `SecretCustodyRecord`
/// is the secret VALUE's home — plaintext bytes at rest under the vault DEK
/// plane, never claims / CRDT / export / logs. Maintenance classification in
/// the system zone.
/// Byte 77 minted under the byte-space v3 rider; already at its canon byte, so
/// ONE-1754's re-key has nothing to move for it. Replication of this byte is
/// fail-closed until ONE-1865's per-credential dial replaces the interim
/// sync/selector.rs exclusion.
pub const ENTITY_TYPE_SECRET_CUSTODY: u8 = 77;

/// ARCH-0055 identity-topology ledger event (ONE-1743, owner-ruled seat;
/// byte pinned by the byte-space v3 canon row shipping in the docs lane).
/// Engine-authored maintenance record written ONLY by the identity-topology
/// apply/undo door; public puts are rejected with
/// `MaintenanceKindNotWritable` (D5/MODEL pattern) regardless of the byte's
/// zone, and sync ingest rides the ARCH-0023b fail-closed single-writer
/// stream class.
pub const ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT: u8 = 76;

pub const ENTITY_TYPE_REDACTION_AUDIT: u8 = 64;

/// MODEL substrate entity (ONE-1138, ratified): engine-authored maintenance
/// kind — "written when a substrate first appears in a write path". Public
/// puts are rejected with `MaintenanceKindNotWritable`. Short-ID prefix
/// `mo` is RESERVED. MACHINE reuse was REJECTED — kind = shape
/// (DEC-0005 §7): a model substrate is not a device.
pub const ENTITY_TYPE_MODEL: u8 = 65;

/// AUTHORITY_LOG entry (ONE-1324). Engine-authored maintenance kind for the
/// fold-verified vault authority roster; public puts are rejected with
/// `MaintenanceKindNotWritable`.
pub const ENTITY_TYPE_AUTHORITY_LOG: u8 = 66;

/// DEC-0005 PolicyManifestV1 entity. Engine-authored maintenance kind used by
/// the Gate resolver; public puts are rejected with
/// `MaintenanceKindNotWritable`.
pub const ENTITY_TYPE_POLICY_MANIFEST: u8 = 67;

/// FED-001 FederationGrant entity. Engine-authored maintenance kind for
/// shared-vault membership records.
pub const ENTITY_TYPE_FEDERATION_GRANT: u8 = 68;

/// GATE-14 DiagnosticEvent entity (ONE-1394). Engine-authored maintenance kind
/// carrying one typed, addressable, provenance-bearing self-healing
/// observation; public puts are rejected with `MaintenanceKindNotWritable` and
/// the only writer is the engine-authored `Vault::emit_diagnostic_event` door
/// in `self_heal.rs`. No short-ID prefix.
///
/// Byte-space v3 migrated this kind OUT of the pre-v3 experimental byte 126
/// and into the System band at 69, so 126 is not a DIAGNOSTIC home — it is
/// dev-only experimental space that `validate_entity_type_for_mode` admits
/// under `dev` alone, which is not where a production maintenance kind can
/// live.
pub const ENTITY_TYPE_DIAGNOSTIC: u8 = 69;

// Byte 72 SUSPICIOUS_WAKE, byte 74 CLAIM_CLASS_DESCRIPTOR and byte 75
// SKILL_HUB are canon-reserved system bytes with no engine substrate yet. They
// stay deliberately unregistered — present in the canon conformance census as
// reserves, rejected with `InvalidEntityType` on every write path — rather
// than disappearing from the record.
/// OF-277 connector-key registry record (GOV-01, ONE-1416). Engine-authored
/// maintenance kind carrying effector budgets (sends / spend / rate) and the
/// charter slots for one outbound connector key; public puts are rejected
/// with `MaintenanceKindNotWritable` (structural "no anonymous connectors").
/// Short-ID prefix `ck`.
pub const ENTITY_TYPE_CONNECTOR_KEY: u8 = 70;

/// AEI-006 PsychProfile snapshot entity. Engine-authored maintenance kind for
/// derived profile mirror snapshots keyed by source revision ids.
pub const ENTITY_TYPE_PSYCH_PROFILE: u8 = 71;

/// EIRI-004 AccessGrant entity. Engine-authored maintenance kind for scoped
/// companion control-plane access records.
pub const ENTITY_TYPE_ACCESS_GRANT: u8 = 73;

/// OF-347 ChannelIdentity entity. Engine-authored maintenance kind for
/// vault-resident agent/channel addressability records.
pub const ENTITY_TYPE_CHANNEL_IDENTITY: u8 = 79;

/// OF-347 CounterpartyContact entity. Engine-authored maintenance kind for
/// per-(identity, counterparty) contact and consent records.
pub const ENTITY_TYPE_COUNTERPARTY_CONTACT: u8 = 80;

/// OF-367 StandingOutboundGrant entity. Engine-authored maintenance kind for
/// ask-card and bundle-approval outbound consent grants.
pub const ENTITY_TYPE_OUTBOUND_GRANT: u8 = 81;

/// OF-325 PersonaSnapshotExport entity. Engine-authored maintenance kind
/// recording each consent-gated persona snapshot export (mode A artifact);
/// projects into the receipt family as a Share receipt carrying the
/// persona_compile_stamp.
pub const ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT: u8 = 82;

/// ARCH-0035 communication projector record. Engine-authored maintenance
/// kind for source events, consent transitions, ruling receipts, and the
/// rebuildable contact-view cache.
pub const ENTITY_TYPE_COMM_RECORD: u8 = 83;

/// ONE-1741 SKILL_CONTENT_ANCHOR entity. Engine-authored maintenance kind: a
/// deterministic per-content-hash anchor that owns `skill.scan_verdict`
/// reserved claims, so scan verdicts key on the immortal content bytes rather
/// than any submitting SKILL holder (which can depart). Its 16-byte id is
/// derived from the 32-byte content hash (see
/// `skill_hub::skill_content_anchor_entity_id`), never `EntityId::now()`, so
/// two nodes ingesting the same bytes converge on one anchor. Public puts of
/// this byte are rejected with `MaintenanceKindNotWritable`.
pub const ENTITY_TYPE_SKILL_CONTENT_ANCHOR: u8 = 84;
