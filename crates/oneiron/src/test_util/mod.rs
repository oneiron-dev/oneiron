//! Shared test helpers. Centralized to avoid drift between per-module
//! copies of `open_test_vault`, seed-id, policy-manifest, and config
//! fixtures.
//!
//! Config carve-out: [`embedding_test_config`] is the canonical
//! embedding-enabled config. A module keeps a LOCAL `test_config()` only
//! when its values genuinely diverge (map size, dimensions, embedding
//! model, HNSW params); a copy that is value-identical to the shared
//! helper is a drift hazard and must route through it.

pub(crate) mod log_capture;
pub(crate) mod row_dump;
/// Test-only-file classification for the source-scanning fences. The
/// integration binaries mount the same file through `tests/common`.
pub(crate) mod source_scan;

mod channel_identity;
pub(crate) use channel_identity::{put_native_mail_sender, self_held_identity_in_state};
mod dreamer_rows;
pub(crate) use dreamer_rows::{seeded_without_dreamer_rows, without_dreamer_rows};

use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Id bytes pinned by production code. `entity` refuses them so a generic
/// fixture can never alias a system identity. Any byte NOT listed here is
/// safe for test seeds. A new production id pin must be added to this list
/// in the same change that mints it.
///
/// - `0x00`, `0xFF`: reserved sentinels (`entity_id::is_reserved_entity_id_bytes`)
/// - `0x11`: dreamer consolidation probe actor
/// - `0x42`: code-run replay canonical request actor
/// - `0x47`: gate local-write actor ref
/// - `0xA1..=0xA6`: seeded system-agent row/actor ids (canonical manifest).
///   ONE-1709's `sys.team_lead` row is deliberately NOT a repeated byte
///   (`aaaa…aaaa1709`): every free byte in the roster's `0xA*` range was
///   already in `[seed; 16]` fixture use, and a non-repeating id is
///   unreachable from that whole class of seed.
/// - `0xD7`: default policy manifest id
/// - `0xE1`: first-party connector actor id
pub(crate) const PINNED_ID_BYTES: [u8; 13] = [
    0x00, 0x11, 0x42, 0x47, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xD7, 0xE1, 0xFF,
];

/// Canonical test entity id: `[seed; 16]`.
///
/// Panics when `seed` is production-pinned (see [`PINNED_ID_BYTES`]) —
/// including `entity(0)`, whose bytes are the reserved zero sentinel.
/// Tests that *intend* a pinned identity must construct it explicitly
/// (a seeded roster row id resolved through
/// `Vault::get_seeded_agent_definition_by_logical_id`,
/// `crate::gate::default_policy_manifest_id()`, or
/// `EntityId::from_bytes` with an intent comment), never through this
/// helper.
pub(crate) fn entity(seed: u8) -> EntityId {
    assert!(
        !PINNED_ID_BYTES.contains(&seed),
        "test seed {seed:#04x} collides with a production-pinned id byte; \
         pick a byte outside PINNED_ID_BYTES or construct the pinned id explicitly"
    );
    EntityId::from_bytes([seed; 16]).expect("non-pinned seed byte forms a valid entity id")
}

/// Seeds a minimal, VALID AGENT_DEF entity at `id` and returns it.
///
/// Centralized because an AGENT_DEF body is validated on write: the
/// obvious `put_entity(id, ENTITY_TYPE_AGENT_DEF, b"fixture")` is rejected
/// with `InvalidAgentDefBody`, so every test needing "an actor that is a
/// real agent" would otherwise grow its own copy of this constructor.
pub(crate) fn seed_agent_definition(vault: &Vault, id: EntityId, label: &str) -> EntityId {
    use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
    use rmpv::Value;

    let def = AgentDefinition::new(
        format!("{label}-{}", id.to_hex()),
        "test_util agent fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("fixture"), Value::from(label))]),
        None,
        true,
        None,
    );
    vault
        .put_agent_definition(
            &id,
            &def,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .expect("seed agent definition");
    id
}

// One implementation each, shared with the test-support doors other crates
// use (the seal organ's end-to-end check).
pub(crate) use crate::test_support::{
    entity_record, provision_engine_machines, put_policy_manifest_bytes, test_host_issuer,
};

/// Removes the Dreamer's read row from the vault's default policy, as a vault
/// seeded before ARCH-0026's warm default (or whose owner removed the row)
/// holds it. Every other row, the Dreamer's ceiling and permit included,
/// stays.
pub(crate) fn withhold_dreamer_read(vault: &Vault) -> crate::Result<()> {
    use rmpv::Value;
    let id = crate::gate::default_policy_manifest_id()?;
    let body = vault.get(&id)?.ok_or(Error::EntityNotFound)?;
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut body.as_slice()).expect("default policy map")
    else {
        unreachable!("default policy manifest is a map");
    };
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?.to_hex();
    for (key, table) in &mut entries {
        if let (Some("scoped_grants"), Value::Array(rows)) = (key.as_str(), table) {
            rows.retain(|row| {
                !row.as_map().is_some_and(|fields| {
                    fields.iter().any(|(name, value)| {
                        name.as_str() == Some("actor_ref") && value.as_str() == Some(&dreamer)
                    })
                })
            });
        }
    }
    entries.retain(|(key, table)| {
        key.as_str() != Some("scoped_grants")
            || table.as_array().is_some_and(|rows| !rows.is_empty())
    });
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).expect("encode policy");
    put_policy_manifest_bytes(vault, id, &data)
}

/// Declares each prefix in `prefixes` normal (criticality and sensitivity) in
/// the vault's default policy, as an owner's own rule would. A predicate no
/// rule names takes the criticality floor, so a fixture that writes one through
/// a gated door and expects a reader to act on it declares it here.
pub(crate) fn declare_predicates_normal(vault: &Vault, prefixes: &[&str]) -> crate::Result<()> {
    declare_predicates(vault, prefixes, "normal")
}

/// Sets each prefix's criticality in the stored default manifest: a rule
/// that already names the prefix takes it, otherwise a new rule does.
pub(crate) fn declare_predicates(
    vault: &Vault,
    prefixes: &[&str],
    criticality: &str,
) -> crate::Result<()> {
    use rmpv::Value;
    let id = crate::gate::default_policy_manifest_id()?;
    // A legacy test vault stores no manifest and reads the shipped one.
    let body = match vault.get(&id)? {
        Some(body) => body,
        None => crate::gate::default_policy_manifest()?,
    };
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut body.as_slice()).expect("default policy map")
    else {
        unreachable!("default policy manifest is a map");
    };
    let axes = || {
        Value::Map(vec![
            (Value::from("criticality"), Value::from(criticality)),
            (Value::from("sensitivity"), Value::from("normal")),
        ])
    };
    let rules = match entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("rules"))
    {
        Some((_, Value::Array(rules))) => rules,
        _ => {
            entries.push((Value::from("rules"), Value::Array(Vec::new())));
            match entries.last_mut() {
                Some((_, Value::Array(rules))) => rules,
                _ => unreachable!("rules were just pushed"),
            }
        }
    };
    for prefix in prefixes {
        let mut named = false;
        for rule in rules.iter_mut() {
            let Value::Map(fields) = rule else { continue };
            if !fields.iter().any(|(key, value)| {
                key.as_str() == Some("prefix") && value.as_str() == Some(*prefix)
            }) {
                continue;
            }
            named = true;
            match fields
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("axes"))
            {
                Some((_, value)) => *value = axes(),
                None => fields.push((Value::from("axes"), axes())),
            }
        }
        if !named {
            rules.push(Value::Map(vec![
                (Value::from("prefix"), Value::from(*prefix)),
                (Value::from("axes"), axes()),
            ]));
        }
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).expect("encode policy");
    put_policy_manifest_bytes(vault, id, &data)
}

/// Pin a test model manifest with a passing teacher-probe receipt, the way
/// the bench publishes one; a bare `set_model_manifest` refuses a new teacher.
pub(crate) fn pin_model_manifest(
    vault: &crate::Vault,
    manifest: &crate::llm::manifest::ModelManifest,
) -> crate::Result<()> {
    let policy = vault.teacher_probe_policy(None)?;
    let approval = crate::llm::manifest::TeacherProbeApproval::for_scored_checkpoint(
        manifest, &policy, 1_000_000,
    )?;
    vault.set_model_manifest_with_teacher_approval(manifest, &approval)
}

/// Re-appends every live claim-bound gate decision as if created at
/// `created_at`, so a test can age real receipts past a retention horizon.
pub(crate) fn backdate_claim_gate_decisions(vault: &Vault, created_at: u64) -> crate::Result<()> {
    vault.with_write_txn(|txn| {
        let mut rows = Vec::new();
        vault.store.for_each_gate_decision_in_txn(txn, |record| {
            if record.claim_id.is_some() && record.redacted_at.is_none() {
                rows.push(record);
            }
            Ok(())
        })?;
        for mut row in rows {
            vault
                .store
                .delete_gate_decision_in_txn(txn, row.decision_id)?;
            row.created_at = created_at;
            vault.store.append_gate_decision_in_txn(txn, &row)?;
        }
        Ok(())
    })
}

/// Copy the shipped teacher-probe policy row into a custom test policy. Tests
/// that replace the seeded default must preserve this floor before pinning a
/// teacher, without accidentally replacing their own Gate policy rows.
pub(crate) fn add_default_teacher_probe_policy(entries: &mut Vec<(rmpv::Value, rmpv::Value)>) {
    let default = crate::gate::default_policy_manifest().unwrap();
    let rmpv::Value::Map(default_entries) =
        rmpv::decode::read_value(&mut default.as_slice()).expect("seeded policy map")
    else {
        panic!("seeded policy map");
    };
    entries.push(
        default_entries
            .into_iter()
            .find(|(key, _)| key.as_str() == Some("teacher_probe"))
            .expect("seeded teacher probe row"),
    );
}

/// Installs the shipped default policy manifest carrying one unrestricted
/// schema-1.2 `core:read` grant per reader. A plain scoped-read key reads
/// nothing until a trusted manifest grants it.
pub(crate) fn authorize_readers(vault: &Vault, readers: &[&str]) {
    authorize_readers_with(vault, readers, Vec::new());
}

/// [`authorize_readers`] with `rows` replacing the shipped manifest's rows
/// under the same keys.
pub(crate) fn authorize_readers_with(
    vault: &Vault,
    readers: &[&str],
    rows: Vec<(rmpv::Value, rmpv::Value)>,
) {
    let authority = crate::federation::scope_codec::encode_scope_value(
        &crate::federation::scope_codec::read_preset(),
    )
    .expect("read preset encodes");
    let grants: Vec<rmpv::Value> = readers
        .iter()
        .map(|reader| {
            rmpv::Value::Map(vec![
                (rmpv::Value::from("actor_ref"), rmpv::Value::from(*reader)),
                (
                    rmpv::Value::from("effector"),
                    rmpv::Value::from("core:read"),
                ),
                (rmpv::Value::from("scope"), authority.clone()),
                (
                    rmpv::Value::from("receipt_required"),
                    rmpv::Value::Boolean(false),
                ),
            ])
        })
        .collect();
    let bytes = crate::gate::default_policy_manifest().unwrap();
    let rmpv::Value::Map(mut entries) =
        rmpv::decode::read_value(&mut bytes.as_slice()).expect("default manifest")
    else {
        panic!("manifest map");
    };
    entries.retain(|(key, _)| {
        key.as_str() != Some("scoped_grants") && rows.iter().all(|(row, _)| row != key)
    });
    entries.push((
        rmpv::Value::from("scoped_grants"),
        rmpv::Value::Array(grants),
    ));
    entries.extend(rows);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries)).expect("manifest encodes");
    put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().expect("manifest id"),
        &bytes,
    )
    .expect("install read grants");
}

/// Canonical embedding-enabled test config: 16 MiB map, 4 dimensions,
/// `test/model@v1` embedding model, 16 readers. Everything else is the
/// `VaultConfig::device()` preset — HNSW and text-analyzer defaults
/// included, so do NOT re-assign defaults here.
pub(crate) fn embedding_test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config
}

/// A store clock pinned at `now` with fresh ids, for fixtures whose records
/// carry fixed timestamps that the engine's clock must agree with.
pub(crate) fn pinned_store_clock(now: u64) -> crate::ports::StoreClock {
    struct Pinned(u64);
    impl crate::ports::Clock for Pinned {
        fn now_recorded_at(&self) -> u64 {
            self.0
        }
    }
    impl crate::ports::IdGen for Pinned {
        fn ulid(&self) -> [u8; 16] {
            uuid::Uuid::now_v7().into_bytes()
        }
    }
    let pinned = std::sync::Arc::new(Pinned(now));
    crate::ports::StoreClock::new(pinned.clone(), pinned)
}

/// Opens a temporary vault with the supplied config. Returns the
/// `TempDir` so callers keep the directory alive for the vault's lifetime.
pub(crate) fn open_test_vault_with(cfg: VaultConfig) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), cfg).expect("open vault");
    clear_default_policy_manifest_for_legacy_tests(&vault);
    (dir, vault)
}

/// Signs a MACHINE writer's candidate with the signer the host retained for
/// the envelope's actor, as an engine writer does before its write door.
pub(crate) fn sign_machine_candidate(
    vault: &Vault,
    id: &EntityId,
    candidate: &crate::ClaimCandidate,
    envelope: &crate::WriteEnvelope,
) -> crate::WriteEnvelope {
    let mut envelope = envelope.clone();
    let txn = vault.store.env.read_txn().expect("read txn");
    vault
        .sign_retained_machine_claim_in_txn(&txn, id, candidate, &mut envelope)
        .expect("machine claim signature");
    envelope
}

/// A native host's proof for the vault's embedded owner, who is ensured
/// first: what an owner-bound door (an off-record promote or flip) takes.
pub(crate) fn embedded_owner_proof(vault: &Vault) -> crate::consent::AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// Roots the test vault under the test host, if nothing has, and binds
/// `owner` as its human owner: owner verbs hold only for a bound owner
/// (H149).
pub(crate) fn bind_test_owner(vault: &Vault, owner: EntityId) {
    let issuer = test_host_issuer();
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .bind_host_owner_for_test(&issuer, owner)
        .expect("owner binding");
}

/// A proof this vault authenticated, with no credential, for a live PERSON
/// who does not own it: what a native host can mint for any person it knows.
/// An owner door refuses it; a person-tier door takes it for that person's
/// own rows.
pub(crate) fn non_owner_proof(vault: &Vault) -> crate::consent::AuthenticatedOwner {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("a live person");
    vault
        .authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("a non-owner person's proof")
}

/// A second live owner's proof on `vault`: an Owner-role member once the
/// vault is shared under its embedded owner. It shares the vault, so a test
/// calls it once per vault.
pub(crate) fn co_owner_proof(vault: &Vault) -> crate::consent::AuthenticatedOwner {
    use crate::federation::{FederationGrantRole, InitialSharedMember};
    let owner = embedded_owner_proof(vault);
    let co_owner = EntityId::now();
    vault
        .put_entity(
            &co_owner,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"co-owner",
        )
        .expect("a live person");
    vault
        .initialize_shared_vault(
            &owner,
            42,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner.actor(),
                    role: Some(FederationGrantRole::Owner),
                },
                InitialSharedMember {
                    member_ref: co_owner,
                    role: Some(FederationGrantRole::Owner),
                },
            ],
            1,
        )
        .expect("a shared vault");
    vault
        .authenticate_owner(
            co_owner,
            &co_owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("the co-owner's proof")
}

/// An owner proof another vault authenticated for `actor` under `principal`,
/// with `actor` a live PERSON there as in the vault under test: what a door
/// of that vault must refuse. The other vault's `TempDir` and handle come
/// back with it, for the proof's lifetime.
pub(crate) fn foreign_owner_proof(
    actor: EntityId,
    principal: &str,
) -> (tempfile::TempDir, Vault, crate::consent::AuthenticatedOwner) {
    let (dir, other) = open_test_vault_with(VaultConfig::device());
    other
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .expect("the shared person");
    let proof = other
        .authenticate_owner(actor, principal, true, crate::store::GateDecisionId::now())
        .expect("the other vault's proof");
    (dir, other, proof)
}

/// The vault owner's proof bound to a full owner slip the test host minted
/// for it under `context`, as an owner route carries one, with that slip's
/// id. Roots the vault under the test host first.
pub(crate) fn credentialed_owner_proof(
    vault: &Vault,
    context: &[u8],
) -> (crate::consent::AuthenticatedOwner, [u8; 32]) {
    let issuer = test_host_issuer();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let mut claims = vault
        .ensure_host_root_slip(&issuer)
        .expect("root slip")
        .claims;
    if !crate::authority::actor_binding_is_active(
        &vault.authority_fold().expect("authority fold"),
        &owner,
        "human",
    ) {
        bind_test_owner(vault, owner);
    }
    claims.slip_id = *blake3::hash(context).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".into());
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("the owner's slip");
    let verified = vault
        .verify_capability_slip(
            &issuer.public_key(),
            &slip,
            context,
            &issuer.binding_proof(&slip, context).expect("binding proof"),
        )
        .expect("verify the slip");
    let proof = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("authenticate the owner");
    let bound = vault
        .bind_owner_credential(proof, verified)
        .expect("bind the owner's slip");
    (bound, slip.claims.slip_id)
}

/// Revokes `slip_id` when this thread next opens a write transaction, after
/// the door's own early checks and before it takes LMDB's writer: the
/// revocation commits while the act waits for the writer.
pub(crate) fn revoke_before_the_next_write(vault: &std::rc::Rc<Vault>, slip_id: [u8; 32]) {
    let vault = std::rc::Rc::clone(vault);
    crate::store::arm_after_seal_check(move || {
        vault
            .revoke_capability_slip(&test_host_issuer(), slip_id)
            .expect("revoke the owner's slip");
    });
}

/// Roots the vault under the test host and binds `agent` as one of the
/// vault's own agents (an active `agent` binding). The host key holds one
/// live binding, so this is the vault's only bound actor.
pub(crate) fn bind_test_agent(vault: &Vault, agent: EntityId) {
    let issuer = test_host_issuer();
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .bind_host_actor_for_test(&issuer, agent, "agent")
        .expect("agent binding");
    assert!(
        crate::authority::actor_binding_is_active(
            &vault.authority_fold().expect("authority fold"),
            &agent,
            "agent"
        ),
        "the host key already binds another actor"
    );
}

/// Gives `member` an Active contact that clears everything, so in a room
/// the member takes the top clearance (ILDF2).
pub(crate) fn clear_test_contact(vault: &Vault, member: EntityId) {
    let contact = EntityId::now();
    let record = crate::counterparty_contact::CounterpartyContactRecord::user_introduction(
        EntityId::now(),
        format!("{}@example.test", member.to_hex()),
        1,
    )
    .expect("contact record");
    vault
        .create_counterparty_contact(&contact, &record)
        .expect("contact");
    vault
        .put_edge(&contact, crate::EdgeKind::About, &member, 1.0)
        .expect("contact names the member");
    vault
        .set_counterparty_disclosure_scope(
            &contact,
            &crate::disclosure::DisclosureScope::new(
                crate::federation::Scope::top(),
                "room member",
                1,
            )
            .expect("clearance"),
        )
        .expect("contact clearance");
}

/// First open seeds the bootstrap skills, whose activation edits wait for
/// idle publication like any other revision. Publishes them through the
/// model-free drain so an idle-refresh law observes only its own entities.
/// Leaves the loop-owned idle delay at zero.
pub(crate) fn publish_seeded_revisions(vault: &Vault) {
    vault.set_indexed_idle_delay_ms(0).expect("idle delay");
    let seeded = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("seeded idle publication");
    assert!(seeded.failed.is_empty(), "seeded revisions need no model");
    assert!(seeded.superseded.is_empty());
}

/// Asserts `error` is the Gate secret-scan denial: [`GateError::GateWriteRejected`](crate::error::GateError::GateWriteRejected)
/// with outcome `"deny"` and reason codes exactly
/// `["gate.secret_scan.detected", expected_reason]`. Call sites pass the
/// expected leaf reason explicitly (e.g. `"gate.secret_scan.github_token"`)
/// so the asserted detector is visible at the test.
pub(crate) fn assert_secret_scan_rejected(error: Error, expected_reason: &'static str) {
    match error {
        Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => {
            assert_eq!(outcome, "deny");
            assert_eq!(
                reason_codes.as_slice(),
                &["gate.secret_scan.detected", expected_reason]
            );
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
}

/// A private key block the secret scan detects: PEM armor around a base64 body
/// that decodes to an English sentence, not a key. The scan needs the whole
/// block with a base64 body; a header alone is text about keys.
pub(crate) const SYNTHETIC_PRIVATE_KEY_BLOCK: &str = "-----BEGIN PRIVATE KEY-----\n\
U3ludGhldGljIGZpeHR1cmUgYm9keSBmb3IgdGhlIHNlY3JldCBzY2FuIHRlc3RzLiBJdCBpcyBub3QgYSBrZXku\n\
-----END PRIVATE KEY-----";

/// Removes the shipped default policy manifest that `Vault::open` seeds, so a
/// fixture writes under the legacy open policy from here on.
pub(crate) fn clear_default_policy_manifest_for_legacy_tests(vault: &Vault) {
    let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
    vault
        .with_write_txn(|wtxn| {
            crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
            Ok(())
        })
        .expect("clear default policy manifest for legacy test fixture");
}

/// Attaches an outstanding critical confirm to `claim`, as a critical Auto
/// write leaves it: the claim is held until its owner answers.
pub(crate) fn hold_claim_for_critical_confirm(vault: &Vault, claim: EntityId, seed: u8) {
    let pending = crate::store::PendingGateConsentRecord {
        version: 0,
        claim_id: *claim.as_bytes(),
        decision_id: crate::store::GateDecisionId::from_bytes([seed; 16]),
        created_at: crate::unix_seconds_now(),
        diff_handle: vec![seed, seed.wrapping_add(1)],
        read_frontier_hash: [seed.wrapping_add(2); 32],
        reason_codes: vec!["gate.pending.critical_confirm_attached".to_owned()],
        dreamer_run_id: None,
    };
    vault
        .with_write_txn(|txn| vault.store.put_pending_gate_consent_in_txn(txn, &pending))
        .expect("attach a critical confirm");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert!(
        !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, &rtxn, &claim)
            .expect("confirm read"),
        "the claim must read as held"
    );
}

/// A genesis owner entry and its signed critical-confirm answer to `pending`,
/// ready for `Vault::put_authority_log_entries`.
pub(crate) fn critical_confirm_owner_entry(
    pending: &crate::store::PendingGateConsentRecord,
    disposition: crate::authority::CriticalWriteConfirmDisposition,
    seed: u8,
) -> (
    crate::authority::AuthorityLogEntry,
    crate::authority::AuthorityLogEntry,
) {
    use crate::authority::{
        AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthorityTier, CriticalWriteConfirmAction, CriticalWriteConfirmMethod, DeviceAuthority,
        ROLE_ADMIN, ROLE_OWNER,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let sign = |mut entry: AuthorityLogEntry| {
        let transcript =
            crate::authority::authority_transcript(&entry).expect("authority transcript");
        entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
        entry
    };
    let genesis = sign(AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [seed.wrapping_add(1); 32],
            recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 1,
    });
    let binding =
        crate::gate::critical_write_confirm_binding(pending).expect("critical pending binding");
    let confirmation = sign(AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(crate::authority::genesis_vault_id(&genesis).expect("vault id")),
        seq: 1,
        parent_hashes: vec![
            crate::authority::authority_entry_hash(&genesis).expect("genesis hash"),
        ],
        op: AuthorityOp::CriticalWriteConfirm(CriticalWriteConfirmAction {
            schema_version: crate::authority::CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
            confirm_id: binding.confirm_id,
            gate_decision_id: binding.gate_decision_id.as_bytes(),
            claim_id: binding.claim_id,
            effect_digest: binding.effect_digest,
            read_frontier_hash: binding.read_frontier_hash,
            nonce: binding.nonce,
            expires_at: binding.expires_at,
            disposition,
            method: CriticalWriteConfirmMethod::TokenReauth,
        }),
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 2,
    });
    (genesis, confirmation)
}
