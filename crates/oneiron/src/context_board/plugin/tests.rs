use super::*;

use crate::claim::ClaimSource as TestClaimSource;

use crate::skill::SkillContentHash;

struct AllowAll;

impl SectionBindingResolver for AllowAll {
    fn state_family_exists(&self, _state_family: &StateFamilyRef) -> bool {
        true
    }
    fn authority_lane_exists(&self, _authority: &AuthorityLaneRef) -> bool {
        true
    }
    fn budget_policy_exists(&self, _budget: &BudgetPolicyRef) -> bool {
        true
    }
}

const CRM_HASH_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn crm_envelope() -> SectionManifestEnvelope {
    SectionManifestEnvelope {
        schema_version: SECTION_MANIFEST_SCHEMA_VERSION,
        manifest: SectionManifest {
            section_id: SectionId("crm_contacts".to_owned()),
            name: "CRM".to_owned(),
            state_family: StateFamilyRef {
                family: "crm.contacts".to_owned(),
                version: 1,
            },
            verbs: vec![
                SectionVerbRef("board.expand".to_owned()),
                SectionVerbRef("tasks.create".to_owned()),
            ],
            authority_lane: AuthorityLaneRef("plugin.crm".to_owned()),
            budget_policy: BudgetPolicyRef(
                super::super::frame::PLUGIN_SECTION_BUDGET_POLICY_REF.to_owned(),
            ),
            provenance: SectionManifestProvenance {
                pack_id: "crm-pack".to_owned(),
                skill_id: "sk_crm".to_owned(),
                skill_version: "1.0.0".to_owned(),
                content_hash_hex: CRM_HASH_HEX.to_owned(),
            },
        },
    }
}

/// The manifest as raw MessagePack, mirroring the derive's named encoding.
/// Used only to build hostile envelopes the typed encoder would refuse.
fn manifest_value(manifest: &SectionManifest) -> Value {
    Value::Map(vec![
        (
            Value::from("section_id"),
            Value::from(manifest.section_id.0.as_str()),
        ),
        (Value::from("name"), Value::from(manifest.name.as_str())),
        (
            Value::from("state_family"),
            Value::Map(vec![
                (
                    Value::from("family"),
                    Value::from(manifest.state_family.family.as_str()),
                ),
                (
                    Value::from("version"),
                    Value::from(manifest.state_family.version),
                ),
            ]),
        ),
        (
            Value::from("verbs"),
            Value::Array(
                manifest
                    .verbs
                    .iter()
                    .map(|verb| Value::from(verb.0.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from("authority_lane"),
            Value::from(manifest.authority_lane.0.as_str()),
        ),
        (
            Value::from("budget_policy"),
            Value::from(manifest.budget_policy.0.as_str()),
        ),
        (
            Value::from("provenance"),
            Value::Map(vec![
                (
                    Value::from("pack_id"),
                    Value::from(manifest.provenance.pack_id.as_str()),
                ),
                (
                    Value::from("skill_id"),
                    Value::from(manifest.provenance.skill_id.as_str()),
                ),
                (
                    Value::from("skill_version"),
                    Value::from(manifest.provenance.skill_version.as_str()),
                ),
                (
                    Value::from("content_hash_hex"),
                    Value::from(manifest.provenance.content_hash_hex.as_str()),
                ),
            ]),
        ),
    ])
}

fn skill(lifecycle: SkillLifecycle, version: &str, hash_hex: &str) -> SkillRecord {
    let mut record = SkillRecord::new(
        "sk_crm",
        "CRM pack",
        version,
        ClaimApprovalStatus::Approved,
        lifecycle,
        TestClaimSource::ToolOutput,
        0.5,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("origin"), Value::from("test"))]),
    );
    let mut bytes = [0_u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let high = u8::from_str_radix(&hash_hex[index * 2..index * 2 + 1], 16).unwrap();
        let low = u8::from_str_radix(&hash_hex[index * 2 + 1..index * 2 + 2], 16).unwrap();
        *slot = (high << 4) | low;
    }
    record.content_hash = Some(SkillContentHash::from_bytes(bytes));
    record
}

struct Lifecycle(Option<SkillRecord>);

impl SkillLifecycleSource for Lifecycle {
    fn skill_record(&self, skill_id: &str) -> PluginResult<Option<SkillRecord>> {
        Ok(self.0.clone().filter(|record| record.skill_id == skill_id))
    }
}

#[test]
fn unknown_manifest_field_is_rejected_not_ignored() {
    // An otherwise-valid envelope carrying ONE extra field. Encoded as raw
    // MessagePack so the hostile shape is not filtered by our own encoder.
    let envelope = crm_envelope();
    let mut valid = Vec::new();
    rmpv::encode::write_value(
        &mut valid,
        &Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(SECTION_MANIFEST_SCHEMA_VERSION),
            ),
            (Value::from("manifest"), manifest_value(&envelope.manifest)),
        ]),
    )
    .expect("encode control envelope");
    assert_eq!(
        decode_section_manifest(&valid).expect("control decodes"),
        envelope
    );

    let mut hostile = Vec::new();
    rmpv::encode::write_value(
        &mut hostile,
        &Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(SECTION_MANIFEST_SCHEMA_VERSION),
            ),
            (Value::from("manifest"), manifest_value(&envelope.manifest)),
            (Value::from("extra"), Value::from(true)),
        ]),
    )
    .expect("encode hostile envelope");
    assert!(matches!(
        decode_section_manifest(&hostile),
        Err(PluginSectionError::ManifestCodec)
    ));
}

#[test]
fn unsupported_schema_version_fails_closed() {
    let mut envelope = crm_envelope();
    envelope.schema_version = SECTION_MANIFEST_SCHEMA_VERSION + 1;
    let verbs = SectionVerbAllowlist::from_exported_verbs();
    assert!(matches!(
        validate_manifest_shape(&envelope, &AllowAll, &verbs),
        Err(PluginSectionError::UnsupportedSchemaVersion { .. })
    ));
}

#[test]
fn admission_requires_the_exact_approved_version_and_hash() {
    let verbs = SectionVerbAllowlist::from_exported_verbs();
    let drifted_version = skill(SkillLifecycle::Active, "1.0.1", CRM_HASH_HEX);
    assert!(matches!(
        validate_manifest_for_admission(crm_envelope(), &drifted_version, &AllowAll, &verbs),
        Err(PluginSectionError::ProvenanceMismatch)
    ));

    let drifted_hash = skill(
        SkillLifecycle::Active,
        "1.0.0",
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    assert!(matches!(
        validate_manifest_for_admission(crm_envelope(), &drifted_hash, &AllowAll, &verbs),
        Err(PluginSectionError::ProvenanceMismatch)
    ));
}

#[test]
fn install_claim_payload_round_trips_and_binds_its_digest() {
    let envelope = crm_envelope();
    let bytes = encode_section_manifest(&envelope).expect("encode");
    let payload = PluginInstallClaimPayload {
        schema_version: PLUGIN_INSTALL_CLAIM_SCHEMA_VERSION,
        manifest_digest: section_manifest_digest(&bytes),
        manifest_bytes: bytes,
        section_id: SectionId("crm_contacts".to_owned()),
        target: PluginInstallTarget::ExistingSkill {
            skill_ref: EntityId::from_bytes([3_u8; 16]).unwrap(),
        },
        origin: PluginInstallOrigin::Conversation {
            turn_ref: "turn_1".to_owned(),
        },
        skill_id: "sk_crm".to_owned(),
        skill_version: "1.0.0".to_owned(),
        content_hash_hex: CRM_HASH_HEX.to_owned(),
        package_pin_type: String::new(),
        package_pin: String::new(),
    };
    let decoded =
        PluginInstallClaimPayload::from_value(&payload.to_value()).expect("payload decodes");
    assert_eq!(decoded, payload);
    assert_eq!(decoded.manifest().expect("manifest decodes"), envelope);

    let mut tampered = payload;
    tampered.manifest_bytes = encode_section_manifest(&{
        let mut other = crm_envelope();
        other.manifest.name = "CRM2".to_owned();
        other
    })
    .expect("encode tampered");
    assert!(matches!(
        tampered.manifest(),
        Err(PluginSectionError::MalformedClaimPayload {
            field: "manifest_digest"
        })
    ));
}

#[test]
fn scratchpad_is_persisted_actor_scoped_board_state_under_live_registration() {
    use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::edge::EdgeActorClass;
    use crate::temporal::TimeRange;
    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        crate::Vault::open(dir.path(), crate::config::VaultConfig::default()).expect("vault");
    let owner = EntityId::from_bytes([0x31; 16]).expect("owner");
    let other = EntityId::from_bytes([0x32; 16]).expect("other");
    let skill_id = EntityId::from_bytes([0x33; 16]).expect("skill");
    let install = EntityId::from_bytes([0x34; 16]).expect("install");
    let at = TimeRange { start: 1, end: 1 };
    for actor in [owner, other] {
        vault
            .put_entity(
                &actor,
                crate::registry::ENTITY_TYPE_PERSON,
                at,
                1,
                b"person",
            )
            .expect("actor");
    }
    let candidate = skill(SkillLifecycle::Candidate, "1.0.0", CRM_HASH_HEX);
    vault
        .put_skill_record(&skill_id, &candidate, at, 1)
        .expect("candidate skill");
    let active = skill(SkillLifecycle::Active, "1.0.0", CRM_HASH_HEX);
    vault
        .update_skill_record(&skill_id, &active, at, 2)
        .expect("admitted skill");
    let mut envelope = crm_envelope();
    envelope.manifest.section_id = SectionId("actor_scratchpad".to_owned());
    envelope.manifest.name = "SCRATCHPAD".to_owned();
    envelope.manifest.state_family = StateFamilyRef {
        family: "scratchpad".to_owned(),
        version: 1,
    };
    envelope.manifest.authority_lane = AuthorityLaneRef("actor.private".to_owned());
    let manifest_bytes = encode_section_manifest(&envelope).expect("manifest");
    let payload = PluginInstallClaimPayload {
        schema_version: PLUGIN_INSTALL_CLAIM_SCHEMA_VERSION,
        manifest_digest: section_manifest_digest(&manifest_bytes),
        manifest_bytes,
        section_id: envelope.manifest.section_id.clone(),
        target: PluginInstallTarget::ExistingSkill {
            skill_ref: skill_id,
        },
        origin: PluginInstallOrigin::Conversation {
            turn_ref: "turn_1".to_owned(),
        },
        skill_id: active.skill_id.clone(),
        skill_version: active.version.clone(),
        content_hash_hex: CRM_HASH_HEX.to_owned(),
        package_pin_type: String::new(),
        package_pin: String::new(),
    };
    let mut install_body = ClaimBody::new(
        PREDICATE_PLUGIN_SECTION_INSTALL,
        ClaimSubject::Entity(skill_id),
        payload.to_value(),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    vault
        .batch()
        .put_replicated(
            &install,
            crate::registry::ENTITY_TYPE_CLAIM,
            at,
            1,
            &crate::claim::encode_claim_body(&install_body).expect("claim bytes"),
        )
        .commit()
        .expect("replicated approved install fixture");
    let registry =
        PluginSectionRegistry::rebuild(&vault, &AllowAll).expect("registered board section");
    let section = envelope.manifest.section_id;
    assert!(registry.get(&section).is_some());
    let input = BoardBlockWriteEnvelope {
        section_id: section.clone(),
        kind: BoardBlockKind::Scratchpad,
        scope: BoardBlockScope::ActorPrivate { owner_ref: owner },
        source_revision_ref: [0x35; 16],
        markdown: "private scratchpad revision".to_owned(),
    };
    let stored = vault
        .memory(owner, EdgeActorClass::Human)
        .put_board_block(&registry, &input)
        .expect("board block");
    assert_eq!(stored.author_ref, *owner.as_bytes());
    assert_eq!(stored.source_revision_ref, [0x35; 16]);
    assert!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_NOTE)
            .expect("notes")
            .is_empty()
    );
    let error = vault
        .memory(other, EdgeActorClass::Human)
        .put_board_block(&registry, &input)
        .expect_err("foreign owner");
    assert_eq!(error.code, crate::memory::MEMORY_CODE_FORBIDDEN);
    assert!(
        vault
            .memory(other, EdgeActorClass::Human)
            .board_blocks(&registry, &section, 10)
            .expect("other blocks")
            .is_empty()
    );
    let snapshot = vault
        .memory(owner, EdgeActorClass::Human)
        .board_block_snapshot(&registry, &section, 10)
        .expect("projection");
    assert_eq!(
        snapshot.rows[0].cells,
        vec![stored.markdown.clone(), "35".repeat(16)]
    );
    let sections = render_plugin_sections(&registry, &[snapshot], &Lifecycle(Some(active)))
        .expect("existing renderer");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].name(), "SCRATCHPAD");
    assert!(sections[0].pinned_rows().is_empty());
    drop(vault);

    let vault =
        crate::Vault::open(dir.path(), crate::config::VaultConfig::default()).expect("reopen");
    let registry = PluginSectionRegistry::rebuild(&vault, &AllowAll).expect("rebuild");
    assert_eq!(
        vault
            .memory(owner, EdgeActorClass::Human)
            .board_blocks(&registry, &section, 10)
            .expect("durable blocks"),
        vec![stored]
    );
    // Revocation invalidates even a previously cached registry at both doors.
    install_body.lifecycle = ClaimLifecycleStatus::Retracted;
    vault
        .batch()
        .put_replicated(
            &install,
            crate::registry::ENTITY_TYPE_CLAIM,
            at,
            2,
            &crate::claim::encode_claim_body(&install_body).expect("claim bytes"),
        )
        .commit()
        .expect("replicated retracted install fixture");
    for error in [
        vault
            .memory(owner, EdgeActorClass::Human)
            .put_board_block(&registry, &input)
            .expect_err("revoked write"),
        vault
            .memory(owner, EdgeActorClass::Human)
            .board_blocks(&registry, &section, 10)
            .expect_err("revoked read"),
    ] {
        assert_eq!(error.code, crate::memory::MEMORY_CODE_FORBIDDEN);
    }
}
