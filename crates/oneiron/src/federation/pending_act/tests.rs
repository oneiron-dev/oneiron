const WEEK: u64 = 7 * 24 * 60 * 60;
use super::*;
use crate::TimeRange;
use crate::federation::InitialSharedMember;
use crate::store::GateDecisionId;

fn fixture(
    preset: SharedVaultPreset,
) -> (
    tempfile::TempDir,
    Vault,
    AuthenticatedOwner,
    AuthenticatedOwner,
    AuthenticatedOwner,
) {
    // Membership defaults and act rows are manifest policy: keep the seeded
    // manifest rather than the legacy test opener that removes policy rows.
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::test_util::embedding_test_config()).unwrap();
    let mut holders = Vec::new();
    for _ in 0..3 {
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .unwrap();
        holders.push(
            vault
                .authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())
                .unwrap(),
        );
    }
    let admin = holders.pop().unwrap();
    let other = holders.pop().unwrap();
    let owner = holders.pop().unwrap();
    vault
        .initialize_shared_vault(
            &owner,
            42,
            Some(preset),
            &[
                InitialSharedMember {
                    member_ref: other.actor(),
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: admin.actor(),
                    role: Some(Role::Admin),
                },
            ],
            10,
        )
        .unwrap();
    (dir, vault, owner, other, admin)
}

#[test]
fn preset_seeds_only_four_rows_and_personal_has_none() -> Result<()> {
    for preset in [
        SharedVaultPreset::Family,
        SharedVaultPreset::Team,
        SharedVaultPreset::Org,
        SharedVaultPreset::Community,
    ] {
        let (_dir, vault, owner, _other, _admin) = fixture(preset);
        for name in [
            "delete_vault",
            "erase",
            "transfer_ownership",
            "remove_owner",
        ] {
            assert_eq!(
                vault.shared_act_policy(name)?,
                Some(SharedActPolicy {
                    wait_secs: WEEK,
                    objector_roles: vec![Role::Owner],
                    initiator_roles: vec![Role::Owner],
                    policy_editor_roles: vec![Role::Owner],
                    required_verb: "admin".into(),
                    starter_may_object: true,
                    max_act_name_bytes: 128,
                    max_payload_bytes: 1_048_576,
                    precedence: SharedActPrecedence::HolderMayNarrow,
                })
            );
            assert!(
                !vault
                    .start_authority_act(&owner, 42, name, vec![], 100)?
                    .completed
            );
        }
        assert_eq!(vault.shared_act_policy("export")?, None);
        assert_eq!(vault.shared_act_policy("_default")?, None);
        assert!(
            vault
                .start_authority_act(&owner, 42, "export", vec![], 100)?
                .completed
        );
    }
    let (_dir, vault, owner, _other, _admin) = fixture(SharedVaultPreset::Personal);
    assert_eq!(vault.shared_act_policy("delete_vault")?, None);
    assert!(
        vault
            .start_authority_act(&owner, 42, "delete_vault", vec![], 100)?
            .completed
    );
    Ok(())
}

#[test]
fn window_notifies_named_holders_refuses_admin_and_holds_until_withdrawn() -> Result<()> {
    let (dir, vault, owner, other, admin) = fixture(SharedVaultPreset::Team);
    let act = vault.start_authority_act(&owner, 42, "delete_vault", b"opaque".to_vec(), 100)?;
    assert_eq!(act.deadline, 100 + WEEK);
    assert_eq!(act.payload, b"opaque");
    assert_eq!(vault.pending_act_started_events(&owner, 42, 101)?.len(), 1);
    assert_eq!(vault.pending_act_started_events(&other, 42, 101)?.len(), 1);
    assert!(
        vault
            .pending_act_started_events(&admin, 42, 101)?
            .is_empty()
    );
    assert!(
        vault
            .change_authority_objection(&admin, &act.id, true, 101)
            .is_err()
    );
    assert!(
        vault
            .change_authority_objection(&other, &act.id, true, 100 + WEEK)
            .is_err()
    );
    assert!(
        !vault
            .advance_authority_act(&act.id, 100 + WEEK - 1)?
            .completed
    );
    let held = vault.change_authority_objection(&other, &act.id, true, 101)?;
    assert!(!held.completed);
    assert!(!vault.advance_authority_act(&act.id, 100 + WEEK)?.completed);
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::test_util::embedding_test_config())?;
    assert!(
        !reopened
            .advance_authority_act(&act.id, 100 + WEEK + 1)?
            .completed
    );
    assert!(
        reopened
            .change_authority_objection(&other, &act.id, false, 100 + WEEK + 2)?
            .completed
    );
    assert!(reopened.pending_authority_act(&act.id)?.unwrap().completed);
    Ok(())
}

#[test]
fn no_objection_completes_and_row_changes_behavior_without_code_change() -> Result<()> {
    let (_dir, vault, owner, other, admin) = fixture(SharedVaultPreset::Org);
    let self_erasure =
        vault.start_authority_act_with_setting(&owner, 42, "erase", vec![], None, 99)?;
    assert!(self_erasure.completed);
    assert_eq!(vault.shared_act_policy("erase")?.unwrap().wait_secs, WEEK);
    let old = vault.start_authority_act(&owner, 42, "erase", vec![], 100)?;
    assert!(
        !vault
            .advance_authority_act(&old.id, 100 + WEEK - 1)?
            .completed
    );
    assert!(vault.advance_authority_act(&old.id, 100 + WEEK)?.completed);
    assert!(
        vault
            .set_shared_act_policy(&owner, &[], 42, "erase", None, 101)
            .is_err()
    );
    vault.set_shared_act_policy(
        &owner,
        &[&other],
        42,
        "erase",
        Some(SharedActPolicy {
            wait_secs: 5,
            objector_roles: vec![Role::Admin],
            initiator_roles: vec![Role::Owner],
            policy_editor_roles: vec![Role::Owner],
            required_verb: "admin".into(),
            starter_may_object: true,
            max_act_name_bytes: 128,
            max_payload_bytes: 1_048_576,
            precedence: SharedActPrecedence::HolderMayNarrow,
        }),
        101,
    )?;
    let updated = vault.start_authority_act(&owner, 42, "erase", vec![], 102)?;
    assert_eq!(updated.deadline, 107);
    assert!(
        vault
            .pending_act_started_events(&admin, 42, 102)?
            .iter()
            .any(|event| event.act_id == updated.id)
    );
    assert!(
        vault
            .change_authority_objection(&other, &updated.id, true, 103)
            .is_err()
    );
    assert!(
        !vault
            .change_authority_objection(&admin, &updated.id, true, 103)?
            .completed
    );
    assert!(!vault.advance_authority_act(&updated.id, 107)?.completed);
    assert!(
        vault
            .change_authority_objection(&admin, &updated.id, false, 108)?
            .completed
    );
    let off = SharedActPolicy {
        wait_secs: 0,
        ..vault.shared_act_policy("erase")?.unwrap()
    };
    vault.set_shared_act_policy(&owner, &[&other], 42, "erase", Some(off), 109)?;
    assert!(
        vault
            .start_authority_act(&owner, 42, "erase", vec![], 110)?
            .completed
    );
    assert!(
        vault
            .set_shared_act_policy(&admin, &[&owner, &other], 42, "erase", None, 111)
            .is_err()
    );
    Ok(())
}

#[test]
fn merged_owner_cannot_hold_objection_or_block_policy_edit() -> Result<()> {
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpWrite, IdentityTopologyOp, MergeOp, SurvivorshipPlan,
    };
    let (_dir, vault, owner, other, _admin) = fixture(SharedVaultPreset::Team);
    let act = vault.start_authority_act(&owner, 42, "erase", vec![], 100)?;
    vault.change_authority_objection(&other, &act.id, true, 101)?;
    let survivor = EntityId::now();
    vault.put_entity(
        &survivor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"survivor",
    )?;
    let merge = IdentityTopologyOp::Merge(MergeOp {
        sources: vec![other.actor()],
        survivor,
        evidence: IdentityOpEvidence {
            refs: Vec::new(),
            rationale: "identity merge".into(),
        },
        survivorship_plan: SurvivorshipPlan::ReadThrough,
    });
    vault.apply_identity_topology_op(
        &merge,
        &IdentityOpWrite::auto(crate::claim::ClaimSource::Inferred),
        102,
    )?;
    assert!(
        vault
            .change_authority_objection(&other, &act.id, false, 103)
            .is_err()
    );
    assert!(vault.pending_act_started_events(&other, 42, 103).is_err());
    vault.set_shared_act_policy(&owner, &[], 42, "erase", None, 104)?;
    assert!(vault.advance_authority_act(&act.id, 100 + WEEK)?.completed);
    Ok(())
}

#[test]
fn row_controls_non_owner_starter_own_objection_and_budgets() -> Result<()> {
    let (_dir, vault, owner, other, admin) = fixture(SharedVaultPreset::Team);
    let base = vault.shared_act_policy("erase")?.unwrap();
    assert!(
        vault
            .start_authority_act(&admin, 42, "erase", vec![], 100)
            .is_err()
    );
    let mut row = base;
    row.initiator_roles.push(Role::Admin);
    row.wait_secs = 5;
    row.max_act_name_bytes = 20;
    row.max_payload_bytes = 3;
    row.objector_roles = vec![Role::Admin, Role::Owner];
    vault.set_shared_act_policy(&owner, &[&other], 42, "small_act", Some(row), 100)?;
    assert!(
        vault
            .start_authority_act(&admin, 42, "small_act", vec![1, 2, 3, 4], 101)
            .is_err()
    );
    let act = vault.start_authority_act(&admin, 42, "small_act", vec![1, 2, 3], 101)?;
    assert!(
        vault
            .change_authority_objection(&admin, &act.id, true, 102)?
            .objections
            .contains(&admin.actor().to_hex())
    );
    assert!(!vault.advance_authority_act(&act.id, 106)?.completed);
    let mut wider = vault.shared_act_policy("small_act")?.unwrap();
    wider.wait_secs = 0;
    assert!(
        vault
            .start_authority_act_with_holder_setting(&admin, 42, "small_act", vec![], wider, 108)
            .is_err()
    );
    let mut narrow = vault.shared_act_policy("small_act")?.unwrap();
    narrow.wait_secs = 10;
    narrow.max_payload_bytes = 2;
    narrow.starter_may_object = false;
    let restricted = vault.start_authority_act_with_holder_setting(
        &admin,
        42,
        "small_act",
        vec![1, 2],
        narrow,
        108,
    )?;
    assert_eq!(restricted.deadline, 118);
    assert!(
        vault
            .change_authority_objection(&admin, &restricted.id, true, 109)
            .is_err()
    );
    assert!(
        vault
            .change_authority_objection(&admin, &act.id, false, 107)?
            .completed
    );
    Ok(())
}

#[test]
fn read_only_owner_cannot_start_or_edit_policy() -> Result<()> {
    let (_dir, vault, owner, other, _admin) = fixture(SharedVaultPreset::Team);
    let creation = vault.shared_vault_creation()?.unwrap();
    for grant_ref in &creation.grant_refs {
        let id = EntityId::from_hex(grant_ref)?;
        let raw = vault.get_raw(&id)?.unwrap();
        let mut grant = super::super::decode_federation_grant_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )?;
        if grant.member_ref != owner.actor() {
            continue;
        }
        grant.authority_scope = super::super::scope_codec::read_preset();
        vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                TimeRange { start: 10, end: 10 },
                10,
                &super::super::encode_federation_grant_body(&grant)?,
            )
            .commit()?;
    }
    assert!(
        vault
            .start_authority_act(&owner, 42, "erase", vec![], 100)
            .is_err()
    );
    assert!(
        vault
            .set_shared_act_policy(&owner, &[&other], 42, "erase", None, 101)
            .is_err()
    );
    assert!(
        vault
            .start_authority_act(&other, 42, "erase", vec![], 102)
            .is_ok()
    );
    Ok(())
}

fn grant_of(vault: &Vault, member: EntityId) -> Result<EntityId> {
    for grant_ref in vault.shared_vault_creation()?.unwrap().grant_refs {
        let id = EntityId::from_hex(&grant_ref)?;
        let raw = vault.get_raw(&id)?.unwrap();
        if decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?.member_ref == member {
            return Ok(id);
        }
    }
    Err(invalid())
}

fn genesis(seed: u8) -> crate::authority::AuthorityLogEntry {
    use crate::authority::{
        AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_OWNER,
    };
    use ed25519_dalek::Signer;
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
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
            genesis_nonce: [seed.wrapping_add(10); 32],
            recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100,
    };
    let transcript = crate::authority::authority_transcript(&entry).unwrap();
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

/// Dual-signed federation lifecycle entries under one local root and one peer.
struct PactLog {
    owner: ed25519_dalek::SigningKey,
    peer: ed25519_dalek::SigningKey,
    genesis: crate::authority::AuthorityLogEntry,
    vault_id: crate::authority::AuthorityVaultId,
    peer_vault_id: crate::authority::AuthorityVaultId,
}
impl PactLog {
    fn new(seed: u8) -> Self {
        let genesis = genesis(seed);
        Self {
            owner: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            peer: ed25519_dalek::SigningKey::from_bytes(&[seed + 1; 32]),
            vault_id: crate::authority::genesis_vault_id(&genesis).unwrap(),
            peer_vault_id: crate::authority::genesis_vault_id(&self::genesis(seed + 1)).unwrap(),
            genesis,
        }
    }
    fn root(&self) -> crate::authority::AuthorityEntryHash {
        crate::authority::authority_entry_hash(&self.genesis).unwrap()
    }
    #[allow(clippy::too_many_arguments)]
    fn entry(
        &self,
        seq: u64,
        parent_hashes: Vec<crate::authority::AuthorityEntryHash>,
        kind: crate::authority::FederationLifecycleKind,
        pact_id: [u8; 32],
        grant_ref: EntityId,
        pact_epoch: u64,
        pact_nonce: [u8; 16],
    ) -> crate::authority::AuthorityLogEntry {
        use crate::authority::{
            AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
            AuthoritySignatureSuite, FederationLifecycleAction,
        };
        use crate::federation::{FederationDirectionScope, FederationPactScope, ScopeAxis};
        use ed25519_dalek::Signer;
        let half = FederationDirectionScope {
            worlds: ScopeAxis::All,
            facets: ScopeAxis::All,
            bands: ScopeAxis::All,
        };
        let scope = FederationPactScope {
            lo_to_hi: half.clone(),
            hi_to_lo: half,
        };
        let digest = crate::authority::federation_scope_digest(
            &pact_nonce,
            &crate::federation::encode_federation_pact_scope(&scope).unwrap(),
        );
        let gesture = crate::authority::sign_federation_pact_gesture(
            kind,
            &pact_id,
            &self.vault_id,
            &self.peer_vault_id,
            pact_epoch,
            &digest,
            None,
            &pact_nonce,
            AuthorityKey::Ed25519(self.peer.verifying_key().to_bytes()),
            |transcript| Ok(self.peer.sign(transcript).to_bytes().to_vec()),
        )
        .unwrap();
        let mut entry = AuthorityLogEntry {
            schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(self.vault_id),
            seq,
            parent_hashes,
            op: AuthorityOp::FederationLifecycle(FederationLifecycleAction {
                kind,
                pact_id,
                grant_ref,
                peer_vault_id: self.peer_vault_id,
                pact_epoch,
                pact_scope: Some(scope),
                effective_scope: None,
                scope_digest: Some(digest),
                gesture: Some(gesture),
                successor_vault_id: None,
                pact_nonce,
            }),
            signer: AuthoritySignature {
                suite: AuthoritySignatureSuite::Ed25519,
                public_key: AuthorityKey::Ed25519(self.owner.verifying_key().to_bytes()),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: 9,
        };
        let transcript = crate::authority::authority_transcript(&entry).unwrap();
        entry.signer.signature = self.owner.sign(&transcript).to_bytes().to_vec();
        entry
    }
}

#[test]
fn suspended_or_discarded_pact_grant_is_not_a_holder() -> Result<()> {
    use crate::authority::FederationLifecycleKind::{Connect, Rescope};
    for discarded in [true, false] {
        let (_dir, vault, owner, other, _admin) = fixture(SharedVaultPreset::Team);
        let grant = grant_of(&vault, other.actor())?;
        // The other binding sorts first, so it wins every equal-digest tie.
        let rival = crate::test_util::entity(0x01);
        assert!(rival < grant);
        let act = vault.start_authority_act(&owner, 42, "erase", vec![], 100)?;
        vault.change_authority_objection(&other, &act.id, true, 101)?;

        let log = PactLog::new(0x61);
        let root = log.root();
        let (pact, nonce) = ([0x63; 32], [0x64; 16]);
        let bind = log.entry(1, vec![root], Connect, pact, grant, 1, nonce);
        let rival_bind = log.entry(2, vec![root], Connect, pact, rival, 1, nonce);
        let parents = vec![
            crate::authority::authority_entry_hash(&bind)?,
            crate::authority::authority_entry_hash(&rival_bind)?,
        ];
        let last = if discarded {
            // The heal names the rival: the grant's binding is discarded.
            log.entry(3, parents, Rescope, pact, rival, 2, [0x65; 16])
        } else {
            // An Active pact names the grant, shadowed by the suspended one.
            log.entry(3, vec![root], Connect, [0x66; 32], grant, 1, [0x67; 16])
        };
        for (seq, entry) in [log.genesis.clone(), bind, rival_bind, last]
            .iter()
            .enumerate()
        {
            let at = seq as u64 + 1;
            vault.put_authority_log_entry(entry, TimeRange { start: at, end: at }, at)?;
        }
        let fold = vault.authority_fold()?;
        assert!(matches!(
            federation_grant_activation(&fold, &grant),
            FederationGrantActivation::Inactive(_)
        ));
        assert_eq!(
            fold.pact_for_grant(&grant).is_some(),
            !discarded,
            "the operative-state scan alone would admit this grant"
        );

        // Objection reconcile: the inactive grant's objection no longer holds.
        assert!(vault.advance_authority_act(&act.id, 100 + WEEK)?.completed);
        // Start and events refuse it.
        assert!(
            vault
                .start_authority_act(&other, 42, "erase", vec![], 102)
                .is_err()
        );
        assert!(vault.pending_act_started_events(&other, 42, 102).is_err());
        // Policy edit: it is neither a co-editor nor a required approver.
        assert!(
            vault
                .set_shared_act_policy(&owner, &[&other], 42, "erase", None, 103)
                .is_err()
        );
        vault.set_shared_act_policy(&owner, &[], 42, "erase", None, 104)?;
    }
    Ok(())
}

#[test]
fn conflicted_vault_root_fails_closed() -> Result<()> {
    let (_dir, vault, owner, other, _admin) = fixture(SharedVaultPreset::Team);
    let act = vault.start_authority_act(&owner, 42, "erase", vec![], 100)?;
    vault.put_authority_log_entry(&genesis(0x76), TimeRange { start: 1, end: 1 }, 1)?;
    vault.put_authority_log_entry(&genesis(0x77), TimeRange { start: 2, end: 2 }, 2)?;
    assert!(vault.authority_fold()?.vault_root_is_conflicted());
    assert!(
        vault
            .start_authority_act(&owner, 42, "erase", vec![], 101)
            .is_err()
    );
    assert!(
        vault
            .set_shared_act_policy(&owner, &[&other], 42, "erase", None, 101)
            .is_err()
    );
    assert!(vault.pending_act_started_events(&owner, 42, 101).is_err());
    assert!(
        vault
            .change_authority_objection(&other, &act.id, true, 101)
            .is_err()
    );
    // Silence does not complete an act whose holders cannot be resolved.
    assert!(vault.advance_authority_act(&act.id, 100 + WEEK).is_err());
    assert!(!vault.pending_authority_act(&act.id)?.unwrap().completed);
    Ok(())
}

#[test]
fn deleted_member_objection_releases_and_is_not_an_approver() -> Result<()> {
    let (_dir, vault, owner, other, _admin) = fixture(SharedVaultPreset::Team);
    let act = vault.start_authority_act(&owner, 42, "erase", vec![], 100)?;
    vault.change_authority_objection(&other, &act.id, true, 101)?;
    // Purged from the active store, the member no longer passes the auth door.
    assert!(vault.delete_entity_with_options(
        &other.actor(),
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);
    assert!(
        !vault
            .advance_authority_act(&act.id, 100 + WEEK - 1)?
            .completed
    );
    assert!(
        vault
            .change_authority_objection(&other, &act.id, false, 102)
            .is_err()
    );
    assert!(vault.pending_act_started_events(&other, 42, 102).is_err());
    // The deleted member is not a required approver of a policy edit.
    vault.set_shared_act_policy(&owner, &[], 42, "erase", None, 103)?;
    // Its objection no longer holds the act at the deadline.
    let done = vault.advance_authority_act(&act.id, 100 + WEEK)?;
    assert!(done.completed);
    assert!(done.objections.is_empty());
    Ok(())
}

#[test]
fn act_policy_rows_live_in_manifest_not_vault_meta() -> Result<()> {
    let (_dir, vault, owner, other, _admin) = fixture(SharedVaultPreset::Team);
    let row = SharedActPolicy {
        wait_secs: 60,
        ..vault.shared_act_policy("erase")?.unwrap()
    };
    vault.set_shared_act_policy(&owner, &[&other], 42, "erase", Some(row.clone()), 100)?;
    assert_eq!(
        vault
            .start_authority_act(&owner, 42, "erase", vec![], 101)?
            .deadline,
        161
    );
    let txn = vault.store.env.read_txn()?;
    let id = crate::gate::default_policy_manifest_id()?;
    let raw = vault.store.entities.get(&txn, id.as_bytes())?.unwrap();
    assert!(crate::gate::manifest_authenticity::manifest_is_trusted(
        &vault.store,
        &txn,
        &id,
        &raw[ENTITY_METADATA_HEADER_LEN..]
    )?);
    let rows = crate::gate::resolve_policy_manifest(&vault.store, &txn)?
        .shared_act_policies
        .unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows.get("erase"), Some(&row));
    for entry in vault.store.vault_meta.iter(&txn)? {
        let (key, value) = entry?;
        assert!(serde_json::from_slice::<SharedActPolicy>(&value).is_err());
        assert!(
            !key.starts_with(b"shared-act:")
                || key.starts_with(ACT_PREFIX)
                || key.starts_with(EVENT_PREFIX),
            "only act state lives in vault_meta"
        );
    }
    Ok(())
}

#[test]
fn manifest_without_owner_door_does_not_change_wait() -> Result<()> {
    let (_dir, vault, owner, other, _admin) = fixture(SharedVaultPreset::Team);
    let fast = SharedActPolicy {
        wait_secs: 5,
        ..vault.shared_act_policy("erase")?.unwrap()
    };
    let body = with_act_table(
        &crate::gate::default_policy_manifest().unwrap(),
        &BTreeMap::from([("erase".to_owned(), fast)]),
    )?;
    // A received manifest at a new id, then a replayed overwrite of the vault's own.
    for id in [EntityId::now(), crate::gate::default_policy_manifest_id()?] {
        vault
            .batch()
            .put_replicated(
                &id,
                crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
                TimeRange { start: 50, end: 50 },
                50,
                &body,
            )
            .commit()?;
        let act = vault.start_authority_act(&owner, 42, "erase", vec![], 100)?;
        assert_eq!(act.deadline, 100 + WEEK);
    }
    // No edit is built on the received bytes.
    assert!(
        vault
            .set_shared_act_policy(&owner, &[&other], 42, "erase", None, 101)
            .is_err()
    );
    Ok(())
}

#[test]
fn malformed_act_policy_table_refuses_start() -> Result<()> {
    use rmpv::Value;
    let (_dir, vault, owner, other, _admin) = fixture(SharedVaultPreset::Team);
    let id = crate::gate::default_policy_manifest_id()?;
    let row = vault.shared_act_policy("erase")?.unwrap();
    let rows = |row: Value| Value::Map(vec![("erase".into(), row)]);
    let tables = [
        // A row missing its fields.
        rows(Value::Map(vec![("wait_secs".into(), 5.into())])),
        // A wait with nobody who may object.
        rows(row_value(&SharedActPolicy {
            objector_roles: Vec::new(),
            ..row
        })?),
        // A positional row.
        rows(Value::Array(vec![5.into()])),
        // A table that is not a map.
        Value::Array(Vec::new()),
    ];
    for table in tables {
        let mut cursor = std::io::Cursor::new(crate::gate::default_policy_manifest().unwrap());
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).unwrap() else {
            unreachable!()
        };
        entries.push((crate::gate::POLICY_SHARED_ACT_POLICIES_KEY.into(), table));
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &Value::Map(entries)).unwrap();
        // The owner door refuses it.
        assert!(
            vault
                .install_owner_policy_manifest(&owner, id, body.clone(), 50)
                .is_err()
        );
        // Stored locally anyway, it governs nothing: every start is refused.
        let mut txn = vault.store.env.write_txn()?;
        crate::batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut txn,
            vec![crate::batch::BatchOp::Put {
                id,
                entity_type: crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
                occurred: TimeRange { start: 50, end: 50 },
                learned_at: 50,
                data: body,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        txn.commit()?;
        for act in ["erase", "export"] {
            assert!(
                vault
                    .start_authority_act(&owner, 42, act, vec![], 100)
                    .is_err()
            );
        }
        assert!(vault.shared_act_policy("erase").is_err());
        assert!(
            vault
                .set_shared_act_policy(&owner, &[&other], 42, "erase", None, 101)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn absent_row_uses_shipped_default_and_zero_wait_runs_at_once() -> Result<()> {
    let (_dir, vault, owner, other, _admin) = fixture(SharedVaultPreset::Family);
    let row = vault.shared_act_policy("erase")?.unwrap();
    // Deleting the row does not turn the wait off: the shipped row applies.
    vault.set_shared_act_policy(&owner, &[&other], 42, "erase", None, 100)?;
    assert_eq!(vault.shared_act_policy("erase")?, None);
    let act = vault.start_authority_act(&owner, 42, "erase", vec![], 101)?;
    assert_eq!(act.deadline, 101 + WEEK);
    assert!(!act.completed);
    // An act with no row anywhere takes the shipped default row: no wait.
    assert!(
        vault
            .start_authority_act(&owner, 42, "export", vec![], 101)?
            .completed
    );
    // A zero wait written into the row runs the act at once.
    let off = SharedActPolicy {
        wait_secs: 0,
        ..row
    };
    vault.set_shared_act_policy(&owner, &[&other], 42, "erase", Some(off), 102)?;
    let now = vault.start_authority_act(&owner, 42, "erase", vec![], 103)?;
    assert!(now.completed);
    assert_eq!(now.deadline, 103);
    Ok(())
}

/// DEC-0006 invariant 7 (REV-9 item 4): an owner's live bypass grant answers
/// that owner's own ask inside its scope, and never skips another Owner's
/// objection window: the act still waits, and the other Owner's objection
/// still holds it.
#[test]
fn a_bypass_grant_never_skips_another_owners_objection_window() -> Result<()> {
    use crate::consent::{
        ActionClass, ActionEnvelope, ActorBound, BypassScope, CatastropheClass, ComposedEffect,
        ConsentDecision, EffectFacts, EffectPlace, GrantBound,
    };
    let (_dir, vault, owner, other, _admin) = fixture(SharedVaultPreset::Team);
    let thread = EntityId::now();
    vault.put_entity(
        &thread,
        crate::registry::ENTITY_TYPE_CONVERSATION,
        TimeRange { start: 1, end: 1 },
        1,
        b"thread",
    )?;
    let bound = GrantBound::action(
        ActorBound::new(owner.actor().to_hex())?,
        ActionClass::new(CatastropheClass::VaultWideDestruction.as_str())?,
        ActionEnvelope::new(["act:delete_vault".to_owned()])?,
    )?;
    let warning = vault.bypass_grant_warning(&owner, bound.clone(), BypassScope::Thread(thread))?;
    vault.create_bypass_grant(&owner, &warning)?;
    let effect = ComposedEffect::new(
        EffectFacts::new("delete_vault")?.with_catastrophe(CatastropheClass::VaultWideDestruction),
    )
    .with_action_requirement(bound)?
    .in_place(EffectPlace {
        project: None,
        thread: Some(thread),
    });
    let evaluation = vault.evaluate_consent_for(&effect, None)?;
    assert_eq!(evaluation.decision, ConsentDecision::Auto);
    assert!(evaluation.bypassed_by.is_some());

    let act = vault.start_authority_act(&owner, 42, "delete_vault", Vec::new(), 100)?;
    assert_eq!(act.deadline, 100 + WEEK, "the bypass opens no shortcut");
    assert!(!act.completed);
    vault.change_authority_objection(&other, &act.id, true, 101)?;
    assert!(
        !vault.advance_authority_act(&act.id, 100 + WEEK)?.completed,
        "the other Owner's objection still holds the act"
    );
    Ok(())
}
