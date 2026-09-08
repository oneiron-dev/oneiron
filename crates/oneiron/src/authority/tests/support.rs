//! Shared fixtures and fold helpers for the authority tests.

use super::*;

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Inverse of [`hex`], for decoding pinned golden vectors back to bytes.
pub(super) fn hex_bytes(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex literal must be even");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub(super) fn ed_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(super) fn authority_key_from_ed(key: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(key.verifying_key().to_bytes())
}

pub(super) fn p256_key(seed: u8) -> P256SigningKey {
    let mut rng = StdRng::from_seed([seed; 32]);
    P256SigningKey::random(&mut rng)
}

pub(super) fn authority_key_from_p256(key: &P256SigningKey) -> AuthorityKey {
    let point = key.verifying_key().to_encoded_point(true);
    AuthorityKey::P256(point.as_bytes().to_vec())
}

pub(super) fn attestation(kind: &str) -> AuthorityAttestation {
    AuthorityAttestation {
        kind: kind.to_owned(),
        evidence: vec![1, 2, 3],
    }
}

pub(super) fn device(key: AuthorityKey, roles: u16, tier: AuthorityTier) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: attestation("SoftwareArgon2id"),
        tier,
        roles,
    }
}

pub(super) fn unsigned_entry(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer_key: AuthorityKey,
    ts: u64,
) -> AuthorityLogEntry {
    AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes,
        op,
        signer: AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts,
    }
}

pub(super) fn sign_ed(mut entry: AuthorityLogEntry, key: &SigningKey) -> AuthorityLogEntry {
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

pub(super) fn sign_ed_legacy_genesis(
    mut entry: AuthorityLogEntry,
    key: &SigningKey,
) -> AuthorityLogEntry {
    let transcript = authority_transcript_with_genesis_delay(&entry, false).unwrap();
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

pub(super) fn sign_p256(mut entry: AuthorityLogEntry, key: &P256SigningKey) -> AuthorityLogEntry {
    let transcript = authority_transcript(&entry).unwrap();
    let mut signature: P256Signature = key.sign(&transcript);
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
    }
    entry.signer.signature = signature.to_bytes().to_vec();
    entry
}

pub(super) fn cosign_ed(
    mut entry: AuthorityLogEntry,
    signer: &SigningKey,
    cosigner: &SigningKey,
) -> AuthorityLogEntry {
    let cosigner_key = authority_key_from_ed(cosigner);
    entry.cosigns.push(AuthoritySignature {
        suite: cosigner_key.suite(),
        public_key: cosigner_key,
        signature: vec![0; 64],
    });
    entry.cosigns.sort_by(|left, right| {
        left.public_key
            .cmp(&right.public_key)
            .then_with(|| left.signature.cmp(&right.signature))
    });
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    let cosigner_key = authority_key_from_ed(cosigner);
    for cosign in &mut entry.cosigns {
        if cosign.public_key == cosigner_key {
            cosign.signature = cosigner.sign(&transcript).to_bytes().to_vec();
        }
    }
    entry
}

pub(super) fn cosign_ed_two(
    mut entry: AuthorityLogEntry,
    signer: &SigningKey,
    first_cosigner: &SigningKey,
    second_cosigner: &SigningKey,
) -> AuthorityLogEntry {
    for cosigner in [first_cosigner, second_cosigner] {
        let cosigner_key = authority_key_from_ed(cosigner);
        entry.cosigns.push(AuthoritySignature {
            suite: cosigner_key.suite(),
            public_key: cosigner_key,
            signature: vec![0; 64],
        });
    }
    entry.cosigns.sort_by(|left, right| {
        left.public_key
            .cmp(&right.public_key)
            .then_with(|| left.signature.cmp(&right.signature))
    });
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    for cosigner in [first_cosigner, second_cosigner] {
        let cosigner_key = authority_key_from_ed(cosigner);
        for cosign in &mut entry.cosigns {
            if cosign.public_key == cosigner_key {
                cosign.signature = cosigner.sign(&transcript).to_bytes().to_vec();
            }
        }
    }
    entry
}

pub(super) fn genesis_entry(seed: u8, pending_widen_delay_secs: u64, ts: u64) -> AuthorityLogEntry {
    let signing = ed_key(seed);
    let key = authority_key_from_ed(&signing);
    let op = AuthorityOp::Genesis {
        device: device(
            key.clone(),
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Software,
        ),
        genesis_nonce: [seed.wrapping_add(10); 32],
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs,
    };
    sign_ed(unsigned_entry(None, 0, Vec::new(), op, key, ts), &signing)
}

pub(super) struct EnrollSpec {
    pub(super) seed: u8,
    pub(super) roles: u16,
    pub(super) tier: AuthorityTier,
    pub(super) seq: u64,
    pub(super) ts: u64,
}

pub(super) fn enroll_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    new_key_seed: u8,
    seq: u64,
    ts: u64,
) -> AuthorityLogEntry {
    enroll_device_entry(
        vault_id,
        parent,
        signer,
        EnrollSpec {
            seed: new_key_seed,
            roles: ROLE_AGENT | ROLE_CLOUD,
            tier: AuthorityTier::Software,
            seq,
            ts,
        },
    )
}

pub(super) fn enroll_device_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    spec: EnrollSpec,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    let new = ed_key(spec.seed);
    let op = AuthorityOp::EnrollDevice {
        device: device(authority_key_from_ed(&new), spec.roles, spec.tier),
    };
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            spec.seq,
            vec![authority_entry_hash(parent).unwrap()],
            op,
            signer_key,
            spec.ts,
        ),
        signer,
    )
}

pub(super) fn revoke_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    revoked: AuthorityKey,
    seq: u64,
) -> AuthorityLogEntry {
    revoke_entry_at(vault_id, parent, signer, revoked, seq, 777)
}

pub(super) fn revoke_entry_at(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    revoked: AuthorityKey,
    seq: u64,
    ts: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::RevokeDevice {
                revoked_key: revoked,
            },
            signer_key,
            ts,
        ),
        signer,
    )
}

pub(super) fn set_tier_floor_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    tier_floor: AuthorityTier,
) -> AuthorityLogEntry {
    set_tier_floor_entry_at(vault_id, parent, signer, seq, tier_floor, 888)
}

pub(super) fn set_tier_floor_entry_at(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    tier_floor: AuthorityTier,
    ts: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::SetTierFloor { tier_floor },
            signer_key,
            ts,
        ),
        signer,
    )
}

pub(super) fn set_ceiling_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    ts: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::SetCeiling {
                authority_key: signer_key.clone(),
                actor_class: "agent".to_string(),
                ceiling: 1,
            },
            signer_key,
            ts,
        ),
        signer,
    )
}

pub(super) fn rotate_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    old_key: AuthorityKey,
    new_seed: u8,
    seq: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    let new = ed_key(new_seed);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::RotateKey {
                old_key,
                new_device: device(
                    authority_key_from_ed(&new),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            signer_key,
            889,
        ),
        signer,
    )
}

pub(super) fn recovery_reboot_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    new_seed: u8,
    seq: u64,
) -> AuthorityLogEntry {
    recovery_reboot_entry_at(vault_id, parent, signer, new_seed, seq, 890)
}

pub(super) fn recovery_reboot_entry_at(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    new_seed: u8,
    seq: u64,
    ts: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    let new = ed_key(new_seed);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::RecoveryReboot {
                new_genesis_nonce: [new_seed; 32],
                new_device: device(
                    authority_key_from_ed(&new),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
                tier_floor: AuthorityTier::Software,
            },
            signer_key,
            ts,
        ),
        signer,
    )
}

pub(super) fn sibling_fold_order_key(
    parent_hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
) -> (bool, AuthorityEntryHash) {
    let hash = authority_entry_hash(entry).unwrap();
    (hash < parent_hash, hash)
}

pub(super) fn veto_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    pending_widen_hash: AuthorityEntryHash,
    seq: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::VetoPendingWiden { pending_widen_hash },
            signer_key,
            999,
        ),
        signer,
    )
}

/// Owned backing store for a default LOCAL [`FoldContext`]: no forks, no
/// equivocations, no seen-time delay, no admitted peers.
///
/// Tests that need one axis populated mutate that field and spread the rest
/// with `..storage.context()`, so a new `FoldContext` field lands HERE once
/// instead of in every fold-internal test.
#[derive(Default)]
pub(super) struct LocalFoldContext {
    pub(super) first_seen_at_secs: BTreeMap<AuthorityEntryHash, u64>,
    pub(super) vetoed_widens: BTreeSet<AuthorityEntryHash>,
    pub(super) authority_forks: BTreeMap<(AuthorityKey, u64), AuthorityFork>,
    pub(super) authority_fork_vault_ids: BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityVaultId>>,
    pub(super) equivocation_groups: BTreeMap<(AuthorityKey, u64), BTreeSet<AuthorityEntryHash>>,
    pub(super) unresolved_equivocation_groups: BTreeSet<(AuthorityKey, u64)>,
    pub(super) peer_consent_roots: BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
}

impl LocalFoldContext {
    pub(super) fn context(&self) -> FoldContext<'_> {
        FoldContext {
            first_seen_at_secs: &self.first_seen_at_secs,
            now_secs: None,
            enforce_seen_time_delay: false,
            vetoed_widens: &self.vetoed_widens,
            authority_forks: &self.authority_forks,
            authority_fork_vault_ids: &self.authority_fork_vault_ids,
            equivocation_groups: &self.equivocation_groups,
            unresolved_equivocation_groups: &self.unresolved_equivocation_groups,
            entry_ancestors: None,
            chain_validated_fork_candidates: None,
            peer_consent_roots: &self.peer_consent_roots,
            consent_arm: folded_device_can_authority_consent,
        }
    }
}

pub(super) fn fold_entry_state_for_test(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> EntryFold {
    let storage = LocalFoldContext::default();
    fold_entry_state(entry, hash, states, storage.context())
}

pub(super) fn single_owner_state(
    seed: u8,
) -> (SigningKey, AuthorityKey, AuthorityEntryHash, FoldState) {
    let owner = ed_key(seed);
    let owner_key = authority_key_from_ed(&owner);
    let parent = [seed.wrapping_add(90); 32];
    let vault_id = [seed.wrapping_add(91); 32];
    let state = FoldState {
        vault_id,
        roster: BTreeMap::from([(
            owner_key.clone(),
            FoldedDevice {
                key: owner_key.clone(),
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
                revoked: false,
            },
        )]),
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
        pending_widens: BTreeMap::new(),
        vetoed_widens: BTreeSet::new(),
        delayed_rotation_veto_revocations: BTreeMap::new(),
        fork_resolution_revocations: BTreeSet::new(),
        authority_forks: BTreeMap::new(),
        federation_pacts: BTreeMap::new(),
        critical_write_confirms: BTreeMap::new(),
        consumed_critical_write_confirm_nonces: BTreeSet::new(),
        critical_write_confirm_nonce_provenance: BTreeMap::new(),
        conflicted_critical_write_confirms: BTreeSet::new(),
        federation_grant_bindings: BTreeMap::new(),
        actor_bindings: BTreeMap::new(),
        actor_binding_revocations: BTreeMap::new(),
        seqs: BTreeMap::from([(owner_key.clone(), 0)]),
    };
    (owner, owner_key, parent, state)
}

pub(super) fn scope_entity(byte: u8) -> EntityId {
    crate::test_util::entity(byte)
}

pub(super) fn symmetric_scope(
    facets: crate::federation::FederationScopeFacets,
    bands: crate::federation::FederationScopeBands,
) -> FederationPactScope {
    let half = FederationDirectionScope {
        worlds: crate::federation::FederationScopeWorlds::All,
        facets,
        bands,
    };
    FederationPactScope {
        lo_to_hi: half.clone(),
        hi_to_lo: half,
    }
}

pub(super) fn default_pact_scope() -> FederationPactScope {
    FederationPactScope {
        lo_to_hi: FederationDirectionScope {
            worlds: crate::federation::FederationScopeWorlds::All,
            facets: crate::federation::FederationScopeFacets::All,
            bands: crate::federation::FederationScopeBands::All,
        },
        hi_to_lo: FederationDirectionScope {
            worlds: crate::federation::FederationScopeWorlds::Base,
            facets: crate::federation::FederationScopeFacets::All,
            bands: crate::federation::FederationScopeBands::All,
        },
    }
}

pub(super) fn scope_digest_for(scope: &FederationPactScope, nonce: &[u8; 16]) -> [u8; 32] {
    federation_scope_digest(nonce, &encode_federation_pact_scope(scope).unwrap())
}

pub(super) struct PactFixture {
    pub(super) owner: SigningKey,
    pub(super) peer: SigningKey,
    pub(super) genesis: AuthorityLogEntry,
    pub(super) peer_genesis: AuthorityLogEntry,
    pub(super) vault_id: AuthorityVaultId,
    pub(super) peer_vault_id: AuthorityVaultId,
    pub(super) pact_id: [u8; 32],
    pub(super) grant_ref: EntityId,
    pub(super) pact_nonce: [u8; 16],
    pub(super) scope: FederationPactScope,
    pub(super) scope_digest: [u8; 32],
}

pub(super) fn pact_fixture_with_scope(seed: u8, scope: FederationPactScope) -> PactFixture {
    let owner = ed_key(seed);
    let genesis = genesis_entry(seed, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let peer = ed_key(seed.wrapping_add(1));
    let peer_genesis = genesis_entry(seed.wrapping_add(1), 86_400, 1);
    let peer_vault_id = genesis_vault_id(&peer_genesis).unwrap();
    let pact_nonce = [seed.wrapping_add(2); 16];
    PactFixture {
        scope_digest: scope_digest_for(&scope, &pact_nonce),
        owner,
        peer,
        genesis,
        peer_genesis,
        vault_id,
        peer_vault_id,
        pact_id: [seed.wrapping_add(3); 32],
        grant_ref: scope_entity(seed.wrapping_add(4)),
        pact_nonce,
        scope,
    }
}

pub(super) fn pact_fixture(seed: u8) -> PactFixture {
    pact_fixture_with_scope(seed, default_pact_scope())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn ed_pact_gesture(
    kind: FederationLifecycleKind,
    pact_id: &[u8; 32],
    vault_a: &AuthorityVaultId,
    vault_b: &AuthorityVaultId,
    pact_epoch: u64,
    scope_digest: &[u8; 32],
    successor: Option<&AuthorityVaultId>,
    pact_nonce: &[u8; 16],
    peer: &SigningKey,
) -> FederationPactGesture {
    sign_federation_pact_gesture(
        kind,
        pact_id,
        vault_a,
        vault_b,
        pact_epoch,
        scope_digest,
        successor,
        pact_nonce,
        authority_key_from_ed(peer),
        |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
    )
    .unwrap()
}

pub(super) fn connect_action_with(
    fixture: &PactFixture,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    scope: &FederationPactScope,
    nonce: [u8; 16],
) -> FederationLifecycleAction {
    let digest = scope_digest_for(scope, &nonce);
    FederationLifecycleAction {
        kind: FederationLifecycleKind::Connect,
        pact_id,
        grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        pact_epoch: 1,
        pact_scope: Some(scope.clone()),
        effective_scope: None,
        scope_digest: Some(digest),
        gesture: Some(ed_pact_gesture(
            FederationLifecycleKind::Connect,
            &pact_id,
            &fixture.vault_id,
            &fixture.peer_vault_id,
            1,
            &digest,
            None,
            &nonce,
            &fixture.peer,
        )),
        successor_vault_id: None,
        pact_nonce: nonce,
    }
}

pub(super) fn connect_action(fixture: &PactFixture) -> FederationLifecycleAction {
    connect_action_with(
        fixture,
        fixture.pact_id,
        fixture.grant_ref,
        &fixture.scope,
        fixture.pact_nonce,
    )
}

pub(super) fn narrow_action_with(
    fixture: &PactFixture,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    pact_epoch: u64,
    effective: FederationDirectionScope,
) -> FederationLifecycleAction {
    FederationLifecycleAction {
        kind: FederationLifecycleKind::Rescope,
        pact_id,
        grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        pact_epoch,
        pact_scope: None,
        effective_scope: Some(effective),
        scope_digest: None,
        gesture: None,
        successor_vault_id: None,
        pact_nonce: fixture.pact_nonce,
    }
}

pub(super) fn repact_action_with(
    fixture: &PactFixture,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    pact_epoch: u64,
    scope: &FederationPactScope,
    nonce: [u8; 16],
) -> FederationLifecycleAction {
    let digest = scope_digest_for(scope, &nonce);
    FederationLifecycleAction {
        kind: FederationLifecycleKind::Rescope,
        pact_id,
        grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        pact_epoch,
        pact_scope: Some(scope.clone()),
        effective_scope: None,
        scope_digest: Some(digest),
        gesture: Some(ed_pact_gesture(
            FederationLifecycleKind::Rescope,
            &pact_id,
            &fixture.vault_id,
            &fixture.peer_vault_id,
            pact_epoch,
            &digest,
            None,
            &nonce,
            &fixture.peer,
        )),
        successor_vault_id: None,
        pact_nonce: nonce,
    }
}

pub(super) fn unilateral_action_with(
    fixture: &PactFixture,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    kind: FederationLifecycleKind,
    pact_epoch: u64,
) -> FederationLifecycleAction {
    FederationLifecycleAction {
        kind,
        pact_id,
        grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        pact_epoch,
        pact_scope: None,
        effective_scope: None,
        scope_digest: None,
        gesture: None,
        successor_vault_id: None,
        pact_nonce: fixture.pact_nonce,
    }
}

pub(super) fn promote_action_with(
    fixture: &PactFixture,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    pact_epoch: u64,
    stored_digest: [u8; 32],
    successor: AuthorityVaultId,
) -> FederationLifecycleAction {
    FederationLifecycleAction {
        kind: FederationLifecycleKind::Promote,
        pact_id,
        grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        pact_epoch,
        pact_scope: None,
        effective_scope: None,
        scope_digest: Some(stored_digest),
        gesture: Some(ed_pact_gesture(
            FederationLifecycleKind::Promote,
            &pact_id,
            &fixture.vault_id,
            &fixture.peer_vault_id,
            pact_epoch,
            &stored_digest,
            Some(&successor),
            &fixture.pact_nonce,
            &fixture.peer,
        )),
        successor_vault_id: Some(successor),
        pact_nonce: fixture.pact_nonce,
    }
}

pub(super) fn lifecycle_entry(
    fixture: &PactFixture,
    parents: Vec<AuthorityEntryHash>,
    seq: u64,
    action: FederationLifecycleAction,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(fixture.vault_id),
            seq,
            parents,
            AuthorityOp::FederationLifecycle(action),
            authority_key_from_ed(&fixture.owner),
            100 + seq,
        ),
        &fixture.owner,
    )
}

pub(super) fn lifecycle_rejection(
    fold: &AuthorityFold,
    hash: AuthorityEntryHash,
) -> Option<FederationLifecycleRejection> {
    fold.issues.iter().find_map(|issue| match issue {
        AuthorityFoldIssue::FederationLifecycleRejected { entry, reason } if *entry == hash => {
            Some(*reason)
        }
        _ => None,
    })
}

pub(super) fn pact_state_with_status(
    fixture: &PactFixture,
    status: FederationPactStatus,
) -> FederationPactState {
    FederationPactState {
        status,
        grant_ref: fixture.grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        peer_owner_key: authority_key_from_ed(&fixture.peer),
        pact_epoch: 1,
        scope_digest: fixture.scope_digest,
        pact_scope: fixture.scope.clone(),
        effective_scope: local_outbound_scope(
            &fixture.vault_id,
            &fixture.peer_vault_id,
            &fixture.scope,
        ),
        successor_vault_id: None,
        terminal_epoch: status.is_terminal().then_some(1),
    }
}

pub(super) fn fold_state_with_pact(
    fixture: &PactFixture,
    status: Option<FederationPactStatus>,
) -> FoldState {
    let owner_key = authority_key_from_ed(&fixture.owner);
    let mut state = FoldState {
        vault_id: fixture.vault_id,
        roster: BTreeMap::from([(
            owner_key.clone(),
            FoldedDevice {
                key: owner_key.clone(),
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
                revoked: false,
            },
        )]),
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
        pending_widens: BTreeMap::new(),
        vetoed_widens: BTreeSet::new(),
        delayed_rotation_veto_revocations: BTreeMap::new(),
        fork_resolution_revocations: BTreeSet::new(),
        authority_forks: BTreeMap::new(),
        federation_pacts: BTreeMap::new(),
        critical_write_confirms: BTreeMap::new(),
        consumed_critical_write_confirm_nonces: BTreeSet::new(),
        critical_write_confirm_nonce_provenance: BTreeMap::new(),
        conflicted_critical_write_confirms: BTreeSet::new(),
        federation_grant_bindings: BTreeMap::new(),
        actor_bindings: BTreeMap::new(),
        actor_binding_revocations: BTreeMap::new(),
        seqs: BTreeMap::from([(owner_key, 0)]),
    };
    if let Some(status) = status {
        state
            .federation_pacts
            .insert(fixture.pact_id, pact_state_with_status(fixture, status));
    }
    state
}

pub(super) fn totality_ops(
    fixture: &PactFixture,
) -> Vec<(&'static str, FederationLifecycleAction)> {
    let narrowed = FederationDirectionScope {
        worlds: crate::federation::FederationScopeWorlds::Base,
        facets: crate::federation::FederationScopeFacets::All,
        bands: crate::federation::FederationScopeBands::All,
    };
    let repact_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    vec![
        ("connect", connect_action(fixture)),
        (
            "narrow",
            narrow_action_with(fixture, fixture.pact_id, fixture.grant_ref, 1, narrowed),
        ),
        (
            "repact",
            repact_action_with(
                fixture,
                fixture.pact_id,
                fixture.grant_ref,
                2,
                &repact_scope,
                [0x7A; 16],
            ),
        ),
        (
            "disconnect",
            unilateral_action_with(
                fixture,
                fixture.pact_id,
                fixture.grant_ref,
                FederationLifecycleKind::Disconnect,
                1,
            ),
        ),
        (
            "promote",
            promote_action_with(
                fixture,
                fixture.pact_id,
                fixture.grant_ref,
                2,
                fixture.scope_digest,
                [0xCE; 32],
            ),
        ),
        (
            "dissolve",
            unilateral_action_with(
                fixture,
                fixture.pact_id,
                fixture.grant_ref,
                FederationLifecycleKind::Dissolve,
                1,
            ),
        ),
    ]
}

pub(super) fn expected_transition(
    status: Option<FederationPactStatus>,
    op: &str,
) -> std::result::Result<FederationPactStatus, FederationLifecycleRejection> {
    use FederationLifecycleRejection as R;
    use FederationPactStatus as S;
    match (status, op) {
        (None, "connect") => Ok(S::Active),
        (None, _) => Err(R::UnknownPact),
        (Some(current), _) if current.is_terminal() => Err(R::TerminalPact),
        (Some(_), "connect") => Err(R::DuplicateConnect),
        (Some(S::Suspended), "narrow") | (Some(S::Suspended), "promote") => Err(R::SuspendedPact),
        (Some(_), "narrow") | (Some(_), "repact") => Ok(S::Active),
        (Some(_), "disconnect") => Ok(S::Disconnected),
        (Some(_), "promote") => Ok(S::Promoted),
        (Some(_), "dissolve") => Ok(S::Dissolved),
        (status, op) => panic!("uncovered transition pair ({status:?}, {op})"),
    }
}

/// A rooted two-key vault: `owner` carries OWNER|ADMIN, `agent` is an enrolled
/// ROLE_AGENT software key. Two active roster keys means every non-genesis op
/// needs a peer cosign, which is exactly the shape the bind ops ship into.
pub(super) struct BindFixture {
    pub(super) owner: SigningKey,
    pub(super) agent: SigningKey,
    pub(super) owner_key: AuthorityKey,
    pub(super) agent_key: AuthorityKey,
    pub(super) vault_id: AuthorityVaultId,
    pub(super) genesis: AuthorityLogEntry,
    pub(super) enroll: AuthorityLogEntry,
    pub(super) actor: EntityId,
}

pub(super) fn bind_fixture(seed: u8) -> BindFixture {
    let genesis = genesis_entry(seed, DEFAULT_PENDING_WIDEN_DELAY_SECS, 100);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let owner = ed_key(seed);
    let agent = ed_key(seed.wrapping_add(1));
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: seed.wrapping_add(1),
            roles: ROLE_AGENT,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 101,
        },
    );
    BindFixture {
        owner_key: authority_key_from_ed(&owner),
        agent_key: authority_key_from_ed(&agent),
        owner,
        agent,
        vault_id,
        genesis,
        enroll,
        actor: scope_entity(seed),
    }
}

/// Signs an owner op onto `parents` with the agent as peer cosigner — the
/// two-key roster makes a cosign mandatory for every non-genesis op.
pub(super) fn cosigned_entry(
    fixture: &BindFixture,
    parents: Vec<AuthorityEntryHash>,
    seq: u64,
    op: AuthorityOp,
    ts: u64,
) -> AuthorityLogEntry {
    let entry = unsigned_entry(
        Some(fixture.vault_id),
        seq,
        parents,
        op,
        fixture.owner_key.clone(),
        ts,
    );
    cosign_ed(entry, &fixture.owner, &fixture.agent)
}

pub(super) fn bind_op(key: &AuthorityKey, actor: EntityId, class: &str, epoch: u64) -> AuthorityOp {
    AuthorityOp::BindActor {
        authority_key: key.clone(),
        actor_ref: actor,
        actor_class: class.to_owned(),
        epoch,
    }
}

pub(super) fn rebind_op(
    key: &AuthorityKey,
    actor: EntityId,
    class: &str,
    epoch: u64,
) -> AuthorityOp {
    AuthorityOp::RebindActor {
        authority_key: key.clone(),
        actor_ref: actor,
        actor_class: class.to_owned(),
        epoch,
    }
}

pub(super) fn revoke_actor_op(key: &AuthorityKey, epoch: u64) -> AuthorityOp {
    AuthorityOp::RevokeActor {
        authority_key: key.clone(),
        epoch,
    }
}

/// The rejection reason recorded for `entry`, if the fold refused it.
pub(super) fn binding_rejection(
    fold: &AuthorityFold,
    entry: &AuthorityLogEntry,
) -> Option<ActorBindingRejection> {
    let hash = authority_entry_hash(entry).unwrap();
    fold.issues.iter().find_map(|issue| match issue {
        AuthorityFoldIssue::ActorBindingRejected {
            entry: rejected,
            reason,
        } if *rejected == hash => Some(*reason),
        _ => None,
    })
}

/// Folded status for `key`, or `None` when no binding folded at all.
pub(super) fn folded_status(
    fold: &AuthorityFold,
    key: &AuthorityKey,
) -> Option<ActorBindingStatus> {
    fold.actor_bindings.get(key).map(|binding| binding.status)
}

pub(super) fn sync_state_snapshot(vault: &crate::Vault) -> Vec<(Vec<u8>, Vec<u8>)> {
    let rtxn = vault.store.env.read_txn().unwrap();
    let rows = vault
        .store
        .sync_state
        .iter(&rtxn)
        .unwrap()
        .map(|row| {
            let (key, value) = row.unwrap();
            (key.as_bytes().to_vec(), value.to_vec())
        })
        .collect();
    drop(rtxn);
    rows
}
