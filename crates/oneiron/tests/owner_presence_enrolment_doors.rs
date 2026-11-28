//! Every owner key enrolment door asks for the person first (row
//! OWNER-CONFIRM-SHEET, PR 4b-2): a declined confirm refuses each door and
//! writes nothing, an agent and an undecodable input never raise the prompt,
//! the device door asks once for one enrolment, and each prompt shows its
//! door's reason line. Another vault's owner proof raises no prompt there, at
//! the root recovery, at a recovery hold's answer or at a box Cancel.
#![cfg(oneiron_test_support)]

use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityAttestation,
    AuthorityEntryHash, AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, AuthorityTier, DeviceAuthority, HostSlipIssuer, MachineRole, OwnerActKind,
    OwnerKeyEnrollment, OwnerPasskeyEnrollment, ROLE_AGENT, ROLE_OWNER, RecoveryHoldAnswerKind,
    RootMaterial, RootSuccessor, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, encode_authority_log_entry_body, webauthn_assertion_envelope,
    webauthn_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{DevicePinRefusal, GateError, OwnerPresenceRefusal, RecordError, SecretError};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::recovery::{
    KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::world_keys::{DevicePin, RecoveryRootSeed};
use oneiron::{EntityId, Error, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::MAX_PARENTS;
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, PRESENCE_WINDOW_SECS, PresenceClock, PresenceError,
    PresenceGate, PresenceInstant, PresenceWindow, ScriptedPresence,
};
use oneiron_store::ports::manual_clock::ManualClock;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest as _, Sha256};

/// The reason lines the doors show, as the engine's constants hold them:
/// the tests assert them literally, since those constants are crate-private.
const ENROL_OWNER_SIGNING_KEY_REASON: &str = "add a device that can approve changes";
const ENROL_OWNER_PASSKEY_REASON: &str = "add a passkey that can approve changes";
const CONFIRM_OWNER_PASSKEY_REASON: &str = "confirm a passkey that another passkey added";
const CONFIRM_OWNER_SIGNING_KEY_REASON: &str = "confirm a device that a passkey added";
const ENROL_THIS_DEVICE_REASON: &str = "let this device approve changes";

/// The owner-only refusal, as the engine's constant holds it.
const OWNER_ONLY: &str = "an owner signing key is the owner's to enrol; no Grant action names it";
/// The managed host's refusal of a serving install's own key, as the engine holds it.
const MANAGED_HOST_HOLDS_NO_OWNER_KEY: &str =
    "a managed host holds no owner key: enrol one on your own device";

/// The owner's device key and a host-held key, by seed byte.
const OWNER_DEVICE_SEED: u8 = 0x71;
const HOST_HELD_SEED: u8 = 0x6B;
/// The three passkeys, by seed byte.
const FIRST_PASSKEY_SEED: u8 = 0x5A;
const SECOND_PASSKEY_SEED: u8 = 0x4B;
const THIRD_PASSKEY_SEED: u8 = 0x5B;
/// The lost device key and the recovery successor, by seed byte.
const LOST_KEY_SEED: u8 = 21;
const NEW_KEY_SEED: u8 = 41;
/// The seeds of the two handoffs' successors in the rootless fixture.
const FIRST_HANDOFF_SEED: u8 = 33;
const SECOND_HANDOFF_SEED: u8 = 34;

/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
/// The origin the passkeys enrol at.
const RP_ID: &str = "oneiron.example";
/// The passkeys' credential ids (`rawId`).
const CREDENTIAL_FIRST: &[u8] = b"passkey-credential-0001";
const CREDENTIAL_SECOND: &[u8] = b"passkey-credential-0002";
const CREDENTIAL_THIRD: &[u8] = b"passkey-credential-0003";

/// The device PIN: a passphrase, since nothing counts wrong tries but this process.
const PIN: &[u8] = b"quiet harbour lantern";

/// The signed fixture rows' advisory timestamp.
const AUTHORITY_ROW_TIME: u64 = 1_790_000_001;
const FIRST_FRONTIER_SEED: u8 = 128;

/// A rooted vault with its serving install profiled and its owner authenticated.
/// The vault drops before its directory.
struct ServedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    keystore: Arc<MemoryKeystore>,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn hosted() -> Self {
        Self::open(HostingPrivacyPosture::Hosted)
    }

    fn self_host() -> Self {
        Self::open(HostingPrivacyPosture::SelfHostLocal)
    }

    fn open(posture: HostingPrivacyPosture) -> Self {
        let (vault, dir) = open_vault(posture);
        let keystore = Arc::new(MemoryKeystore::default());
        vault.install_device_keystore(keystore.clone());
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        bind_host_owner(&vault, &issuer, person).expect("the owner's host binding");
        let owner = vault
            .authenticate_owner(
                person,
                &person.to_hex(),
                true,
                GateDecisionId::from_bytes([2; 16]),
            )
            .expect("the owner's proof");
        Self {
            vault,
            issuer,
            owner,
            keystore,
            _dir: dir,
        }
    }

    fn owner_authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall)
    }

    /// This install's machine.
    fn machine(&self) -> EntityId {
        self.vault
            .prepare_install_signing()
            .expect("this install's machine")
    }

    /// `key`'s enrolment input for this install's machine, with its proof of possession.
    fn enrollment(&self, key: &SigningKey) -> OwnerKeyEnrollment {
        keyed_enrollment(self, self.machine(), key)
    }

    /// How many authority log rows the fold holds valid.
    fn stored_rows(&self) -> usize {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .len()
    }

    /// The signed authority history.
    fn history(&self) -> Vec<Vec<u8>> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
    }

    /// Whether `key` is a live owner key on the roster.
    fn live_owner_key(&self, key: &AuthorityKey) -> bool {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
    }
}

fn open_vault(posture: HostingPrivacyPosture) -> (Vault, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = posture;
    config.store_clock = ManualClock::new(1_790_000_000).bundle();
    let vault = Vault::open(dir.path(), config).expect("vault");
    (vault, dir)
}

/// A scripted device prompt on `vault`: `answers` in order, a prompt past
/// the script declined. Answers the device, which counts prompts and reasons.
fn scripted_gate(
    vault: &Vault,
    answers: impl IntoIterator<Item = Result<(), PresenceError>>,
) -> Arc<ScriptedPresence> {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let window = PresenceWindow::new(ManualPresenceClock::new(1_000_000, 1_000_000));
    let gate = PresenceGate::new(presence.clone(), window);
    vault.install_presence_gate(Arc::new(gate));
    presence
}

/// A presence clock that is past the last confirm's window on every reading,
/// so no confirm ever serves a second act.
struct ExpiresAtOnce {
    next_ms: AtomicU64,
}

impl ExpiresAtOnce {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next_ms: AtomicU64::new(1_000_000),
        })
    }
}

impl PresenceClock for ExpiresAtOnce {
    fn now(&self) -> PresenceInstant {
        let ms = self
            .next_ms
            .fetch_add(PRESENCE_WINDOW_SECS * 1_000 + 1, Ordering::SeqCst);
        PresenceInstant {
            wall_ms: ms,
            monotonic_ms: ms,
        }
    }
}

/// A scripted device prompt on `vault` whose window is over after each
/// confirm. Answers the device, which counts prompts and reasons.
fn expiring_gate(
    vault: &Vault,
    answers: impl IntoIterator<Item = Result<(), PresenceError>>,
) -> Arc<ScriptedPresence> {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let window = PresenceWindow::new(ExpiresAtOnce::new());
    let gate = PresenceGate::new(presence.clone(), window);
    vault.install_presence_gate(Arc::new(gate));
    presence
}

/// An agent's act on `vault`: a named agent whose live Grant from `owner`
/// names the free-time policy act, one of the acts an agent's Grant may name.
fn agent_act(vault: &Vault, owner: &AuthenticatedOwner) -> ActAuthority {
    let agent = vault
        .ensure_agent_principal("owner-presence-enrolment-doors-agent")
        .expect("a named agent");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "free_time_policy_set".to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        vault,
        owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("the owner grants the agent the act");
    assert!(minted.grant.confers, "guard: the agent's Grant is live");
    ActAuthority::Agent(
        vault
            .granted_act(agent, minted.grant.grant_ref, OwnerActKind::FreeTimePolicy)
            .expect("the agent's Grant names the act"),
    )
}

/// One vault with a device PIN set, over a process-memory keystore.
/// The vault drops first.
struct PinDevice {
    vault: Vault,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    pin: Arc<DevicePin>,
    _dir: tempfile::TempDir,
}

impl PinDevice {
    fn with_pin_set() -> Self {
        let (vault, dir) = open_vault(HostingPrivacyPosture::Hosted);
        let keystore = Arc::new(MemoryKeystore::new());
        vault.install_device_keystore(keystore.clone());
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("install's machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let proof = vault
            .authenticate_owner(
                owner,
                &owner.to_hex(),
                true,
                GateDecisionId::from_bytes([1; 16]),
            )
            .expect("authenticated owner");
        let pin = DevicePin::with_clock_and_cost(
            keystore,
            ManualPresenceClock::new(1_000_000, 1_000_000),
            PassphraseCost::FLOOR,
        )
        .expect("device PIN over the vault's keystore");
        vault
            .install_device_pin(pin.clone())
            .expect("install device PIN");
        let authority = ActAuthority::Owner(proof.clone(), ActSurface::ThisInstall);
        vault
            .set_device_pin_as(&authority, PIN, false)
            .expect("set the device PIN as the owner");
        Self {
            vault,
            issuer,
            proof,
            pin,
            _dir: dir,
        }
    }

    fn owner_authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.proof.clone(), ActSurface::ThisInstall)
    }

    /// How many authority log rows the fold holds valid.
    fn stored_rows(&self) -> usize {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .len()
    }

    /// The signed authority history.
    fn history(&self) -> Vec<Vec<u8>> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
    }
}

/// Asserts `refused` is a declined confirm's refusal of `what`.
fn assert_declined<T: std::fmt::Debug>(refused: &oneiron::Result<T>, what: &str) {
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a declined confirm refuses {what}: {refused:?}"
    );
}

/// Asserts `refused` is the owner-only refusal of `what`.
fn assert_owner_only<T: std::fmt::Debug>(refused: &oneiron::Result<T>, what: &str) {
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::AuthorityRefused(reason)))
                if *reason == OWNER_ONLY
        ),
        "an agent's {what} is refused as the owner's only: {refused:?}"
    );
}

/// Asserts `refused` is the undecodable-input refusal of `what`.
fn assert_not_valid<T: std::fmt::Debug>(refused: &oneiron::Result<T>, what: &str) {
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::InvalidAuthorityLogBody(_)))
        ),
        "an input that does not decode refuses {what}: {refused:?}"
    );
}

/// What `navigator.credentials.get` returns for a challenge: authenticator
/// data (RP id hash, flags, a zero sign count), the client data JSON, and
/// the DER signature over the one and SHA-256 of the other.
struct Assertion {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
}

/// A platform authenticator's passkey, as a software key from `seed`.
fn software_passkey(seed: u8) -> P256SigningKey {
    P256SigningKey::from_slice(&[seed; 32]).expect("a P-256 scalar")
}

/// The passkey's assertion over its challenge at this fixture's origin.
fn passkey_assertion(key: &P256SigningKey, challenge: &[u8]) -> Assertion {
    let mut authenticator_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
    authenticator_data.push(FLAGS_PRESENT_VERIFIED);
    authenticator_data.extend_from_slice(&[0; 4]);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://{RP_ID}","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    )
    .into_bytes();
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let signature: P256Signature = key.sign(&signed);
    Assertion {
        authenticator_data,
        client_data_json,
        signature: signature.to_der().as_bytes().to_vec(),
    }
}

/// `key`'s enrolment input under `credential_id`: its assertion over its
/// enrolment challenge.
fn passkey_input(
    served: &ServedVault,
    key: &P256SigningKey,
    credential_id: &[u8],
) -> OwnerPasskeyEnrollment {
    let public_key = key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let challenge = served
        .vault
        .owner_passkey_enrollment_challenge_as(&served.owner_authority(), &public_key)
        .expect("the passkey's enrolment challenge");
    let assertion = passkey_assertion(key, &challenge);
    OwnerPasskeyEnrollment {
        credential_id: credential_id.to_vec(),
        public_key,
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
        signature: assertion.signature,
    }
}

/// `key` signs an authority transcript as the browser would: an assertion
/// over its challenge, in its envelope.
fn passkey_signs_with(key: &P256SigningKey, transcript: &[u8]) -> Vec<u8> {
    let assertion = passkey_assertion(key, &webauthn_challenge(transcript));
    webauthn_assertion_envelope(
        &assertion.authenticator_data,
        &assertion.client_data_json,
        &assertion.signature,
    )
    .expect("an envelope")
}

/// `key` as the roster names it: compressed SEC1.
fn passkey_roster_key(key: &P256SigningKey) -> AuthorityKey {
    AuthorityKey::P256(
        key.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    )
}

/// The owner's device key.
fn owner_device() -> SigningKey {
    SigningKey::from_bytes(&[OWNER_DEVICE_SEED; 32])
}

/// A key the host holds, which a mislabelled prompt had the passkey vouch for.
fn host_held() -> SigningKey {
    SigningKey::from_bytes(&[HOST_HELD_SEED; 32])
}

fn ed_key(key: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(key.verifying_key().to_bytes())
}

/// `device`'s enrolment input for `machine`: its key and its proof.
fn keyed_enrollment(
    served: &ServedVault,
    machine: EntityId,
    device: &SigningKey,
) -> OwnerKeyEnrollment {
    let public_key = device.verifying_key().to_bytes();
    let challenge = served
        .vault
        .owner_key_enrollment_challenge_as(&served.owner_authority(), machine, &public_key)
        .expect("the device key's challenge");
    OwnerKeyEnrollment {
        machine,
        public_key,
        proof: device.sign(&challenge).to_bytes().to_vec(),
    }
}

/// Enrols the first passkey with the host root as predecessor. Answers the carrier.
fn enrol_first_passkey(served: &ServedVault, first: &P256SigningKey) -> EntityId {
    served
        .vault
        .enrol_owner_passkey_as_host(
            &served.owner_authority(),
            &passkey_input(served, first, CREDENTIAL_FIRST),
            &served.issuer,
        )
        .expect("the owner enrols his passkey")
        .machine
}

/// The owner's passkey and device key, and a host-held key that only the
/// passkey vouched for. Answers the carrier.
fn passkey_vouched_host_key(served: &ServedVault) -> EntityId {
    let first = software_passkey(FIRST_PASSKEY_SEED);
    let machine = enrol_first_passkey(served, &first);
    served
        .vault
        .enrol_owner_signing_key_as_host(
            &served.owner_authority(),
            keyed_enrollment(served, machine, &owner_device()),
            &served.issuer,
        )
        .expect("the owner's device key");
    served
        .vault
        .enrol_owner_signing_key_as(
            &served.owner_authority(),
            keyed_enrollment(served, machine, &host_held()),
            passkey_roster_key(&first),
            |transcript| Ok(passkey_signs_with(&first, transcript)),
        )
        .expect("the passkey vouches for the host-held key");
    assert!(
        served.live_owner_key(&ed_key(&host_held())),
        "guard: the passkey-vouched key is a live owner key"
    );
    machine
}

/// This vault's authority id.
fn authority_vault_id(vault: &Vault) -> [u8; 32] {
    vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault")
}

/// `seed` rebuilt from two stored pieces of a kit issued for it: the owner's restore.
fn restored(vault_id: [u8; 32], seed: &RecoveryRootSeed) -> RecoveryRootSeed {
    let issue = KitIssue {
        vault_id,
        homes: [
            PieceHome::ThisMachine,
            PieceHome::OtherMachine(
                EntityId::from_bytes([0x51; 16]).expect("first backup machine id"),
            ),
            PieceHome::OtherMachine(
                EntityId::from_bytes([0x52; 16]).expect("second backup machine id"),
            ),
        ],
        passphrase: None,
        cost: PassphraseCost::FLOOR,
        only_machine: false,
    };
    let pieces = issue_recovery_root_kit(&issue, &seed.kit_bytes())
        .expect("the kit")
        .into_pieces();
    let secret = restore_kit(
        vault_id,
        KitSecretKind::RecoveryRoot,
        &[&pieces[0], &pieces[1]],
        None,
    )
    .expect("two stored pieces restore the seed");
    RecoveryRootSeed::from_restored_kit(secret).expect("the restored seed")
}

/// The owner enrols the kit root's authority key before the loss.
fn enrol_root_key(served: &ServedVault, seed: &RecoveryRootSeed) -> AuthorityKey {
    let receipt = served
        .vault
        .enrol_recovery_authority_key_as_host(
            &served.owner_authority(),
            served.machine(),
            seed,
            &served.issuer,
        )
        .expect("the owner enrols the root's authority key");
    AuthorityKey::Ed25519(receipt.public_key)
}

/// Each stored authority row, decoded.
fn history_rows(vault: &Vault) -> Vec<AuthorityLogEntry> {
    vault
        .export_signed_authority_history()
        .expect("the signed history")
        .iter()
        .map(|row| decode_authority_log_entry_body(row).expect("a row"))
        .collect()
}

/// The rows no row names as a parent.
fn heads_of(vault: &Vault) -> Vec<AuthorityEntryHash> {
    let rows = history_rows(vault);
    let parents: BTreeSet<AuthorityEntryHash> = rows
        .iter()
        .flat_map(|row| row.parent_hashes.iter().copied())
        .collect();
    rows.iter()
        .map(|row| authority_entry_hash(row).expect("a hash"))
        .filter(|row| !parents.contains(row))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// `signer`'s next sequence in the stored history.
fn next_seq_of(vault: &Vault, signer: &AuthorityKey) -> u64 {
    history_rows(vault)
        .iter()
        .filter(|row| row.signer_key() == signer)
        .map(|row| row.seq + 1)
        .max()
        .unwrap_or(0)
        .max(1)
}

/// A software device with the given roles and seed.
fn software_device(seed: u8, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key: AuthorityKey::Ed25519(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        ),
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

/// `op`, signed by `signer` at `seq` on `parents`.
fn signed_authority_row(
    vault_id: [u8; 32],
    signer: &SigningKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
) -> AuthorityLogEntry {
    let public_key = AuthorityKey::Ed25519(signer.verifying_key().to_bytes());
    let overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&op)
        .expect("authority overlay seed");
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: parents,
        op,
        overlay_seed,
        signer: AuthoritySignature {
            suite: public_key.suite(),
            public_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: AUTHORITY_ROW_TIME,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    row
}

/// The owner key hands the vault to two new keys on the heads, and both
/// handoffs arrive together: a fork that leaves no live root key.
fn fork_rootless(served: &ServedVault, owner_key: &SigningKey) {
    let vault_id = authority_vault_id(&served.vault);
    let heads = heads_of(&served.vault);
    let seq = next_seq_of(&served.vault, &ed_key(owner_key)).max(1);
    let first = signed_authority_row(
        vault_id,
        owner_key,
        seq,
        heads.clone(),
        AuthorityOp::ReRoot {
            new_device: software_device(FIRST_HANDOFF_SEED, ROLE_OWNER),
        },
    );
    let second = signed_authority_row(
        vault_id,
        owner_key,
        seq + 1,
        heads,
        AuthorityOp::ReRoot {
            new_device: software_device(SECOND_HANDOFF_SEED, ROLE_OWNER),
        },
    );
    served
        .vault
        .import_signed_authority_history(
            &[
                encode_authority_log_entry_body(&first).expect("the signed bytes"),
                encode_authority_log_entry_body(&second).expect("the signed bytes"),
            ],
            &std::collections::BTreeMap::new(),
        )
        .expect("both handoffs land");
}

/// Installs more counted concurrent main-log heads than an enrolment can name.
fn widen_frontier(served: &ServedVault) {
    let owner = owner_device();
    served
        .vault
        .enrol_owner_signing_key_as_host(
            &served.owner_authority(),
            served.enrollment(&owner),
            &served.issuer,
        )
        .expect("the owner enrols the frontier signer");
    let parents = heads_of(&served.vault);
    let seq = next_seq_of(&served.vault, &ed_key(&owner));
    let vault_id = authority_vault_id(&served.vault);
    let at = TimeRange {
        start: AUTHORITY_ROW_TIME,
        end: AUTHORITY_ROW_TIME,
    };
    let parent_limit =
        u8::try_from(MAX_PARENTS).expect("parent limit fits the fixture's seed range");
    let rows: Vec<_> = (0..=parent_limit)
        .map(|offset| {
            let row = signed_authority_row(
                vault_id,
                &owner,
                seq + u64::from(offset),
                parents.clone(),
                AuthorityOp::EnrollDevice {
                    device: software_device(FIRST_FRONTIER_SEED + offset, ROLE_AGENT),
                },
            );
            (row, at, AUTHORITY_ROW_TIME)
        })
        .collect();
    served
        .vault
        .put_authority_log_entries(&rows)
        .expect("the concurrent owner-signed rows land");
    let fold = served.vault.authority_fold().expect("authority fold");
    let heads = heads_of(&served.vault);
    assert!(heads.len() > MAX_PARENTS);
    assert!(heads.iter().all(|hash| fold.valid_entries.contains(hash)));
}

/// Whether the roster holds no live root key.
fn is_rootless(served: &ServedVault) -> bool {
    served
        .vault
        .authority_fold()
        .expect("the fold")
        .issues
        .contains(&AuthorityFoldIssue::NoRootKey)
}

/// A self-hosted vault whose roster holds no live root key, and the restored
/// seed of the kit root its install pins: the state the root appointment serves.
fn rootless_with_kit_seed() -> (ServedVault, RecoveryRootSeed) {
    let appoint = ServedVault::self_host();
    let owner_key = SigningKey::from_bytes(&[LOST_KEY_SEED; 32]);
    appoint
        .vault
        .enrol_owner_signing_key_as_host(
            &appoint.owner_authority(),
            appoint.enrollment(&owner_key),
            &appoint.issuer,
        )
        .expect("the owner enrols an owner key");
    appoint
        .vault
        .enrol_device_owner_signing_key(&appoint.owner_authority(), &appoint.issuer)
        .expect("this install holds a predecessor for the activation");
    let prepared = appoint
        .vault
        .prepare_owner_root(&appoint.owner)
        .expect("a kit root");
    let seed = restored(authority_vault_id(&appoint.vault), prepared.seed());
    let _activated = appoint
        .vault
        .activate_owner_root(&appoint.owner, prepared, &BTreeSet::new())
        .expect("the owner activates his root");
    fork_rootless(&appoint, &owner_key);
    assert!(
        is_rootless(&appoint),
        "guard: the fork leaves no live root key"
    );
    (appoint, seed)
}

/// Puts an empty keystore on `served`'s handle. The handle drops the signing
/// keys it loaded, the vault still names its machine and its device key, and
/// no slot holds their seed: readying this install's signing keys now would
/// forget that machine and mint another.
fn install_empty_keystore(served: &ServedVault) {
    served
        .vault
        .install_device_keystore(Arc::new(MemoryKeystore::default()));
}

/// This install's machine once `served`'s own keystore is back on its handle:
/// the machine the vault named before, unless a door readied the signing keys
/// under the empty keystore and forgot it.
fn machine_under_own_keystore(served: &ServedVault) -> EntityId {
    served
        .vault
        .install_device_keystore(served.keystore.clone());
    served.machine()
}

/// A declined confirm refuses the host enrolment of an owner key and stores nothing.
#[test]
fn a_declined_confirm_refuses_the_host_enrolment_of_an_owner_key_and_stores_nothing() {
    let served = ServedVault::hosted();
    let input = served.enrollment(&SigningKey::from_bytes(&[41; 32]));
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let rows = served.stored_rows();
    let history = served.history();
    let refused = served.vault.enrol_owner_signing_key_as_host(
        &served.owner_authority(),
        input,
        &served.issuer,
    );
    assert_declined(&refused, "the host enrolment of an owner key");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        served.history(),
        history,
        "the log holds the entries it held before"
    );
}

/// A declined confirm refuses an owner key enrolment signed by the caller's closure.
#[test]
fn a_declined_confirm_refuses_an_owner_key_enrolment_signed_by_the_callers_closure() {
    let served = ServedVault::hosted();
    served
        .vault
        .enrol_owner_signing_key_as_host(
            &served.owner_authority(),
            served.enrollment(&owner_device()),
            &served.issuer,
        )
        .expect("the owner's device key");
    let input = served.enrollment(&SigningKey::from_bytes(&[42; 32]));
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let rows = served.stored_rows();
    let called = Cell::new(false);
    let refused = served.vault.enrol_owner_signing_key_as(
        &served.owner_authority(),
        input,
        ed_key(&owner_device()),
        |transcript| {
            called.set(true);
            Ok(owner_device().sign(transcript).to_bytes().to_vec())
        },
    );
    assert_declined(&refused, "the enrolment signed by the caller's closure");
    assert!(!called.get(), "the closure is never called");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
}

/// A declined confirm refuses a key confirmation.
#[test]
fn a_declined_confirm_refuses_a_key_confirmation() {
    let served = ServedVault::hosted();
    let machine = passkey_vouched_host_key(&served);
    let input = keyed_enrollment(&served, machine, &host_held());
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let rows = served.stored_rows();
    let history = served.history();
    let called = Cell::new(false);
    let refused = served.vault.confirm_owner_key_as(
        &served.owner_authority(),
        input,
        ed_key(&owner_device()),
        |transcript| {
            called.set(true);
            Ok(owner_device().sign(transcript).to_bytes().to_vec())
        },
    );
    assert_declined(&refused, "the key confirmation");
    assert!(!called.get(), "the closure is never called");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        served.history(),
        history,
        "the log holds the entries it held before"
    );
}

/// A declined confirm refuses a prepared enrolment before its frontier join.
#[test]
fn a_declined_confirm_refuses_a_prepared_enrolment_before_its_frontier_join() {
    let served = ServedVault::hosted();
    widen_frontier(&served);
    let input = served.enrollment(&SigningKey::from_bytes(&[43; 32]));
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let rows = served.stored_rows();
    let history = served.history();
    let refused = served.vault.prepare_owner_key_enrollment_as(
        &served.owner_authority(),
        input,
        served.issuer.public_key(),
    );
    assert_declined(&refused, "the prepared enrolment");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(
        served.stored_rows(),
        rows,
        "the refusal stores no row, frontier join included"
    );
    assert_eq!(
        served.history(),
        history,
        "the log holds the entries it held before"
    );
}

/// A declined confirm refuses the landing of a prepared enrolment.
#[test]
fn a_declined_confirm_refuses_the_landing_of_a_prepared_enrolment() {
    let served = ServedVault::hosted();
    let input = served.enrollment(&SigningKey::from_bytes(&[44; 32]));
    let presence = scripted_gate(&served.vault, [Ok(()), Err(PresenceError::Declined)]);
    let prepared = served
        .vault
        .prepare_owner_key_enrollment_as(
            &served.owner_authority(),
            input,
            served.issuer.public_key(),
        )
        .expect("the prepare lands under a confirm");
    assert_eq!(presence.prompts(), 1, "the prepare showed one prompt");
    let rows = served.stored_rows();
    let history = served.history();
    served
        .vault
        .presence_gate()
        .expect("the installed gate")
        .end_window();
    let refused = served.vault.land_owner_key_enrollment_as(
        &served.owner_authority(),
        &prepared.entry,
        vec![7; 64],
    );
    assert_declined(&refused, "the landing of the prepared enrolment");
    assert_eq!(presence.prompts(), 2, "the landing prompted again");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        served.history(),
        history,
        "the log holds the entries it held before"
    );
}

/// A declined confirm refuses a passkey enrolment and a passkey confirmation.
#[test]
fn a_declined_confirm_refuses_a_passkey_enrolment_and_a_passkey_confirmation() {
    let served = ServedVault::hosted();
    let first = software_passkey(FIRST_PASSKEY_SEED);
    let machine = enrol_first_passkey(&served, &first);
    served
        .vault
        .enrol_owner_signing_key_as_host(
            &served.owner_authority(),
            keyed_enrollment(&served, machine, &owner_device()),
            &served.issuer,
        )
        .expect("the owner's device key");
    let second = software_passkey(SECOND_PASSKEY_SEED);
    served
        .vault
        .enrol_owner_passkey_as(
            &served.owner_authority(),
            &passkey_input(&served, &second, CREDENTIAL_SECOND),
            passkey_roster_key(&first),
            |transcript| Ok(passkey_signs_with(&first, transcript)),
        )
        .expect("the first passkey vouches for the second");
    let third = software_passkey(THIRD_PASSKEY_SEED);
    let enrolment = passkey_input(&served, &third, CREDENTIAL_THIRD);
    let confirmation = passkey_input(&served, &second, CREDENTIAL_SECOND);
    let presence = scripted_gate(
        &served.vault,
        [Err(PresenceError::Declined), Err(PresenceError::Declined)],
    );
    let rows = served.stored_rows();
    let history = served.history();
    let refused = served.vault.enrol_owner_passkey_as_host(
        &served.owner_authority(),
        &enrolment,
        &served.issuer,
    );
    assert_declined(&refused, "the passkey enrolment");
    let refused = served.vault.confirm_owner_passkey_as(
        &served.owner_authority(),
        &confirmation,
        ed_key(&owner_device()),
        |transcript| Ok(owner_device().sign(transcript).to_bytes().to_vec()),
    );
    assert_declined(&refused, "the passkey confirmation");
    assert_eq!(presence.prompts(), 2, "each door showed one prompt");
    assert_eq!(
        presence.reasons(),
        [ENROL_OWNER_PASSKEY_REASON, CONFIRM_OWNER_PASSKEY_REASON],
        "each prompt shows its door's line"
    );
    assert_eq!(served.stored_rows(), rows, "the refusals store no row");
    assert_eq!(
        served.history(),
        history,
        "the log holds the entries it held before"
    );
}

/// A declined confirm refuses the recovery authority key enrolment.
#[test]
fn a_declined_confirm_refuses_the_recovery_authority_key_enrolment() {
    let served = ServedVault::hosted();
    let seed = restored(
        authority_vault_id(&served.vault),
        &RecoveryRootSeed::generate().expect("a root seed"),
    );
    let machine = served.machine();
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let rows = served.stored_rows();
    let history = served.history();
    let refused = served.vault.enrol_recovery_authority_key_as_host(
        &served.owner_authority(),
        machine,
        &seed,
        &served.issuer,
    );
    assert_declined(&refused, "the recovery authority key enrolment");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        served.history(),
        history,
        "the log holds the entries it held before"
    );
}

/// A declined confirm refuses this device's own key enrolment.
#[test]
fn a_declined_confirm_refuses_this_devices_own_key_enrolment() {
    let served = ServedVault::self_host();
    let pin = DevicePin::with_clock_and_cost(
        served.keystore.clone(),
        ManualPresenceClock::new(1_000_000, 1_000_000),
        PassphraseCost::FLOOR,
    )
    .expect("a device PIN handle with no PIN set");
    served
        .vault
        .install_device_pin(pin)
        .expect("install device PIN handle");
    let presence = scripted_gate(
        &served.vault,
        [
            Err(PresenceError::Declined),
            Err(PresenceError::Declined),
            Ok(()),
        ],
    );
    let rows = served.stored_rows();
    let history = served.history();
    let refused = served
        .vault
        .enrol_device_owner_signing_key(&served.owner_authority(), &served.issuer);
    assert_declined(&refused, "this device's own key enrolment");
    let refused = served
        .vault
        .enrol_serving_install_owner_signing_key(&served.owner_authority(), &served.issuer);
    assert_declined(&refused, "the serving install's key enrolment");
    assert_eq!(presence.prompts(), 2, "each door showed one prompt");
    assert_eq!(served.stored_rows(), rows, "the refusals store no row");
    assert_eq!(
        served.history(),
        history,
        "the log holds the entries it held before"
    );
    let receipt = served
        .vault
        .enrol_device_owner_signing_key(&served.owner_authority(), &served.issuer)
        .expect("a confirm then enrols: no step is left held");
    assert_eq!(presence.prompts(), 3, "the confirm showed one prompt");
    assert!(
        served.live_owner_key(&AuthorityKey::Ed25519(receipt.public_key)),
        "the key is on the roster"
    );
    let again = served
        .vault
        .enrol_serving_install_owner_signing_key(&served.owner_authority(), &served.issuer)
        .expect("the serving install answers the live key");
    assert_eq!(
        again.public_key, receipt.public_key,
        "the live key's receipt answers"
    );
    assert_eq!(
        presence.prompts(),
        3,
        "the live answer stands in the confirm's window"
    );
}

/// The device door asks once for one enrolment.
#[test]
fn the_device_door_asks_once_for_one_enrolment() {
    let served = ServedVault::self_host();
    let presence = expiring_gate(&served.vault, [Ok(()), Ok(())]);
    let receipt = served
        .vault
        .enrol_device_owner_signing_key(&served.owner_authority(), &served.issuer)
        .expect("one enrolment under one confirm");
    assert_eq!(
        presence.prompts(),
        1,
        "one enrolment shows exactly one prompt"
    );
    assert_eq!(presence.reasons(), [ENROL_THIS_DEVICE_REASON]);
    assert!(
        served.live_owner_key(&AuthorityKey::Ed25519(receipt.public_key)),
        "the key is on the roster"
    );
}

/// A declined confirm refuses the root recovery and the root appointment.
#[test]
fn a_declined_confirm_refuses_the_root_recovery_and_the_root_appointment() {
    let served = ServedVault::hosted();
    let lost = SigningKey::from_bytes(&[LOST_KEY_SEED; 32]);
    served
        .vault
        .enrol_owner_signing_key_as_host(
            &served.owner_authority(),
            served.enrollment(&lost),
            &served.issuer,
        )
        .expect("the owner enrols the lost key");
    let seed = restored(
        authority_vault_id(&served.vault),
        &RecoveryRootSeed::generate().expect("a root seed"),
    );
    let root_key = enrol_root_key(&served, &seed);
    assert!(
        served.live_owner_key(&root_key),
        "guard: the root's authority key is live"
    );
    let successor = served.enrollment(&SigningKey::from_bytes(&[NEW_KEY_SEED; 32]));
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let rows = served.stored_rows();
    let history = served.history();
    let refused = served.vault.recover_owner_root(
        &served.owner,
        ActSurface::ThisInstall,
        RootMaterial::Kit {
            seed: restored(authority_vault_id(&served.vault), &seed),
            confirm: None,
        },
        RootSuccessor::Device(successor),
        &[AuthorityKey::Ed25519(lost.verifying_key().to_bytes())],
    );
    assert_declined(&refused, "the root recovery");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        served.history(),
        history,
        "the log holds the entries it held before"
    );

    let (appoint, seed) = rootless_with_kit_seed();
    let presence = scripted_gate(&appoint.vault, [Err(PresenceError::Declined)]);
    let rows = appoint.stored_rows();
    let history = appoint.history();
    let refused = appoint
        .vault
        .appoint_owner_root(&appoint.owner, &seed, None);
    assert_declined(&refused, "the root appointment");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(appoint.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        appoint.history(),
        history,
        "the log holds the entries it held before"
    );
}

/// A declined confirm at this device's door leaves this install's machine identity unchanged.
#[test]
fn a_declined_confirm_at_this_devices_door_leaves_this_installs_machine_identity_unchanged() {
    let served = ServedVault::self_host();
    let machine = served.machine();
    install_empty_keystore(&served);
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let rows = served.stored_rows();
    let refused = served
        .vault
        .enrol_device_owner_signing_key(&served.owner_authority(), &served.issuer);
    assert_declined(&refused, "this device's own key enrolment");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        machine_under_own_keystore(&served),
        machine,
        "the refused door readied no signing keys: this install is the machine it was"
    );
}

/// A declined confirm at the root recovery leaves this install's machine identity unchanged.
#[test]
fn a_declined_confirm_at_the_root_recovery_leaves_this_installs_machine_identity_unchanged() {
    let served = ServedVault::hosted();
    let seed = restored(
        authority_vault_id(&served.vault),
        &RecoveryRootSeed::generate().expect("a root seed"),
    );
    let root_key = enrol_root_key(&served, &seed);
    assert!(
        served.live_owner_key(&root_key),
        "guard: the root's authority key is live"
    );
    let machine = served.machine();
    install_empty_keystore(&served);
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let rows = served.stored_rows();
    let refused = served.vault.recover_owner_root(
        &served.owner,
        ActSurface::ThisInstall,
        RootMaterial::Kit {
            seed: restored(authority_vault_id(&served.vault), &seed),
            confirm: None,
        },
        RootSuccessor::ThisInstall,
        &[],
    );
    assert_declined(&refused, "the root recovery for this install");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        machine_under_own_keystore(&served),
        machine,
        "the refused door readied no signing keys: this install is the machine it was"
    );
}

/// A declined confirm at the root appointment leaves this install's machine identity unchanged.
#[test]
fn a_declined_confirm_at_the_root_appointment_leaves_this_installs_machine_identity_unchanged() {
    let (appoint, seed) = rootless_with_kit_seed();
    let machine = appoint.machine();
    install_empty_keystore(&appoint);
    let presence = scripted_gate(&appoint.vault, [Err(PresenceError::Declined)]);
    let rows = appoint.stored_rows();
    let refused = appoint
        .vault
        .appoint_owner_root(&appoint.owner, &seed, None);
    assert_declined(&refused, "the root appointment");
    assert_eq!(presence.prompts(), 1, "the door showed one prompt");
    assert_eq!(appoint.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        machine_under_own_keystore(&appoint),
        machine,
        "the refused door readied no signing keys: this install is the machine it was"
    );
}

/// An owner proof of another vault never raises the prompt at the root recovery.
#[test]
fn an_owner_proof_of_another_vault_never_raises_the_prompt_at_the_root_recovery() {
    let served = ServedVault::hosted();
    let other = ServedVault::hosted();
    let seed = restored(
        authority_vault_id(&served.vault),
        &RecoveryRootSeed::generate().expect("a root seed"),
    );
    let root_key = enrol_root_key(&served, &seed);
    assert!(
        served.live_owner_key(&root_key),
        "guard: the root's authority key is live"
    );
    let successor = served.enrollment(&SigningKey::from_bytes(&[NEW_KEY_SEED; 32]));
    let presence = scripted_gate(&served.vault, []);
    let rows = served.stored_rows();
    let refused = served.vault.recover_owner_root(
        &other.owner,
        ActSurface::ThisInstall,
        RootMaterial::Kit {
            seed: restored(authority_vault_id(&served.vault), &seed),
            confirm: None,
        },
        RootSuccessor::Device(successor),
        &[],
    );
    assert!(
        matches!(
            refused,
            Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
        ),
        "another vault's owner proof is refused as no owner of this vault: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the door showed no prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
}

/// An owner proof of another vault never raises the prompt at a recovery
/// hold's answer or at a recovery box Cancel: the proof is refused first.
#[test]
fn an_owner_proof_of_another_vault_never_raises_the_prompt_at_a_hold_answer_or_a_box_cancel() {
    let served = ServedVault::hosted();
    let other = ServedVault::hosted();
    let foreign = other.owner_authority();
    let presence = scripted_gate(&served.vault, []);
    let rows = served.stored_rows();
    let hold: AuthorityEntryHash = [0x5A; 32];
    for answer in [
        RecoveryHoldAnswerKind::ItIsMe,
        RecoveryHoldAnswerKind::Cancel,
    ] {
        let refused = served.vault.answer_recovery_hold_as(&foreign, hold, answer);
        assert!(
            matches!(
                refused,
                Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
            ),
            "another vault's owner proof is refused at the {answer:?} answer: {refused:?}"
        );
    }
    let refused = served.vault.sign_recovery_box_cancel_as(&foreign, None);
    assert!(
        matches!(
            refused,
            Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
        ),
        "another vault's owner proof is refused at the box cancel: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the doors showed no prompt");
    assert_eq!(served.stored_rows(), rows, "the refusals store no row");
}

/// An agent never raises the prompt at an enrolment door.
#[test]
fn an_agent_never_raises_the_prompt_at_an_enrolment_door() {
    let served = ServedVault::hosted();
    let agent = agent_act(&served.vault, &served.owner);
    let seed = restored(
        authority_vault_id(&served.vault),
        &RecoveryRootSeed::generate().expect("a root seed"),
    );
    let machine = served.machine();
    let presence = scripted_gate(&served.vault, []);
    let rows = served.stored_rows();
    let refused = served.vault.enrol_owner_signing_key_as_host(
        &agent,
        served.enrollment(&SigningKey::from_bytes(&[45; 32])),
        &served.issuer,
    );
    assert_owner_only(&refused, "host enrolment");
    let refused = served.vault.confirm_owner_key_as(
        &agent,
        served.enrollment(&SigningKey::from_bytes(&[46; 32])),
        served.issuer.public_key(),
        |_| Ok(Vec::new()),
    );
    assert_owner_only(&refused, "key confirmation");
    let refused = served.vault.prepare_owner_key_enrollment_as(
        &agent,
        served.enrollment(&SigningKey::from_bytes(&[47; 32])),
        served.issuer.public_key(),
    );
    assert_owner_only(&refused, "prepared enrolment");
    let refused = served
        .vault
        .land_owner_key_enrollment_as(&agent, &[9; 32], vec![1, 2, 3]);
    assert_owner_only(&refused, "landing of a prepared enrolment");
    let refused =
        served
            .vault
            .enrol_recovery_authority_key_as_host(&agent, machine, &seed, &served.issuer);
    assert_owner_only(&refused, "recovery authority key enrolment");
    let refused = served
        .vault
        .enrol_device_owner_signing_key(&agent, &served.issuer);
    assert_owner_only(&refused, "this device's own key enrolment");
    assert_eq!(presence.prompts(), 0, "no door showed a prompt");
    assert_eq!(served.stored_rows(), rows, "the refusals store no row");
}

/// An input that does not decode never raises the prompt.
#[test]
fn an_input_that_does_not_decode_never_raises_the_prompt() {
    let served = ServedVault::hosted();
    let bad = OwnerPasskeyEnrollment {
        credential_id: vec![1],
        public_key: vec![2],
        authenticator_data: vec![3],
        client_data_json: vec![4],
        signature: vec![5],
    };
    let presence = scripted_gate(&served.vault, []);
    let rows = served.stored_rows();
    let refused =
        served
            .vault
            .enrol_owner_passkey_as_host(&served.owner_authority(), &bad, &served.issuer);
    assert_not_valid(&refused, "the passkey enrolment");
    let refused = served.vault.confirm_owner_passkey_as(
        &served.owner_authority(),
        &bad,
        served.issuer.public_key(),
        |_| Ok(Vec::new()),
    );
    assert_not_valid(&refused, "the passkey confirmation");
    let refused =
        served
            .vault
            .land_owner_key_enrollment_as(&served.owner_authority(), &[9; 32], vec![1]);
    assert_not_valid(&refused, "the landing");
    assert_eq!(presence.prompts(), 0, "no door showed a prompt");
    assert_eq!(served.stored_rows(), rows, "the refusals store no row");
}

/// A passkey assertion whose client data does not decode never raises the prompt.
#[test]
fn a_passkey_assertion_whose_client_data_does_not_decode_never_raises_the_prompt() {
    let served = ServedVault::hosted();
    let mut undecodable = passkey_input(
        &served,
        &software_passkey(FIRST_PASSKEY_SEED),
        CREDENTIAL_FIRST,
    );
    // An opened object and nothing after it: the envelope takes one byte of
    // client data, and no client data parses from it.
    undecodable.client_data_json = b"{".to_vec();
    let presence = scripted_gate(&served.vault, []);
    let rows = served.stored_rows();
    let refused = served.vault.enrol_owner_passkey_as_host(
        &served.owner_authority(),
        &undecodable,
        &served.issuer,
    );
    assert_not_valid(&refused, "the passkey enrolment");
    let refused = served.vault.confirm_owner_passkey_as(
        &served.owner_authority(),
        &undecodable,
        served.issuer.public_key(),
        |_| Ok(Vec::new()),
    );
    assert_not_valid(&refused, "the passkey confirmation");
    assert_eq!(presence.prompts(), 0, "no door showed a prompt");
    assert_eq!(served.stored_rows(), rows, "the refusals store no row");
}

/// A managed host's serving install is refused with no prompt.
#[test]
fn a_managed_hosts_serving_install_is_refused_with_no_prompt() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, []);
    let rows = served.stored_rows();
    let refused = served
        .vault
        .enrol_serving_install_owner_signing_key(&served.owner_authority(), &served.issuer);
    assert!(
        matches!(
            &refused,
            Err(Error::Record(RecordError::AuthorityRefused(reason)))
                if *reason == MANAGED_HOST_HOLDS_NO_OWNER_KEY
        ),
        "a managed host holds no owner key: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the door showed no prompt");
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
}

/// Each enrolment prompt shows its door's reason line.
#[test]
fn each_enrolment_prompt_shows_its_doors_reason_line() {
    let served = ServedVault::hosted();
    let key = served.enrollment(&SigningKey::from_bytes(&[48; 32]));
    let confirmation = served.enrollment(&SigningKey::from_bytes(&[50; 32]));
    let passkey = passkey_input(
        &served,
        &software_passkey(FIRST_PASSKEY_SEED),
        CREDENTIAL_FIRST,
    );
    let authority = served.owner_authority();
    let predecessor = served.issuer.public_key();
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined); 4]);
    let rows = served.stored_rows();
    let refused = served
        .vault
        .enrol_owner_signing_key_as_host(&authority, key, &served.issuer);
    assert_declined(&refused, "the host enrolment");
    let refused = served
        .vault
        .enrol_owner_passkey_as_host(&authority, &passkey, &served.issuer);
    assert_declined(&refused, "the passkey enrolment");
    let refused =
        served
            .vault
            .confirm_owner_passkey_as(
                &authority,
                &passkey,
                predecessor.clone(),
                |_| Ok(Vec::new()),
            );
    assert_declined(&refused, "the passkey confirmation");
    let refused = served
        .vault
        .confirm_owner_key_as(&authority, confirmation, predecessor, |_| Ok(Vec::new()));
    assert_declined(&refused, "the key confirmation");
    assert_eq!(
        presence.reasons(),
        [
            ENROL_OWNER_SIGNING_KEY_REASON,
            ENROL_OWNER_PASSKEY_REASON,
            CONFIRM_OWNER_PASSKEY_REASON,
            CONFIRM_OWNER_SIGNING_KEY_REASON,
        ],
        "each prompt shows its door's line"
    );
    assert_eq!(served.stored_rows(), rows, "the refusals store no row");
}

/// A device with a PIN set answers PIN required at the host enrolment door.
#[test]
fn a_device_with_a_pin_set_answers_pin_required_at_the_host_enrolment_door() {
    let device = PinDevice::with_pin_set();
    device.pin.end_window();
    let key = SigningKey::from_bytes(&[49; 32]);
    let public_key = key.verifying_key().to_bytes();
    let machine = device
        .vault
        .prepare_install_signing()
        .expect("this install's machine");
    let challenge = device
        .vault
        .owner_key_enrollment_challenge_as(&device.owner_authority(), machine, &public_key)
        .expect("the enrolment challenge");
    let input = OwnerKeyEnrollment {
        machine,
        public_key,
        proof: key.sign(&challenge).to_bytes().to_vec(),
    };
    let presence = scripted_gate(&device.vault, [Ok(())]);
    let rows = device.stored_rows();
    let history = device.history();
    let refused = device.vault.enrol_owner_signing_key_as_host(
        &device.owner_authority(),
        input,
        &device.issuer,
    );
    assert!(
        matches!(
            refused,
            Err(Error::Secret(SecretError::DevicePin(
                DevicePinRefusal::Required
            )))
        ),
        "outside the PIN's window the door asks for the PIN: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the PIN answers before any prompt");
    assert_eq!(device.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        device.history(),
        history,
        "the log holds the entries it held before"
    );
}
