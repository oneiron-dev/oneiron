//! OPUS-WAYBACK-BOX R7 box deposit, engine half (WAYBACK-BOX-DEPOSIT-PATH =
//! A, Engine 16 Nov 02:00): the confirm answer at both route sites carries
//! R's authority seed for the recovery box once, and none under "Nobody but
//! me"; the CLI writes it only with `--box-deposit-out`; the answer never
//! reaches a log line.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test recovery_box_deposit_answer`
//!
//! Red on fa6a6fcc2c5d (R4 PR 2): the doors do not exist there, so the file does not compile.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use oneiron::authority::{
    ActAuthority, ActSurface, EnrolledOwnerKey, EnrolledOwnerKeyKind, HostSlipIssuer,
    MachineOwnership, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{CodeKeeping, KitIssue, KitPiece, PassphraseCost, PieceHome};
use oneiron::store::GateDecisionId;
use oneiron::test_support::bind_host_owner;
use oneiron::verbs::{RootRequestCreateRequest, create_root_request_as};
use oneiron::world_keys::{IssuedWorldKit, KitPasskey, RecoveryPreset};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::test_doors::root_work_answer as doors;
use zeroize::Zeroizing;

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// A self-hosted vault whose host seed this install holds in its keystore.
struct SelfHosted {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    person: EntityId,
    machine: EntityId,
    vault_id: [u8; 32],
    held: BTreeSet<Vec<u8>>,
}

fn self_hosted() -> SelfHosted {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let machine = vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("the host seed");
    vault.ensure_host_root_slip(&issuer).expect("the host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machines");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    SelfHosted {
        _dir: dir,
        vault,
        issuer,
        person,
        machine,
        vault_id,
        held: BTreeSet::new(),
    }
}

impl SelfHosted {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    fn authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner(), ActSurface::ThisInstall)
    }

    fn issue(&self) -> IssuedWorldKit {
        self.vault
            .issue_world_kit(
                &self.owner(),
                &KitIssue {
                    vault_id: self.vault_id,
                    homes: [
                        PieceHome::RecoveryCode(CodeKeeping::Paper),
                        PieceHome::TrustedPerson,
                        PieceHome::SecurityKey,
                    ],
                    passphrase: None,
                    cost: PassphraseCost::FLOOR,
                    only_machine: false,
                },
            )
            .expect("a kit")
    }
}

/// A self-hosted vault under "Nobody but me": its data key held, the preset
/// entered the way `recovery_preset_nobody_but_me` enters it.
fn nobody_but_me() -> SelfHosted {
    let fixture = self_hosted();
    fixture
        .vault
        .ensure_vault_key()
        .expect("the vault data key");
    fixture
        .vault
        .set_recovery_preset_as(&fixture.owner(), RecoveryPreset::NobodyButMe, |_| Ok(()))
        .expect("the owner enters Nobody but me");
    fixture
}

/// A self-hosted vault under "Nobody but me, any 2 pieces", the other
/// "Nobody but me" preset: entered from "Nobody but me" with its own kit,
/// the way `recovery_preset_nobody_but_me` enters it.
fn any_two_pieces() -> SelfHosted {
    let fixture = nobody_but_me();
    let prf = Zeroizing::new([6u8; 32]);
    let switched = fixture
        .vault
        .set_recovery_preset_any_two_as(
            &fixture.owner(),
            &KitIssue {
                vault_id: fixture.vault.vault_key_vault_id(),
                homes: [
                    PieceHome::RecoveryCode(CodeKeeping::Paper),
                    PieceHome::Passkey,
                    PieceHome::TrustedPerson,
                ],
                passphrase: None,
                cost: PassphraseCost::DEFAULT,
                only_machine: false,
            },
            Some(KitPasskey {
                credential: "phone",
                prf: &prf,
            }),
            |_| Ok(()),
        )
        .expect("the owner turns on any 2 pieces");
    assert_eq!(
        switched.change.preset,
        RecoveryPreset::NobodyButMeAnyTwo,
        "the vault is under any 2 pieces"
    );
    fixture
}

/// The owner's second install, enrolled as the owner's: it takes the vault's
/// authority history from the first install, as sync does.
struct SecondInstall {
    _dir: tempfile::TempDir,
    vault: Vault,
    machine: EntityId,
    person: EntityId,
    held: BTreeSet<Vec<u8>>,
}

impl SecondInstall {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    fn authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner(), ActSurface::ThisInstall)
    }
}

/// The rows of `giver`'s history `taker` does not hold yet land there.
fn take(taker: &Vault, held: &mut BTreeSet<Vec<u8>>, giver: &Vault) {
    held.extend(
        taker
            .export_signed_authority_history()
            .expect("the taker's history"),
    );
    let new: Vec<Vec<u8>> = giver
        .export_signed_authority_history()
        .expect("the giver's history")
        .into_iter()
        .filter(|row| !held.contains(row))
        .collect();
    taker
        .import_signed_authority_history(&new)
        .expect("the take lands");
    held.extend(new);
}

fn second_install(first: &SelfHosted) -> SecondInstall {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the second install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = vault
        .machine_encryption_key(first.vault_id)
        .expect("the second install's encryption key");
    let request = vault
        .machine_enrolment_request(first.vault_id, key)
        .expect("the second install's enrolment request");
    first
        .vault
        .enroll_machine(
            &first.owner(),
            ActSurface::HostedConsole,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the second install as the owner's");
    let person = vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the second install");
    let mut second = SecondInstall {
        _dir: dir,
        vault,
        machine: request.machine,
        person,
        held: BTreeSet::new(),
    };
    take(&second.vault, &mut second.held, &first.vault);
    second
}

/// R's live enrolled rows: kind `RecoveryAuthority`, live.
fn live_recovery_authority(vault: &Vault) -> Vec<EnrolledOwnerKey> {
    vault
        .enrolled_owner_keys()
        .expect("the list")
        .into_iter()
        .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
        .collect()
}

fn bytes32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "64 hex digits: {hex}");
    let mut out = [0u8; 32];
    for (at, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).expect("hex");
    }
    out
}

/// The Ed25519 public key R's seed derives.
fn authority_public_key(seed_hex: &str) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&bytes32(seed_hex))
        .verifying_key()
        .to_bytes()
}

/// The answer confirms the kit and carries the box deposit once: the label,
/// the root, a 64 lowercase hex seed that is R's live row, named nowhere
/// else in the answer. Hands the seed hex back.
fn assert_deposit_once(answer: &serde_json::Value, vault: &Vault) -> String {
    assert_eq!(
        answer["done"], "kit_confirmed",
        "the answer confirms: {answer}"
    );
    let deposit = answer
        .get("box_deposit")
        .expect("the answer carries the box deposit");
    assert_eq!(
        deposit["label"], "recovery-authority",
        "the box's label: {answer}"
    );
    assert_eq!(
        deposit["source_root"], answer["root"],
        "the deposit binds the live root: {answer}"
    );
    let seed_hex = deposit["seed_hex"]
        .as_str()
        .expect("seed_hex is a string")
        .to_owned();
    assert_eq!(seed_hex.len(), 64, "64 hex digits: {seed_hex}");
    assert!(
        seed_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "lowercase hex: {seed_hex}"
    );
    assert!(
        seed_hex.bytes().any(|byte| byte != b'0'),
        "the seed is not all zero"
    );
    let live = live_recovery_authority(vault);
    assert_eq!(live.len(), 1, "one live R");
    assert_eq!(
        authority_public_key(&seed_hex),
        live[0].public_key,
        "the deposit's seed is R's"
    );
    let text = serde_json::to_string(answer).expect("the answer serializes");
    assert_eq!(
        text.matches(seed_hex.as_str()).count(),
        1,
        "the seed is named once in the answer"
    );
    assert!(
        !answer["text"]
            .as_str()
            .expect("the answer's words")
            .contains(seed_hex.as_str()),
        "the words name no seed"
    );
    seed_hex
}

fn confirm_codes(issued: &IssuedWorldKit) -> Vec<String> {
    issued
        .pieces
        .iter()
        .take(2)
        .map(|piece| piece.recovery_code().reveal().to_owned())
        .collect()
}

#[test]
fn the_confirm_answer_carries_the_box_deposit_once() {
    let fixture = self_hosted();
    let issued = fixture.issue();
    let answer = doors::confirm_answer_json(
        &fixture.vault,
        &fixture.authority(),
        serde_json::json!({
            "target": fixture.machine.to_hex(),
            "pieces": confirm_codes(&issued),
        }),
    )
    .expect("the confirm answers");
    assert_deposit_once(&answer, &fixture.vault);
}

#[test]
fn the_run_answer_carries_the_box_deposit_once() {
    // A root change's target is never the install the owner asked on
    // (`TargetIsRecorder`), so the activate request is recorded on the first
    // install for the second, which runs it.
    let mut first = self_hosted();
    let mut second = second_install(&first);
    // The second install's predecessor for R: its own device key, enrolled
    // with the vault's live host root signing.
    second
        .vault
        .enrol_device_owner_signing_key(&second.authority(), &first.issuer)
        .expect("the owner enrols the second install's device key");
    take(&first.vault, &mut first.held, &second.vault);
    let created = create_root_request_as(
        &first.vault,
        &first.owner(),
        ActSurface::ThisInstall,
        RootRequestCreateRequest {
            target: second.machine.to_hex(),
            change: "activate".to_owned(),
            root: None,
            machine: None,
            check_in_ref: None,
        },
    )
    .expect("the activate request");
    let request = created
        .receipt
        .request
        .clone()
        .expect("the request is recorded for the second install");
    take(&second.vault, &mut second.held, &first.vault);

    let authority = second.authority();
    let target = second.machine.to_hex();
    let issued = doors::run_answer_json(
        &second.vault,
        &authority,
        serde_json::json!({
            "target": target.clone(),
            "request": request.clone(),
            "material": {
                "kind": "issue_kit",
                "homes": [{"recovery_code": "paper"}, "trusted_person", "security_key"],
            },
        }),
    )
    .expect("the issue runs");
    assert_eq!(issued["done"], "kit_issued", "the run issues: {issued}");
    let codes: Vec<String> = issued["pieces"]
        .as_array()
        .expect("the issued pieces")
        .iter()
        .take(2)
        .map(|piece| {
            piece["recovery_code"]
                .as_str()
                .expect("a recovery code")
                .to_owned()
        })
        .collect();
    let answer = doors::run_answer_json(
        &second.vault,
        &authority,
        serde_json::json!({
            "target": target,
            "request": request,
            "material": {"kind": "confirm_kit", "pieces": codes},
        }),
    )
    .expect("the confirm runs");
    assert_deposit_once(&answer, &second.vault);
}

#[test]
fn under_nobody_but_me_the_confirm_answer_has_no_box_deposit() {
    confirm_answer_has_no_box_deposit(&nobody_but_me());
}

#[test]
fn under_any_two_pieces_the_confirm_answer_has_no_box_deposit() {
    confirm_answer_has_no_box_deposit(&any_two_pieces());
}

/// The confirm answer of `fixture`, a vault under a "Nobody but me"
/// preset, carries no box deposit.
fn confirm_answer_has_no_box_deposit(fixture: &SelfHosted) {
    let issued = fixture.issue();
    let answer = doors::confirm_answer_json(
        &fixture.vault,
        &fixture.authority(),
        serde_json::json!({
            "target": fixture.machine.to_hex(),
            "pieces": confirm_codes(&issued),
        }),
    )
    .expect("the confirm answers");
    assert_eq!(
        answer["done"], "kit_confirmed",
        "the answer confirms: {answer}"
    );
    assert!(
        answer.get("box_deposit").is_none(),
        "no box deposit under Nobody but me: {answer}"
    );
    let text = serde_json::to_string(&answer).expect("the answer serializes");
    assert!(!text.contains("seed_hex"), "no seed_hex key: {text}");
}

/// What the test subscriber wrote, kept instead of sent anywhere.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("the sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'w> tracing_subscriber::fmt::MakeWriter<'w> for Captured {
    type Writer = Self;

    fn make_writer(&'w self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn the_box_deposit_never_reaches_a_log_line() {
    let fixture = self_hosted();
    let sink = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(sink.clone())
        .finish();
    let seed_hex = tracing::subscriber::with_default(subscriber, || {
        let issued = fixture.issue();
        let answer = doors::confirm_answer_json(
            &fixture.vault,
            &fixture.authority(),
            serde_json::json!({
                "target": fixture.machine.to_hex(),
                "pieces": confirm_codes(&issued),
            }),
        )
        .expect("the confirm answers");
        assert_deposit_once(&answer, &fixture.vault)
    });
    let written = String::from_utf8_lossy(&sink.0.lock().expect("the sink")).into_owned();
    assert!(
        !written.contains(seed_hex.as_str()),
        "the seed reached a log line: {written}"
    );
}

#[test]
fn the_cli_writes_the_box_deposit_only_with_the_flag() {
    // Without the flag: nothing is written anywhere.
    {
        let fixture = self_hosted();
        let temp = tempfile::tempdir().expect("tempdir");
        let issued = fixture.issue();
        let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
        let answer = doors::cli_confirm_json(&fixture.vault, &fixture.owner(), &pieces, None)
            .expect("the CLI confirm answers");
        assert_eq!(
            answer["box_deposit_out"],
            serde_json::Value::Null,
            "no path without the flag: {answer}"
        );
        let text = serde_json::to_string(&answer).expect("the answer serializes");
        assert!(
            !text.contains("seed_hex"),
            "the CLI answer names no seed: {text}"
        );
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("the temp dir")
                .count(),
            0,
            "no file was written"
        );
    }
    // With the flag: the deposit alone is written to the named file.
    {
        let fixture = self_hosted();
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("deposit.json");
        let issued = fixture.issue();
        let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
        let answer = doors::cli_confirm_json(
            &fixture.vault,
            &fixture.owner(),
            &pieces,
            Some(path.as_path()),
        )
        .expect("the CLI confirm answers");
        assert_eq!(
            answer["box_deposit_out"],
            path.display().to_string(),
            "the answer names the path: {answer}"
        );
        let written = std::fs::read_to_string(&path).expect("the deposit file");
        let deposit: serde_json::Value =
            serde_json::from_str(&written).expect("the deposit parses");
        let object = deposit.as_object().expect("an object");
        let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            BTreeSet::from(["label", "seed_hex", "source_root"]),
            "exactly the deposit's keys, no pin"
        );
        assert_eq!(object["label"], "recovery-authority", "the box's label");
        let seed_hex = object["seed_hex"].as_str().expect("seed_hex");
        let live = live_recovery_authority(&fixture.vault);
        assert_eq!(live.len(), 1, "one live R");
        assert_eq!(
            authority_public_key(seed_hex),
            live[0].public_key,
            "the file's seed is R's"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("the deposit file")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the deposit file is owner-only");
        }
    }
}

#[test]
fn the_cli_refuses_an_existing_deposit_file_before_confirming() {
    let fixture = self_hosted();
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("deposit.json");
    std::fs::write(&path, b"held").expect("the held file");
    let issued = fixture.issue();
    let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
    let refused = doors::cli_confirm_json(
        &fixture.vault,
        &fixture.owner(),
        &pieces,
        Some(path.as_path()),
    )
    .expect_err("an existing deposit file refuses the confirm");
    assert!(
        refused.to_string().contains("exists"),
        "the refusal names the held file: {refused}"
    );
    assert!(
        live_recovery_authority(&fixture.vault).is_empty(),
        "the kit is still unconfirmed"
    );
}

#[test]
fn under_nobody_but_me_the_cli_writes_no_deposit_file() {
    cli_writes_no_deposit_file(&nobody_but_me());
}

#[test]
fn under_any_two_pieces_the_cli_writes_no_deposit_file() {
    cli_writes_no_deposit_file(&any_two_pieces());
}

/// The CLI confirm on `fixture`, a vault under a "Nobody but me" preset,
/// writes no deposit file and answers no path.
fn cli_writes_no_deposit_file(fixture: &SelfHosted) {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("deposit.json");
    let issued = fixture.issue();
    let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
    let answer = doors::cli_confirm_json(
        &fixture.vault,
        &fixture.owner(),
        &pieces,
        Some(path.as_path()),
    )
    .expect("the CLI confirm answers");
    assert_eq!(
        answer["box_deposit_out"],
        serde_json::Value::Null,
        "no path under Nobody but me: {answer}"
    );
    assert!(!path.exists(), "no deposit file under Nobody but me");
}
