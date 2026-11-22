//! The owner's yes to a pack's waiting proposal reads before it asks (row OWNER-CONFIRM-SHEET,
//! PR 4b-3c2b): a yes the door's own checks refuse raises no prompt, and a yes that passes them
//! asks as an important act.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test owner_presence_pack_defaults_accept`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::{ActAuthority, ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{DevicePinRefusal, GateError, OwnerPresenceRefusal, RecordError, SecretError};
use oneiron::memory::Memory;
use oneiron::recovery::PassphraseCost;
use oneiron::setting::{ENGINE_PACK, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{
    apply_pack_defaults, plant_pack_head_digest, plant_undecodable_row,
};
use oneiron::world_keys::DevicePin;
use oneiron::{EdgeActorClass, EntityId, Error, Vault, VaultConfig};
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, PresenceError, PresenceGate, PresenceWindow,
    ScriptedPresence,
};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const LIST: &str = "vault.settings.list";
const T0: u64 = 1_790_000_000;
/// An ordered test key whose build default is 10: a higher cap is looser, so a raised default
/// waits for the owner's yes.
const CAP: &str = "test.ordered_cap";
/// The reason line the door shows, as the engine's constant holds it: the test asserts it
/// literally, since that constant is crate-private.
const ACCEPT_PACK_DEFAULTS_REASON: &str = "accept new default settings";
/// The device PIN: a passphrase, since nothing counts wrong tries but this process.
const PIN: &[u8] = b"quiet harbour lantern";

/// A rooted vault with its install enrolled and its embedded owner authenticated, opened owned,
/// as `tests/setting_packs.rs` opens one; or one whose install has no live machine profile, as
/// `tests/setting_act_write.rs` opens one. The vault drops before its directory.
struct Fixture {
    vault: Vault,
    keystore: Arc<MemoryKeystore>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    _clock: Arc<ManualClock>,
    _issuer: HostSlipIssuer,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A root, and this install carries the owner's acts.
    fn rooted() -> Self {
        Self::open(true)
    }

    /// A root, and no live machine profile of this install to carry an act.
    fn rooted_without_carrier() -> Self {
        Self::open(false)
    }

    fn open(carries: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        if carries {
            vault
                .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
                .expect("serving install profile");
        }
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            keystore,
            owner,
            owner_proof,
            _clock: clock,
            _issuer: issuer,
            _dir: dir,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The pack door over a raised cap, as an update of the engine pack: the looser default
    /// waits. Answers the waiting proposal's digest.
    fn propose_cap(&self, cap: u64) -> String {
        let applied = apply_pack_defaults(&self.vault, ENGINE_PACK, &[(CAP, json!(cap))])
            .expect("the pack door runs")
            .expect("the defaults are new to the head");
        assert_eq!(
            applied.proposed,
            vec![CAP.to_owned()],
            "a looser default waits"
        );
        self.waiting().expect("a waiting proposal")
    }

    /// The digest of the proposal in which a default of the cap waits, if one does.
    fn waiting(&self) -> Option<String> {
        let listed = call(&self.as_owner(), LIST, json!({ "prefix": CAP }));
        let entry = listed["keys"]
            .as_array()
            .expect("the list's keys")
            .iter()
            .find(|entry| entry["key"] == CAP)
            .expect("the list names the cap");
        entry["proposed_default"]["proposal"]
            .as_str()
            .map(str::to_owned)
    }

    /// The cap a read answers.
    fn cap(&self) -> Value {
        call(&self.as_owner(), GET, json!({ "key": CAP }))["value"].clone()
    }

    /// The owner's yes to `pack`'s proposal `proposal`, at the door.
    fn accept(&self, pack: &str, proposal: &str) -> oneiron::Result<Vec<String>> {
        self.vault
            .accept_pack_defaults(&self.owner_proof, pack, proposal)
    }
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

/// A scripted device prompt on `vault`: `answers` in order, a prompt past the script declined.
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

/// Whether `answer` is an `InvalidConfig` refusal whose words hold `words`.
fn refused_as<T>(answer: &oneiron::Result<T>, words: &str) -> bool {
    matches!(answer, Err(Error::InvalidConfig(reason)) if reason.contains(words))
}

/// A yes the door's own checks refuse raises no prompt and changes nothing: a pack with no
/// head, a proposal that is not the pack's waiting one, another vault's owner proof. The yes to
/// the waiting proposal passes the same read, and it asks.
#[test]
fn a_yes_the_read_refuses_raises_no_prompt() {
    let fx = Fixture::rooted();
    let other = Fixture::rooted();
    let proposal = fx.propose_cap(20);
    let presence = scripted_gate(&fx.vault, []);
    let no_head = fx.accept("a-pack-with-no-head", &proposal);
    assert!(
        refused_as(&no_head, "no pack named"),
        "a pack with no head is refused as that: {no_head:?}"
    );
    let not_waiting = fx.accept(ENGINE_PACK, &"0".repeat(64));
    assert!(
        refused_as(&not_waiting, "no waiting proposal"),
        "a proposal that is not waiting is refused as that: {not_waiting:?}"
    );
    let anothers = fx
        .vault
        .accept_pack_defaults(&other.owner_proof, ENGINE_PACK, &proposal);
    assert!(
        matches!(
            anothers,
            Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
        ),
        "another vault's owner proof is refused: {anothers:?}"
    );
    assert_eq!(presence.prompts(), 0, "no refusal showed a prompt");
    assert_eq!(
        fx.waiting(),
        Some(proposal.clone()),
        "the proposal still waits"
    );
    assert_eq!(fx.cap(), json!(10), "every read is as it was");
    // The yes to the waiting proposal passes the read, and it asks.
    let asked = fx.accept(ENGINE_PACK, &proposal);
    assert!(
        matches!(
            asked,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a yes that passes the read asks: {asked:?}"
    );
    assert_eq!(
        presence.reasons(),
        [ACCEPT_PACK_DEFAULTS_REASON],
        "that yes showed one prompt, with the door's line"
    );
    assert_eq!(
        fx.waiting(),
        Some(proposal),
        "a declined confirm leaves the proposal waiting"
    );
    assert_eq!(fx.cap(), json!(10), "a declined confirm lands nothing");
}

/// A yes over a row that moved since the proposal is refused on the read, with no prompt.
#[test]
fn a_yes_over_a_row_that_moved_raises_no_prompt() {
    let fx = Fixture::rooted();
    let proposal = fx.propose_cap(20);
    plant_undecodable_row(&fx.vault, CAP, SettingScope::Pack(ENGINE_PACK.to_owned()))
        .expect("a damaged layer row");
    let presence = scripted_gate(&fx.vault, []);
    let moved = fx.accept(ENGINE_PACK, &proposal);
    assert!(
        refused_as(&moved, "moved since proposal"),
        "a row that moved is refused as that: {moved:?}"
    );
    assert_eq!(presence.prompts(), 0, "the refusal showed no prompt");
}

/// A yes on an install that cannot carry the owner's act is refused on the read as the append
/// refuses it, with no prompt. The same yes on an install that carries the act asks.
#[test]
fn a_yes_on_an_install_that_cannot_carry_the_act_raises_no_prompt() {
    let fx = Fixture::rooted_without_carrier();
    let proposal = fx.propose_cap(20);
    let presence = scripted_gate(&fx.vault, []);
    let refused = fx.accept(ENGINE_PACK, &proposal);
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::AuthorityRefused(reason)))
                if reason.contains("no live machine profile")
        ),
        "an install that cannot carry the act refuses the yes as the append does: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the refusal showed no prompt");
    assert_eq!(
        fx.waiting(),
        Some(proposal),
        "the refused yes leaves the proposal waiting"
    );
    assert_eq!(fx.cap(), json!(10), "the refused yes lands nothing");
    // The control: the same yes on an install that carries the act passes the read, and asks.
    let carrying = Fixture::rooted();
    let proposal = carrying.propose_cap(20);
    let presence = scripted_gate(&carrying.vault, []);
    let asked = carrying.accept(ENGINE_PACK, &proposal);
    assert!(
        matches!(
            asked,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a yes on an install that carries the act asks: {asked:?}"
    );
    assert_eq!(presence.prompts(), 1, "that yes showed one prompt");
}

/// A yes to a head whose digest a damaged store holds is refused on the read, with no prompt.
#[test]
fn a_yes_to_a_head_with_a_damaged_digest_raises_no_prompt() {
    let fx = Fixture::rooted();
    let proposal = fx.propose_cap(20);
    plant_pack_head_digest(&fx.vault, ENGINE_PACK, "not sixty-four hex digits")
        .expect("a damaged head digest");
    let presence = scripted_gate(&fx.vault, []);
    let damaged = fx.accept(ENGINE_PACK, &proposal);
    assert!(
        matches!(damaged, Err(Error::CorruptedIndex(_))),
        "a head digest that does not decode is refused as a damaged store: {damaged:?}"
    );
    assert_eq!(presence.prompts(), 0, "the refusal showed no prompt");
}

/// A confirmed yes lands its default after one prompt, and the proposal closes.
#[test]
fn a_confirmed_yes_lands_after_one_prompt() {
    let fx = Fixture::rooted();
    let proposal = fx.propose_cap(20);
    let presence = scripted_gate(&fx.vault, [Ok(())]);
    let keys = fx
        .accept(ENGINE_PACK, &proposal)
        .expect("the confirmed yes lands");
    assert_eq!(keys, vec![CAP.to_owned()]);
    assert_eq!(
        presence.reasons(),
        [ACCEPT_PACK_DEFAULTS_REASON],
        "the yes showed one prompt, with the door's line"
    );
    assert_eq!(fx.cap(), json!(20), "the default landed");
    assert_eq!(fx.waiting(), None, "the proposal closed");
    let again = fx.accept(ENGINE_PACK, &proposal);
    assert!(
        refused_as(&again, "no waiting proposal"),
        "a second yes finds no waiting proposal: {again:?}"
    );
}

/// On a device whose PIN window ended, a yes the read refuses answers that refusal, and a yes
/// that passes the read answers PIN required and lands nothing.
#[test]
fn a_yes_on_a_device_whose_pin_window_ended() {
    let fx = Fixture::rooted();
    let proposal = fx.propose_cap(20);
    let pin = DevicePin::with_clock_and_cost(
        fx.keystore.clone(),
        ManualPresenceClock::new(1_000_000, 1_000_000),
        PassphraseCost::FLOOR,
    )
    .expect("device PIN over the vault's keystore");
    fx.vault
        .install_device_pin(pin.clone())
        .expect("install device PIN");
    fx.vault
        .set_device_pin_as(
            &ActAuthority::Owner(fx.owner_proof.clone(), ActSurface::ThisInstall),
            PIN,
            false,
        )
        .expect("set the device PIN as the owner");
    pin.end_window();
    let not_waiting = fx.accept(ENGINE_PACK, &"0".repeat(64));
    assert!(
        refused_as(&not_waiting, "no waiting proposal"),
        "a yes the read refuses answers that refusal, not the PIN's: {not_waiting:?}"
    );
    let required = fx.accept(ENGINE_PACK, &proposal);
    assert!(
        matches!(
            required,
            Err(Error::Secret(SecretError::DevicePin(
                DevicePinRefusal::Required
            )))
        ),
        "a yes that passes the read answers PIN required: {required:?}"
    );
    assert_eq!(
        fx.waiting(),
        Some(proposal),
        "the refused yes leaves the proposal waiting"
    );
    assert_eq!(fx.cap(), json!(10), "the refused yes lands nothing");
}
