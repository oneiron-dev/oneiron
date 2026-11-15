//! The owner's two widen-proposal keys (restriction census C26, C62, C72; owner principle
//! 16 Nov 00:44: a restriction that is not a correctness fix ships as a good default plus an
//! owner opt-out). Each default is today's behaviour:
//! - `consent.widen.max_open_secs` (one hour): the longest a widen proposal may stay open for the
//!   owner's answer. A longer window admits a later expiry, the row reads back, and the engine's
//!   own offer for a person's first entry into a room stays open that long. Zero and anything
//!   past thirty days are refused.
//! - `consent.widen.member_proposals` (off): a member's human credential that lists a
//!   `propose_*_widen` verb files a proposal as an agent's does. The owner still settles it.
//!
//! `cargo test --locked -p oneiron --all-features --test consent_widen_setting_keys`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole, VerifiedSlip};
use oneiron::consent::widen::WidenProposal;
use oneiron::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const MAX_OPEN: &str = "consent.widen.max_open_secs";
const MEMBER_PROPOSALS: &str = "consent.widen.member_proposals";
const PROPOSE_ACTION: &str = "propose_action_widen";
const TWO_HOURS: u64 = 7_200;
const THIRTY_DAYS: u64 = 30 * 24 * 3_600;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, on a still clock.
    fn rooted() -> Self {
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
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            issuer,
            owner,
            owner_proof,
        }
    }

    /// The owner sets `key` at the vault scope.
    fn set_as_owner(&self, key: &str, value: Value) -> oneiron::Result<SetSettingOutcome> {
        self.vault.set_setting(
            SettingCaller::Owner(&self.owner_proof),
            SetSetting {
                key: key.to_owned(),
                item: None,
                scope: SettingScope::Vault,
                mode: SettingMode::Value,
                value: Some(value),
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        )
    }

    /// A PERSON row for an agent or a member to hold a credential as.
    fn person(&self) -> EntityId {
        let id = EntityId::now();
        let now = self.vault.now_recorded_at();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"person",
            )
            .expect("person row");
        id
    }

    /// A verified, reusable credential of `holder` under `actor_class` that lists only
    /// `propose_action_widen`, minted by the host as a client holds it.
    fn credential(&self, holder: EntityId, actor_class: &str, slip_byte: u8) -> VerifiedSlip {
        let root = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("host root slip");
        let issued_at = self.vault.capability_slip_now().expect("authority clock");
        let mut claims = root.claims.clone();
        claims.slip_id = [slip_byte; 32];
        claims.holder_ref = holder.to_hex();
        claims.actor_class = Some(actor_class.to_owned());
        claims.issued_at = issued_at;
        claims.expires_at = issued_at + 3_600;
        claims.ttl_secs = 3_600;
        claims.single_use = false;
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from([PROPOSE_ACTION.to_owned()]));
        claims.scope = scope;
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the host mints the credential");
        let challenge = b"consent-widen-setting-keys";
        let proof = self
            .issuer
            .binding_proof(&slip, challenge)
            .expect("binding proof");
        self.vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &proof)
            .expect("verified credential")
    }

    /// `holder`'s action widening for `claim.put` in the home world, open until `expires_at`.
    fn propose(
        &self,
        credential: &VerifiedSlip,
        holder: EntityId,
        expires_at: u64,
    ) -> oneiron::Result<WidenProposal> {
        let bound = GrantBound::action(
            ActorBound::new(holder.to_hex()).expect("actor bound"),
            ActionClass::new("claim.put").expect("action class"),
            ActionEnvelope::new(["world:home".to_owned()]).expect("action envelope"),
        )
        .expect("action bound");
        self.vault
            .propose_action_widen(credential, bound, &self.owner.to_hex(), expires_at)
    }

    /// The engine's offer for a new contact's first entry into a fresh room.
    fn entry_offer(&self) -> WidenProposal {
        let person = self.person();
        let contact = EntityId::now();
        let now = self.vault.now_recorded_at();
        self.vault
            .create_counterparty_contact(
                &contact,
                &CounterpartyContactRecord::public(person, "entrant@example.com", now)
                    .expect("contact record"),
            )
            .expect("contact");
        self.vault
            .file_person_entry_disclosure_offer(
                contact,
                &EntityId::now(),
                Scope::top(),
                &self.owner.to_hex(),
            )
            .expect("the entry offer files")
            .expect("an uncleared contact is asked about")
    }
}

/// How long `proposal` stays open.
fn open_secs(proposal: &WidenProposal) -> u64 {
    proposal.expires_at - proposal.created_at
}

/// Red before the key exists: the owner's two-hour window admits a two-hour proposal, and the
/// stored row reads back with its own two-hour window.
#[test]
fn the_owner_window_admits_a_longer_proposal_and_the_row_reads_back() {
    let fixture = Fixture::rooted();
    let agent = fixture.person();
    let credential = fixture.credential(agent, "agent", 0x51);
    fixture
        .set_as_owner(MAX_OPEN, json!(TWO_HOURS))
        .expect("the owner sets a two-hour window");
    let proposal = fixture
        .propose(&credential, agent, T0 + TWO_HOURS)
        .expect("a two-hour proposal files under a two-hour window");
    assert_eq!(open_secs(&proposal), TWO_HOURS);
    let stored = fixture
        .vault
        .widen_proposal(&proposal.proposal_ref)
        .expect("the row decodes")
        .expect("the row stands");
    assert_eq!(stored, proposal, "the row reads back as filed");
    assert!(
        fixture
            .propose(&credential, agent, T0 + TWO_HOURS + 1)
            .is_err(),
        "a proposal past the owner's window is still refused"
    );
}

/// Red before the key exists: the engine's room-entry offer stays open for the owner's window.
#[test]
fn the_entry_offer_stays_open_for_the_owner_window() {
    let fixture = Fixture::rooted();
    fixture
        .set_as_owner(MAX_OPEN, json!(TWO_HOURS))
        .expect("the owner sets a two-hour window");
    let offer = fixture.entry_offer();
    assert_eq!(open_secs(&offer), TWO_HOURS);
}

/// Red before the key exists: with member proposals on, a member's human credential files a
/// proposal under its own name, the owner settles it, and turning the key off refuses the next.
#[test]
fn a_member_files_a_widen_proposal_while_the_owner_allows_it() {
    let fixture = Fixture::rooted();
    let member = fixture.person();
    let credential = fixture.credential(member, "human", 0x52);
    fixture
        .set_as_owner(MEMBER_PROPOSALS, json!(true))
        .expect("the owner turns member proposals on");
    let proposal = fixture
        .propose(&credential, member, T0 + 600)
        .expect("the member's proposal files");
    assert_eq!(proposal.proposer, member.to_hex());
    fixture
        .vault
        .accept_widen(
            &fixture.owner_proof,
            &proposal.proposal_ref,
            &proposal.canonical_delta,
        )
        .expect("the owner settles the member's proposal");
    fixture
        .set_as_owner(MEMBER_PROPOSALS, json!(false))
        .expect("the owner turns member proposals off");
    let refused = fixture
        .propose(&credential, member, T0 + 900)
        .expect_err("a member's proposal is refused once the key is off");
    assert!(
        format!("{refused:?}").contains("lacks widen proposal authority"),
        "{refused:?}"
    );
}

/// Red before the key exists (its last set): the window refuses zero and anything past thirty
/// days, and takes thirty days.
#[test]
fn the_window_takes_one_second_to_thirty_days() {
    let fixture = Fixture::rooted();
    assert!(fixture.set_as_owner(MAX_OPEN, json!(0)).is_err());
    assert!(
        fixture
            .set_as_owner(MAX_OPEN, json!(THIRTY_DAYS + 1))
            .is_err()
    );
    fixture
        .set_as_owner(MAX_OPEN, json!(THIRTY_DAYS))
        .expect("thirty days is the longest window");
}

/// Guard, green on both sides: unset, the window is one hour, for a proposal and for the entry
/// offer.
#[test]
fn the_default_window_is_one_hour() {
    let fixture = Fixture::rooted();
    let agent = fixture.person();
    let credential = fixture.credential(agent, "agent", 0x53);
    let refused = fixture
        .propose(&credential, agent, T0 + 3_601)
        .expect_err("a proposal past one hour is refused");
    assert!(
        format!("{refused:?}").contains("InvalidConsentBound"),
        "{refused:?}"
    );
    let proposal = fixture
        .propose(&credential, agent, T0 + 3_600)
        .expect("a one-hour proposal files");
    assert_eq!(open_secs(&proposal), 3_600);
    assert_eq!(open_secs(&fixture.entry_offer()), 3_600);
}

/// Guard, green on both sides: unset, a member's human credential is refused and an agent's
/// still files.
#[test]
fn a_member_proposal_is_refused_by_default() {
    let fixture = Fixture::rooted();
    let member = fixture.person();
    let member_credential = fixture.credential(member, "human", 0x54);
    let refused = fixture
        .propose(&member_credential, member, T0 + 600)
        .expect_err("a member's proposal is refused");
    assert!(
        format!("{refused:?}").contains("lacks widen proposal authority"),
        "{refused:?}"
    );
    let agent = fixture.person();
    let agent_credential = fixture.credential(agent, "agent", 0x55);
    fixture
        .propose(&agent_credential, agent, T0 + 600)
        .expect("an agent's proposal still files");
}
