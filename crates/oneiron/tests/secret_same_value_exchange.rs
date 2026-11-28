//! SECRETS-SAME-VALUE-FACT (Engine RULINGS SECRETS-LIST-DUP-GROUPING = A, SECRET-SAMEFACT-HOST-SEES
//! = B and SECRET-SAMEFACT-SEAL-RECIPIENTS = A, Mon 16 Nov): a machine of the owner's that holds no
//! copy of a value lists the two records another of his machines proves hold it as one item.
//!
//! The writer derives the pairs its own records prove (matching current-generation known-value
//! entries), seals them to each machine mine here and signs the statement with its machine key; it
//! travels through the residence home (`residence.secret_same_value.exchange`), and each machine
//! takes it only when its own fold admits the writer's signature, opening the envelope sealed to it.
//!
//! Nodes of one vault: a hosted home (never mine, so never a recipient), a laptop that registers
//! the secrets, a phone that holds no copy, and in one case a tablet the owner removes. Each node is
//! its own install, enrolled as the owner's (`machine_names_exchange.rs`'s fixture). A pass runs the
//! two halves the RPC joins: the machine's (a door) and the home's
//! (`secret_same_value_residence_exchange`, which the server arm calls with the socket's
//! `PeerMachine`).
//!
//! Red pin: the head with one fault commit that keeps every type and door and cuts the behaviour
//! (no pair derived, no statement taken, the list ignores pairs).
//!
//! Run: RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features \
//!   --test secret_same_value_exchange
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole, PeerMachine};
use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding, SameValueStatement,
};
use oneiron::store::GateDecisionId;
use oneiron::sync::residence::secret_same_value_residence_exchange;
use oneiron::test_doors::secret_same_value::{
    holds_statement_from, opened_pair, recipients, signed_again_by, statements_to_send,
    take_answer, with_altered_envelope, writer,
};
use oneiron::test_support::bind_host_owner;
use oneiron::{EntityId, Vault, VaultConfig};

const NOW: u64 = 1_700_000_000;
/// The one value the laptop holds twice, under two names.
const SHARED: &[u8] = b"sk-samefact-0123456789abcdef0123456789abcdef";
/// A value of its own.
const OTHER: &[u8] = b"sk-samefact-fedcba9876543210fedcba9876543210";
/// The value b takes when the owner rotates it: no other record holds it.
const ROTATED: &[u8] = b"sk-samefact-00112233445566778899aabbccddeeff";

/// A fresh owner proof minted on `vault`'s own handle.
fn proof(vault: &Vault) -> AuthenticatedOwner {
    let person = vault
        .ensure_embedded_owner_actor()
        .expect("the owner on this node");
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// The vault's home: a hosted node, rooted, carrying the owner's acts.
struct Home {
    _dir: tempfile::TempDir,
    vault: Vault,
    _issuer: HostSlipIssuer,
    vault_id: [u8; 32],
    held: BTreeSet<Vec<u8>>,
}

fn home() -> Home {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the home's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("the hosted node's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let vault_id = vault
        .authority_fold()
        .expect("the home's fold")
        .vault_id
        .expect("a rooted vault");
    Home {
        _dir: dir,
        vault,
        _issuer: issuer,
        vault_id,
        held: BTreeSet::new(),
    }
}

impl Home {
    /// Imports the rows of `node`'s history this home does not hold yet, as the authority
    /// residence RPCs bring a machine's acts home.
    fn take(&mut self, node: &Node) {
        let own: BTreeSet<Vec<u8>> = self
            .vault
            .export_signed_authority_history()
            .expect("the home's history")
            .into_iter()
            .collect();
        self.held.extend(own);
        let new: Vec<Vec<u8>> = node
            .vault
            .export_signed_authority_history()
            .expect("the node's history")
            .into_iter()
            .filter(|row| !self.held.contains(row))
            .collect();
        self.vault
            .import_signed_authority_history(&new, &std::collections::BTreeMap::new())
            .expect("the home takes the node's rows");
        self.held.extend(new);
    }
}

/// One of the owner's machines: its own install, enrolled as his, taking the vault's authority
/// history from the home as sync does.
struct Node {
    _dir: tempfile::TempDir,
    vault: Vault,
    machine: EntityId,
    key: [u8; 32],
    held: BTreeSet<Vec<u8>>,
}

fn node(home: &Home) -> Node {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the node's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = vault
        .machine_encryption_key(home.vault_id)
        .expect("the node's encryption key");
    let request = vault
        .machine_enrolment_request(home.vault_id, key)
        .expect("the node's enrolment request");
    home.vault
        .enroll_machine(
            &proof(&home.vault),
            ActSurface::HostedConsole,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the node as his");
    vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the node");
    let mut node = Node {
        _dir: dir,
        vault,
        machine: request.machine,
        key: request.machine_key,
        held: BTreeSet::new(),
    };
    node.take(home);
    node
}

impl Node {
    /// Imports the rows of the home's history this node does not hold yet.
    fn take(&mut self, home: &Home) {
        let new: Vec<Vec<u8>> = home
            .vault
            .export_signed_authority_history()
            .expect("the home's history")
            .into_iter()
            .filter(|row| !self.held.contains(row))
            .collect();
        self.vault
            .import_signed_authority_history(&new, &std::collections::BTreeMap::new())
            .expect("the node takes the rows");
        self.held.extend(new);
    }

    /// This node as its socket proves it to the home.
    fn proven(&self) -> PeerMachine {
        PeerMachine::Proven {
            machine: self.machine,
            key: self.key,
        }
    }

    /// One steady pass's exchange with the home: how many statements changed here.
    fn pass(&self, home: &Home) -> usize {
        let statements = statements_to_send(&self.vault)
            .expect("the node's statement")
            .expect("the node serves its machine");
        let answer = secret_same_value_residence_exchange(&home.vault, self.proven(), statements)
            .expect("the home answers a machine of the owner's");
        take_answer(&self.vault, answer).expect("the node takes the home's statements")
    }

    /// Registers `value` as the portable secret `name`, enacted here in the same commit.
    fn register(&self, name: &str, value: &[u8], at: u64) -> EntityId {
        let registered = self
            .vault
            .register_secret_as_owner(
                &proof(&self.vault),
                &OwnerSecretRegistration {
                    name,
                    class: CustodyClass::CustodyPortable,
                    device_only: false,
                    rung: CustodyTier::T1Leased,
                    bindings: vec![RequestedBinding {
                        effector: "deploy".to_owned(),
                        tier_ceiling: None,
                        scopes: vec!["read".to_owned()],
                    }],
                    manifest: None,
                    value,
                },
                at,
            )
            .expect("the owner registers the secret on this node");
        assert!(
            registered.custody.kept_here.is_none(),
            "the fixture: a rooted vault files the register as owner work"
        );
        registered.secret_id
    }

    /// The records of each item of this node's owner list, as sets.
    fn items(&self) -> Vec<BTreeSet<EntityId>> {
        self.vault
            .secret_custody_list(&proof(&self.vault))
            .expect("the owner's list")
            .items
            .into_iter()
            .map(|item| item.records.into_iter().map(|record| record.id).collect())
            .collect()
    }

    /// This node's own statement, as it would send it now.
    fn statement(&self) -> SameValueStatement {
        statements_to_send(&self.vault)
            .expect("the node's statement")
            .expect("the node serves its machine")
            .into_iter()
            .next()
            .expect("the node states its pairs")
    }
}

/// The items `records` form, as a set of sets, for a comparison that ignores order.
fn grouped(items: &[&[EntityId]]) -> BTreeSet<BTreeSet<EntityId>> {
    items
        .iter()
        .map(|records| records.iter().copied().collect())
        .collect()
}

/// The home, the laptop and the phone, each folding the others; the laptop holds `a` and `b` of
/// one value and `c` of another, and the home and the phone hold the laptop's acts.
struct Three {
    home: Home,
    laptop: Node,
    phone: Node,
    a: EntityId,
    b: EntityId,
    c: EntityId,
}

fn three() -> Three {
    let mut home = home();
    let mut laptop = node(&home);
    let mut phone = node(&home);
    laptop.take(&home);
    let a = laptop.register("laptop-a", SHARED, NOW);
    let b = laptop.register("laptop-b", SHARED, NOW + 1);
    let c = laptop.register("laptop-c", OTHER, NOW + 2);
    home.take(&laptop);
    phone.take(&home);
    let fold = home.vault.authority_fold().expect("the home's fold");
    for (machine, key) in [(phone.machine, phone.key), (laptop.machine, laptop.key)] {
        assert!(
            fold.trusted_machine(machine).is_some(),
            "the fixture: the home trusts each node as the owner's"
        );
        assert_eq!(
            fold.machine_proof_key(machine),
            Some(key),
            "the fixture: each node proves its enrolment key at the home"
        );
    }
    assert_eq!(
        phone.items().into_iter().collect::<BTreeSet<_>>(),
        grouped(&[&[a], &[b], &[c]]),
        "the fixture: the phone holds no copy, so it lists each of the laptop's records alone"
    );
    Three {
        home,
        laptop,
        phone,
        a,
        b,
        c,
    }
}

#[test]
fn a_machine_holding_no_copy_lists_two_records_of_one_value_as_one_item_after_the_exchange() {
    let t = three();
    assert_eq!(
        t.laptop.items().into_iter().collect::<BTreeSet<_>>(),
        grouped(&[&[t.a, t.b], &[t.c]]),
        "the laptop proves a and b hold one value itself"
    );
    t.laptop.pass(&t.home);
    assert_eq!(
        t.phone.pass(&t.home),
        1,
        "the phone takes the laptop's statement"
    );
    assert!(
        opened_pair(&t.phone.vault, t.laptop.machine, t.a, t.b).expect("the phone's statements"),
        "the envelope sealed to the phone opens to the pair"
    );
    assert_eq!(
        t.phone.items().into_iter().collect::<BTreeSet<_>>(),
        grouped(&[&[t.a, t.b], &[t.c]]),
        "the phone lists a and b as one item, and c, another value, as its own"
    );
}

#[test]
fn the_home_relays_the_statement_and_opens_no_pair() {
    let t = three();
    t.laptop.pass(&t.home);
    let statement = t.laptop.statement();
    assert!(
        holds_statement_from(&t.home.vault, t.laptop.machine).expect("the home's statements"),
        "the home keeps the laptop's statement to relay"
    );
    assert_eq!(recipients(&statement), vec![t.phone.machine]);
    assert!(
        !opened_pair(&t.home.vault, t.laptop.machine, t.a, t.b).expect("the home's statements"),
        "the hosted home, never mine, is no recipient and opens no pair"
    );
    let text = serde_json::to_string(&statement).expect("the statement as it travels");
    for record in [t.a, t.b, t.c] {
        assert!(
            !text.contains(&record.to_hex()),
            "no record id travels in the clear"
        );
    }
    assert_eq!(
        t.home
            .vault
            .secret_custody_list(&proof(&t.home.vault))
            .expect("the home's list")
            .items
            .len(),
        3,
        "the home groups nothing it cannot open"
    );
}

#[test]
fn a_statement_altered_or_signed_again_on_the_way_is_not_taken() {
    let t = three();
    let statement = t.laptop.statement();
    assert_eq!(writer(&statement), t.laptop.machine);
    let altered = with_altered_envelope(&statement);
    assert_eq!(
        take_answer(&t.phone.vault, vec![altered]).expect("the phone takes"),
        0,
        "an altered envelope breaks the writer's signature"
    );
    let signed_again = signed_again_by(&t.phone.vault, &statement).expect("the phone signs");
    assert_eq!(
        take_answer(&t.phone.vault, vec![signed_again]).expect("the phone takes"),
        0,
        "a statement another machine signed in the writer's name is refused"
    );
    assert!(
        !holds_statement_from(&t.phone.vault, t.laptop.machine).expect("the phone's statements"),
        "neither was kept"
    );
    assert_eq!(t.phone.items().len(), 3, "the phone groups nothing on them");
    assert_eq!(
        take_answer(&t.phone.vault, vec![statement]).expect("the phone takes"),
        1,
        "the statement as its writer signed it is taken"
    );
    assert_eq!(t.phone.items().len(), 2);
}

#[test]
fn a_rotation_of_one_record_parts_the_item_again() {
    let mut t = three();
    t.laptop.pass(&t.home);
    t.phone.pass(&t.home);
    assert_eq!(t.phone.items().len(), 2, "the phone groups a and b");
    t.laptop
        .vault
        .rotate_secret_as_owner(&proof(&t.laptop.vault), "laptop-b", ROTATED, NOW + 10)
        .expect("the owner rotates b on the laptop");
    t.home.take(&t.laptop);
    t.phone.take(&t.home);
    assert_eq!(
        t.phone.items().len(),
        3,
        "the pair names b at its old generation, which the phone no longer lists"
    );
    t.laptop.pass(&t.home);
    t.phone.pass(&t.home);
    assert!(
        !opened_pair(&t.phone.vault, t.laptop.machine, t.a, t.b).expect("the phone's statements"),
        "the laptop's next statement names the pair no longer"
    );
    assert_eq!(t.phone.items().len(), 3);
}

#[test]
fn the_home_keeps_only_a_proved_peers_own_statement() {
    let t = three();
    let statements = statements_to_send(&t.laptop.vault)
        .expect("the laptop's statement")
        .expect("the laptop serves its machine");
    assert!(
        secret_same_value_residence_exchange(
            &t.home.vault,
            PeerMachine::Unknown,
            statements.clone()
        )
        .is_err(),
        "an unproved socket is refused"
    );
    assert!(
        secret_same_value_residence_exchange(
            &t.home.vault,
            PeerMachine::Proven {
                machine: t.laptop.machine,
                key: [7; 32],
            },
            statements.clone(),
        )
        .is_err(),
        "a socket proving another key is refused"
    );
    secret_same_value_residence_exchange(&t.home.vault, t.phone.proven(), statements)
        .expect("the phone is a machine of the owner's");
    assert!(
        !holds_statement_from(&t.home.vault, t.laptop.machine).expect("the home's statements"),
        "the home keeps no statement from a peer that did not write it"
    );
}

#[test]
fn a_machine_removed_from_the_vault_opens_nothing_from_the_next_statement_on() {
    let mut home = home();
    let mut laptop = node(&home);
    let mut phone = node(&home);
    let tablet = node(&home);
    laptop.take(&home);
    let a = laptop.register("laptop-a", SHARED, NOW);
    let b = laptop.register("laptop-b", SHARED, NOW + 1);
    home.take(&laptop);
    phone.take(&home);
    laptop.pass(&home);
    let first = laptop.statement();
    let mut expected = vec![phone.machine, tablet.machine];
    expected.sort();
    assert_eq!(recipients(&first), expected);
    assert_eq!(
        tablet.pass(&home),
        1,
        "the tablet takes the laptop's statement"
    );
    assert!(
        opened_pair(&tablet.vault, laptop.machine, a, b).expect("the tablet's statements"),
        "the tablet opens the pair while it is the owner's"
    );
    home.vault
        .set_machine_role(
            &proof(&home.vault),
            ActSurface::HostedConsole,
            tablet.machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the tablet");
    laptop.take(&home);
    phone.take(&home);
    let second = laptop.statement();
    assert_eq!(
        recipients(&second),
        vec![phone.machine],
        "the laptop seals its next statement to the phone alone"
    );
    assert!(
        secret_same_value_residence_exchange(&home.vault, tablet.proven(), Vec::new()).is_err(),
        "the home serves the removed tablet no more"
    );
    assert_eq!(
        take_answer(&tablet.vault, vec![second]).expect("the tablet takes"),
        1,
        "a relay hands the tablet the newer statement"
    );
    assert!(
        holds_statement_from(&tablet.vault, laptop.machine).expect("the tablet's statements"),
        "the tablet holds the newer statement"
    );
    assert!(
        !opened_pair(&tablet.vault, laptop.machine, a, b).expect("the tablet's statements"),
        "and opens nothing from it: no envelope is sealed to it"
    );
}
