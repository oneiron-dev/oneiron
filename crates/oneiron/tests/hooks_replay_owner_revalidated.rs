//! FIX row HOOKS-REPLAY-OWNER-NOT-RECHECKED: `vault.hooks.replay`'s owner call
//! (`replay_hooks_as_owner_listing`) checks the owner's proof again on the vault it
//! replays, as every owner door does. A proof minted for a live person who does not
//! own the vault, or by another vault's open, replays nothing; the vault's live owner
//! replays as before. Before the fix the call took the proof as `_owner` and never
//! read it, and a plain `Vault::authenticate_owner` proof names no ownership, so both
//! refusal tests answered a page.
//!
//! `cargo test --locked -p oneiron --all-features --test hooks_replay_owner_revalidated`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::{HookBodyRun, HookBodyRuntime, HookRunContext};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::PackInstallDisposition;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{HooksReplayPage, HooksReplayRequest, replay_hooks_as_owner_listing};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;

const T0: u64 = 1_790_000_000;

/// The pack the owner puts to bind one hook: an author-scoped name, as a hub pack has.
const PACK: &str = "example.hookreplay";
/// Its one hook.
const HOOK: &str = "fact-note";

const PACK_MD: &str = "---
name: example.hookreplay
description: One fact hook the owner binds.
version: 1.0.0
kind: capability
hooks: [\"fact-note\"]
---
A pack whose one fact hook the owner's put binds.
";

const HOOK_MD: &str = "---
name: fact-note
version: 1.0.0
verbs: [\"claim.landed:example.hookreplay.input\"]
actors: [\"human\"]
phase: fact
outcomes: [\"propose\"]
---
Propose one note per landed input claim.
";

const BODY_JS: &str = "return {
  kind: \"propose\",
  claim: {
    subject: input.claim.subject,
    predicate: \"example.hookreplay.note\",
    confidence: 1,
    value: { note: input.claim.value }
  }
};
";

/// The page size every replay below asks for.
const LIMIT: usize = 10;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned,
    /// as `page_and_cut_setting_keys.rs` builds it for its replay test.
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
            owner_proof,
        }
    }

    /// The owner puts the pack, which binds its one hook; the request replays that binding.
    fn bound_hook_request(&self) -> HooksReplayRequest {
        let files = vec![
            HubFile::new("PACK.md", PACK_MD),
            HubFile::new(format!("hooks/{HOOK}/HOOK.md"), HOOK_MD),
            HubFile::new(format!("hooks/{HOOK}/body.js"), BODY_JS),
        ];
        match self.vault.put_pack(&self.owner_proof, files) {
            Ok(PackInstallDisposition::Installed(receipt)) => {
                assert_eq!(receipt.pack_name, PACK);
            }
            other => panic!("the owner's put installs the pack and binds its hook: {other:?}"),
        }
        let binding = self
            .vault
            .pack_hook_bindings()
            .expect("hook bindings")
            .into_iter()
            .find(|(_, bound)| bound.pack == PACK)
            .map(|(id, _)| id.to_hex())
            .expect("the pack's hook binding");
        HooksReplayRequest {
            binding,
            since: None,
            limit: Some(LIMIT),
            cursor: None,
        }
    }

    /// A live PERSON of this vault who is not its owner, with an owner proof minted for them
    /// by the plain authenticate door, which checks no ownership.
    fn non_owner_proof(&self) -> AuthenticatedOwner {
        let person = EntityId::now();
        let at = self.vault.now_recorded_at();
        self.vault
            .put_entity(
                &person,
                ENTITY_TYPE_PERSON,
                TimeRange { start: at, end: at },
                at,
                b"a member who does not own the vault",
            )
            .expect("a live PERSON");
        self.vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("the plain authenticate door mints a proof for any live person")
    }
}

/// A hook body runtime that answers an empty outcome. No fact the hook takes has landed, so
/// no body runs; the page is all a replay below reads.
struct StubRuntime;

impl HookBodyRuntime for StubRuntime {
    fn run_hook(
        &self,
        _body: &str,
        _input: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        Ok(HookBodyRun {
            outcome_json: "{}".to_owned(),
            fuel_used: None,
            host_calls: 0,
        })
    }
}

/// `vault.hooks.replay` of `request` on `fx`'s vault under `proof`.
fn replay(
    fx: &Fixture,
    proof: &AuthenticatedOwner,
    request: &HooksReplayRequest,
) -> MemoryResult<(HooksReplayPage, Vec<EntityId>)> {
    replay_hooks_as_owner_listing(&fx.vault, proof, &StubRuntime, None, request)
}

/// Control: the vault's live owner replays the bound hook, a page at the asked size.
#[test]
fn the_live_owner_replays_the_bound_hook() {
    let fx = Fixture::rooted();
    let request = fx.bound_hook_request();
    let (page, _) = replay(&fx, &fx.owner_proof, &request).expect("the owner replays the hook");
    assert_eq!(page.effective_limit, LIMIT);
    assert!(page.rows.is_empty(), "no fact the hook takes has landed");
}

/// A live person who does not own the vault holds a proof from the plain authenticate door.
/// The replay refuses it as not the vault's owner; the owner's own replay of the same request
/// still answers, so the refusal is the proof's.
#[test]
fn a_non_owner_persons_proof_replays_nothing() {
    let fx = Fixture::rooted();
    let request = fx.bound_hook_request();
    let member = fx.non_owner_proof();
    let refusal = replay(&fx, &member, &request)
        .expect_err("the replay refuses a proof whose person does not own this vault");
    let text = format!("{refusal:?}");
    assert!(
        text.contains("is not an owner of this vault"),
        "the refusal names the missing ownership: {text}"
    );
    replay(&fx, &fx.owner_proof, &request).expect("the owner's replay of the same request answers");
}

/// The owner of another vault holds a proof that vault's open authenticated. The replay
/// refuses it on this vault; this vault's owner's replay of the same request still answers.
#[test]
fn another_vaults_owner_proof_replays_nothing() {
    let fx = Fixture::rooted();
    let other = Fixture::rooted();
    let request = fx.bound_hook_request();
    let refusal = replay(&fx, &other.owner_proof, &request)
        .expect_err("the replay refuses an owner proof another vault authenticated");
    let text = format!("{refusal:?}");
    assert!(
        text.contains("belongs to another vault"),
        "the refusal names the other vault's proof: {text}"
    );
    replay(&fx, &fx.owner_proof, &request).expect("the owner's replay of the same request answers");
}
