//! FIX [HOST-COMPACT-PREHOOK-SKIP-UNPROVEN-AT-DOOR]: a `host.compact`
//! pre-hook may not Skip.
//!
//! Canon ARCH-0080 (oneiron-docs `generated/llms-full.txt`, line 351742):
//! "Every host verb takes the full pre and post outcome sets. One exception:
//! a `host.compact` pre-hook may not Skip, because a skipped compaction
//! overflows the next turn (review fix S1)."
//!
//! The engine refuses such a Skip in `admit_verb_outcome`
//! (`crates/oneiron/src/runtime_hooks/verb/chain.rs`): the run is recorded
//! with token "refused" and the chain goes on. A refused Skip also never
//! turns into an indirect Ask: a blocking hook whose Skip was refused does
//! not take the Write-domain fail-safe (the refused-Skip arm above the
//! blocking arm in the same file).
//!
//! - `a_skip_on_host_compact_is_refused_and_the_chain_goes_on`: two
//!   pre-hooks on `host.compact`; the first answers Skip, the second answers
//!   a Rewrite that pins one window line. The first hook's run is refused,
//!   the chain reaches the second hook, and its pin joins `keep`. With the
//!   Skip refusal gone, the Skip stops the chain and `keep` stays the host's
//!   own list.
//! - `a_blocking_skip_on_host_compact_never_turns_into_an_ask`: one blocking
//!   pre-hook on `host.compact` answering Skip, alone. No ask opens, the
//!   host's keep list is unchanged, and the run's receipt carries no
//!   fail-safe. With the refused-Skip arm gone, the refused blocking run
//!   takes the Write-domain fail-safe: an ask (the pass returns Pending), or
//!   a skip when the ask cannot open.
//!
//! Public paths only: `Vault::put_pack` installs the pack and binds its
//! hooks, `Vault::pre_compact_hooks` runs the pass, `Vault::receipts` reads
//! the Hook receipts. The bodies run in the hook sandbox, which the
//! `code-sandbox-wasmtime` feature builds:
//! `cargo test --locked -p oneiron --all-features --test host_compact_skip_refused`.

use oneiron::compaction::{CompactionWindowMessage, compact_invocation};
use oneiron::consent::AuthenticatedOwner;
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{HookOutcomeKind, PackHookBinding, PackInstallDisposition};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};

/// The pack the tests put: an author-scoped name, as a hub pack has.
const PACK: &str = "example.compactskip";
/// The host's own keep line: already kept before the hooks run.
const HOST_KEEP: &str = "The north pier log holds the morning watch.";
/// The one line the Rewrite hook pins.
const PIN: &str = "The lamp room keeps a spare wick.";
/// The exact refusal the engine records for a `host.compact` Skip.
const SKIP_REFUSED: &str = "a host.compact pre-hook may not skip";

const PACK_MD_TWO: &str = "---
name: example.compactskip
description: Two host.compact pre-hooks: a Skip the pass refuses and a Rewrite that pins one line.
version: 1.0.0
kind: capability
hooks: [\"pin-second\", \"skip-first\"]
---
A pack whose first hook's Skip the host.compact chain refuses.
";

const PACK_MD_ONE: &str = "---
name: example.compactskip
description: One blocking host.compact pre-hook answering Skip.
version: 1.0.0
kind: capability
hooks: [\"blocking-skip\"]
---
A pack whose blocking hook's Skip never turns into an ask.
";

/// Runs first (higher priority runs first): answers Skip, which
/// `host.compact` refuses. No `actors` field: an empty actor list selects
/// every class, so the System class of a compaction pass matches.
const SKIP_FIRST_HOOK_MD: &str = "---
name: skip-first
version: 1.0.0
verbs: [\"host.compact\"]
phase: pre
priority: 10
budget_ms: 1000
blocking: false
outcomes: [\"skip\"]
---
First hook: answers Skip, which host.compact refuses.
";

const SKIP_FIRST_BODY_JS: &str =
    "return { kind: \"skip\", reason: \"skip-first tries to stop compaction.\" };\n";

/// Runs after `skip-first` (lower priority): pins one window line.
const PIN_SECOND_HOOK_MD: &str = "---
name: pin-second
version: 1.0.0
verbs: [\"host.compact\"]
phase: pre
priority: 0
budget_ms: 1000
blocking: false
outcomes: [\"rewrite\"]
---
Second hook: pins one window line by rewrite.
";

/// Alone and blocking: answers Skip, which must stay refused and never ask.
const BLOCKING_SKIP_HOOK_MD: &str = "---
name: blocking-skip
version: 1.0.0
verbs: [\"host.compact\"]
phase: pre
priority: 0
budget_ms: 1000
blocking: true
outcomes: [\"skip\"]
---
Blocking hook: answers Skip, which never turns into an ask.
";

const BLOCKING_SKIP_BODY_JS: &str =
    "return { kind: \"skip\", reason: \"blocking-skip tries to stop compaction.\" };\n";

/// The Rewrite body, built from `PIN` so the pinned line and the asserted
/// line cannot drift apart: it appends the pin to the pass's keep list.
fn pin_second_body() -> String {
    format!(
        "const pin = {pin:?};\nreturn {{ kind: \"rewrite\", args: {{ ...input.args, keep_list: [...input.args.keep_list, pin] }} }};\n",
        pin = PIN,
    )
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A vault opened with the shipped default manifest and its owner's
    /// proof, as an embedded owner holds it. The shape of
    /// `crates/oneiron/tests/pack_hook_owner_floor.rs`.
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            owner,
            owner_proof,
            _directory: directory,
        }
    }

    /// The owner's put of `files`: installs the pack and binds its hooks in
    /// one transaction. Answers this pack's live bindings.
    fn put_pack(&self, files: Vec<HubFile>) -> Vec<(EntityId, PackHookBinding)> {
        match self.vault.put_pack(&self.owner_proof, files) {
            Ok(PackInstallDisposition::Installed(receipt)) => {
                assert_eq!(
                    receipt.pack_name, PACK,
                    "the owner's put installs this pack"
                );
            }
            other => panic!("the owner's put installs the pack and binds its hooks: {other:?}"),
        }
        let bindings = self
            .vault
            .pack_hook_bindings()
            .expect("live bindings read")
            .into_iter()
            .filter(|(_, binding)| binding.pack == PACK)
            .collect::<Vec<_>>();
        assert!(
            !bindings.is_empty(),
            "the put binds this pack's hooks live: {bindings:?}"
        );
        bindings
    }

    /// The Hook receipts of the pass `invocation`.
    fn hook_runs(&self, invocation: &str) -> Vec<ReceiptRecord> {
        self.vault
            .receipts(ReceiptQuery::new(1000).with_kind(ReceiptKind::Hook))
            .expect("hook receipts read")
            .into_iter()
            .filter(|receipt| receipt.trigger_ref.as_deref() == Some(invocation))
            .collect()
    }
}

/// The pass's window: one message whose content holds the host's keep line
/// and the pin word for word, so the Rewrite's pin is admissible.
fn window() -> Vec<CompactionWindowMessage> {
    vec![CompactionWindowMessage {
        message_id: EntityId::now(),
        turn_id: EntityId::now(),
        content: format!("{HOST_KEEP} {PIN} The crew signed the handover at dusk."),
        turn: 7,
        tokens: 64,
    }]
}

/// The binding of `hook` among `bindings`.
fn binding_of<'b>(bindings: &'b [(EntityId, PackHookBinding)], hook: &str) -> &'b PackHookBinding {
    bindings
        .iter()
        .find(|(_, binding)| binding.hook == hook)
        .map(|(_, binding)| binding)
        .unwrap_or_else(|| panic!("the {hook} hook is bound live: {bindings:?}"))
}

/// The receipt of `hook` among `runs`.
fn run_of<'r>(runs: &'r [ReceiptRecord], hook: &str) -> Option<&'r ReceiptRecord> {
    let name = format!("{PACK}/{hook}");
    runs.iter()
        .find(|receipt| receipt.fields.get("hook").map(String::as_str) == Some(name.as_str()))
}

#[test]
fn a_skip_on_host_compact_is_refused_and_the_chain_goes_on() {
    let f = Fixture::new();
    let bindings = f.put_pack(vec![
        HubFile::new("PACK.md", PACK_MD_TWO),
        HubFile::new("hooks/skip-first/HOOK.md", SKIP_FIRST_HOOK_MD),
        HubFile::new("hooks/skip-first/body.js", SKIP_FIRST_BODY_JS),
        HubFile::new("hooks/pin-second/HOOK.md", PIN_SECOND_HOOK_MD),
        HubFile::new("hooks/pin-second/body.js", pin_second_body()),
    ]);
    assert_eq!(bindings.len(), 2, "both hooks bind live: {bindings:?}");
    let skip = binding_of(&bindings, "skip-first");
    let pin = binding_of(&bindings, "pin-second");
    assert!(
        skip.selector.priority > pin.selector.priority,
        "skip-first runs before pin-second: higher priority runs first"
    );
    assert!(
        !skip.selector.blocking && !pin.selector.blocking,
        "both hooks are non-blocking, so this test proves the chain goes on"
    );
    assert_eq!(
        skip.selector.verbs,
        vec!["host.compact".to_owned()],
        "skip-first matches the host.compact verb"
    );
    assert_eq!(
        pin.selector.verbs,
        vec!["host.compact".to_owned()],
        "pin-second matches the host.compact verb"
    );
    assert_eq!(
        skip.selector.outcomes,
        vec![HookOutcomeKind::Skip],
        "skip-first may answer Skip, so the host.compact rule refuses its run, not its binding"
    );
    assert_eq!(
        pin.selector.outcomes,
        vec![HookOutcomeKind::Rewrite],
        "pin-second may answer Rewrite, so its run is admitted"
    );

    let window = window();
    let mut keep = vec![HOST_KEEP.to_owned()];
    let after = vec![HOST_KEEP.to_owned(), PIN.to_owned()];
    // A ceiling the host's own rewrite check (the tokenizer count over the
    // whole list) admits; the pass's `fits` closure admits everything.
    let ceiling = oneiron::count_context_pack_tokens(&after.join("\n")) as u64 + 100;
    let fits = |_: &[String]| true;
    let invocation = compact_invocation(b"host-compact-skip-refused-1", 1);
    let hooks = f.vault.pre_compact_hooks(
        invocation, f.owner, None, &window, &mut keep, ceiling, &fits,
    );

    assert_eq!(
        keep, after,
        "skip-first's Skip is refused and the chain goes on: pin-second's pin joins keep"
    );
    assert!(
        hooks.pending().is_none(),
        "no ask opens on this pass: a refused Skip parks nothing"
    );

    let runs = f.hook_runs(&invocation.to_hex());
    let skip_run = run_of(&runs, "skip-first")
        .unwrap_or_else(|| panic!("skip-first's run stands as a Hook receipt: {runs:?}"));
    assert_eq!(
        skip_run.outcome, "refused",
        "skip-first's Skip is refused, not taken: {skip_run:?}"
    );
    assert_eq!(
        skip_run.fields.get("reason").map(String::as_str),
        Some(SKIP_REFUSED),
        "the receipt names the refusal: a host.compact pre-hook may not skip"
    );
    assert_eq!(
        skip_run.fields.get("verb").map(String::as_str),
        Some("host.compact"),
        "the refused run was on host.compact"
    );
    assert!(
        skip_run.fields.get("fail_safe").is_none(),
        "a refused run fails nothing safe: its receipt carries no fail_safe: {skip_run:?}"
    );
    let pin_run = run_of(&runs, "pin-second")
        .unwrap_or_else(|| panic!("pin-second ran after the refusal: {runs:?}"));
    assert_eq!(
        pin_run.outcome, "rewrite",
        "pin-second's rewrite is admitted after the refused Skip: {pin_run:?}"
    );
}

#[test]
fn a_blocking_skip_on_host_compact_never_turns_into_an_ask() {
    let f = Fixture::new();
    let bindings = f.put_pack(vec![
        HubFile::new("PACK.md", PACK_MD_ONE),
        HubFile::new("hooks/blocking-skip/HOOK.md", BLOCKING_SKIP_HOOK_MD),
        HubFile::new("hooks/blocking-skip/body.js", BLOCKING_SKIP_BODY_JS),
    ]);
    assert_eq!(bindings.len(), 1, "the one hook binds live: {bindings:?}");
    let binding = binding_of(&bindings, "blocking-skip");
    assert!(
        binding.selector.blocking,
        "the hook is blocking: only a blocking hook could take the Write-domain fail-safe"
    );
    assert_eq!(
        binding.selector.verbs,
        vec!["host.compact".to_owned()],
        "the hook matches the host.compact verb"
    );
    assert_eq!(
        binding.selector.outcomes,
        vec![HookOutcomeKind::Skip],
        "the hook may answer Skip, so the host.compact rule refuses its run, not its binding"
    );

    let window = window();
    let mut keep = vec![HOST_KEEP.to_owned()];
    let host_keep = keep.clone();
    let ceiling = oneiron::count_context_pack_tokens(&host_keep.join("\n")) as u64 + 100;
    let fits = |_: &[String]| true;
    let invocation = compact_invocation(b"host-compact-skip-refused-2", 1);
    let hooks = f.vault.pre_compact_hooks(
        invocation, f.owner, None, &window, &mut keep, ceiling, &fits,
    );

    assert!(
        hooks.pending().is_none(),
        "a refused blocking Skip never turns into an ask: pending stays None"
    );
    assert_eq!(
        keep, host_keep,
        "the host's keep list is unchanged: the refused Skip adds nothing"
    );
    // No outcome token is asserted here: with the Skip refusal itself gone,
    // the admitted Skip ends the pass Skipped with no fail-safe, which this
    // test does not prove against (the first test does).
    let runs = f.hook_runs(&invocation.to_hex());
    let run = run_of(&runs, "blocking-skip")
        .unwrap_or_else(|| panic!("blocking-skip ran on this pass: {runs:?}"));
    assert!(
        run.fields.get("fail_safe").is_none(),
        "a refused blocking Skip takes no fail-safe, neither an ask nor a skip: {run:?}"
    );
}
