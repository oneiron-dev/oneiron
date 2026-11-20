//! The owner's pre hook that skips every call of the verbs it names, for the
//! served tests that show a door judges its caller's live Grant before any
//! verb hook runs (FIX CONTINUE-ADMISSION-SKIPS-LIVE-GRANT): a caller the
//! door admits meets the hook's skip, and a caller it refuses gets the
//! door's refusal, never the hook's answer.
//!
//! The pack is put as `vault_hooks_doors.rs` puts its owner packs: this
//! install's signing keys loaded, then the owner's own proof.

use oneiron::Vault;
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::PackInstallDisposition;
use oneiron::store::GateDecisionId;

/// The pack's name.
const SKIP_PACK: &str = "example.skiphook";
/// Its one hook.
const SKIP_HOOK: &str = "skip-verbs";

/// The owner puts a pack whose one pre hook skips every call of `verbs`, by
/// any caller (a hook that names no actors selects every one).
pub(crate) fn put_owner_skip_hook(vault: &Vault, verbs: &[&str]) {
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let verbs_json = serde_json::to_string(verbs).expect("the verb list as JSON");
    let pack_md = format!(
        "---\nname: {SKIP_PACK}\ndescription: One pre hook that skips the verbs it names.\nversion: 1.0.0\nkind: capability\nhooks: [\"{SKIP_HOOK}\"]\n---\nA pack whose one hook skips every call of its verbs.\n"
    );
    let hook_md = format!(
        "---\nname: {SKIP_HOOK}\nversion: 1.0.0\nverbs: {verbs_json}\nphase: pre\noutcomes: [\"skip\"]\n---\nSkip every call the hook is asked about.\n"
    );
    let files = vec![
        HubFile::new("PACK.md", pack_md),
        HubFile::new(format!("hooks/{SKIP_HOOK}/HOOK.md"), hook_md),
        HubFile::new(
            format!("hooks/{SKIP_HOOK}/body.js"),
            "return { kind: \"skip\", reason: \"held by the owner hook\" };\n",
        ),
    ];
    match vault
        .put_pack(&proof, files)
        .expect("the owner puts the skip pack")
    {
        PackInstallDisposition::Installed(receipt) => {
            assert_eq!(receipt.pack_name, SKIP_PACK, "the put installs the pack");
        }
        other => panic!("the owner's skip pack installs and binds its hook: {other:?}"),
    }
}
