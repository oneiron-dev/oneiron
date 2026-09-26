//! Vault intent survives reload and drives the upgrade behavior-diff gate.

use super::*;
use crate::{Error, Result, VaultConfig};
use std::cell::{Cell, RefCell};

fn revision(stale: bool, role: LensHandleRole) -> Result<LensEvaluatedRevision> {
    let mut root = v2_only_root();
    root.bindings.push(binding("claims", role));
    let current = GeneratedLens::new(root)?;
    let lens = if stale {
        let mut wire = serde_json::to_value(&current)
            .map_err(|error| Error::InvalidConfig(error.to_string()))?;
        wire["apps_contract_version"] = 0.into();
        serde_json::from_value(wire).map_err(|error| Error::InvalidConfig(error.to_string()))?
    } else {
        current
    };
    let fingerprint = LensBehaviorFingerprint::from_golden_renders([("case", &lens)])?;
    Ok(LensEvaluatedRevision::new(lens, fingerprint))
}

struct IntentRegenerator {
    calls: Cell<usize>,
    seen: RefCell<Vec<String>>,
    candidate: Option<LensEvaluatedRevision>,
}

impl LensRegenerator for IntentRegenerator {
    fn regenerate(
        &self,
        request: &LensRegenRequest,
    ) -> std::result::Result<LensEvaluatedRevision, LensRegenFailure> {
        self.calls.set(self.calls.get() + 1);
        self.seen
            .borrow_mut()
            .push(request.intent_prompt().to_owned());
        self.candidate.clone().ok_or_else(|| {
            LensRegenFailure::new(
                LensRegenFailurePhase::Compile,
                "candidate could not compile",
            )
        })
    }
}

#[test]
fn vault_intent_drives_version_upgrade_and_preserves_last_good() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let id = crate::test_util::entity(120);
    let other_id = crate::test_util::entity(121);
    let intent = LensIntentRecord::new("summarize open claims")?;
    vault.put_lens_intent(&id, &intent)?;
    vault.put_lens_intent(&other_id, &LensIntentRecord::new("other view")?)?;
    drop(vault);
    let vault = crate::Vault::open(_dir.path(), VaultConfig::device())?;
    assert_eq!(vault.get_lens_intent(&id)?, Some(intent));
    assert_eq!(
        vault.get_lens_intent(&other_id)?.unwrap().prompt(),
        "other view"
    );
    let last_good = revision(true, LensHandleRole::ClaimSet)?;
    let candidate = revision(false, LensHandleRole::EntitySet)?;
    let regenerator = IntentRegenerator {
        calls: Cell::new(0),
        seen: RefCell::new(Vec::new()),
        candidate: Some(candidate),
    };
    let outcome = vault
        .regenerate_lens_on_upgrade(&id, &regenerator, last_good.clone())
        .expect("contract stamp changed");
    assert!(
        matches!(outcome, LensRegenOutcome::NeedsHumanStamp { .. }),
        "changed bound reads require a stamp"
    );
    assert_eq!(outcome.active_revision(), &last_good);
    assert_eq!(&*regenerator.seen.borrow(), &["summarize open claims"]);
    assert_eq!(regenerator.calls.get(), 1);

    let same_reads = IntentRegenerator {
        calls: Cell::new(0),
        seen: RefCell::new(Vec::new()),
        candidate: Some(revision(false, LensHandleRole::ClaimSet)?),
    };
    let outcome = vault
        .regenerate_lens_on_upgrade(&id, &same_reads, last_good.clone())
        .expect("contract stamp changed");
    assert!(matches!(outcome, LensRegenOutcome::AutoAdopt { .. }));
    assert_eq!(
        outcome.active_revision().lens().version_stamp(),
        LensVersionStamp::current()
    );
    assert_eq!(&*same_reads.seen.borrow(), &["summarize open claims"]);

    let failed = IntentRegenerator {
        calls: Cell::new(0),
        seen: RefCell::new(Vec::new()),
        candidate: None,
    };
    let outcome = vault
        .regenerate_lens_on_upgrade(&id, &failed, last_good.clone())
        .unwrap();
    assert!(matches!(outcome, LensRegenOutcome::RolledBack { .. }));
    assert_eq!(
        outcome.active_revision(),
        &last_good,
        "failure cannot unmount the last-good body"
    );
    assert_eq!(&*failed.seen.borrow(), &["summarize open claims"]);
    assert!(
        vault
            .regenerate_lens_on_upgrade(&id, &failed, revision(false, LensHandleRole::ClaimSet)?)
            .is_none(),
        "current stamp needs no regeneration"
    );
    assert_eq!(failed.calls.get(), 1);
    Ok(())
}

#[test]
fn missing_or_invalid_intent_never_runs_regenerator() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let id = crate::test_util::entity(122);
    let last_good = revision(true, LensHandleRole::ClaimSet)?;
    let regen = IntentRegenerator {
        calls: Cell::new(0),
        seen: RefCell::new(Vec::new()),
        candidate: None,
    };
    let outcome = vault
        .regenerate_lens_on_upgrade(&id, &regen, last_good.clone())
        .unwrap();
    assert!(matches!(outcome, LensRegenOutcome::RolledBack { .. }));
    assert_eq!(outcome.active_revision(), &last_good);
    assert_eq!(regen.calls.get(), 0);
    assert!(LensIntentRecord::new("  ").is_err());
    assert!(LensIntentRecord::new("x".repeat(LENS_INTENT_MAX_BYTES + 1)).is_err());
    vault.with_write_txn(|txn| {
        let mut key = b"lens/intent/v1\0".to_vec();
        key.extend_from_slice(id.as_bytes());
        vault.store.vault_meta.put(txn, &key, b"broken")?;
        Ok(())
    })?;
    let outcome = vault
        .regenerate_lens_on_upgrade(&id, &regen, last_good.clone())
        .unwrap();
    assert!(matches!(outcome, LensRegenOutcome::RolledBack { .. }));
    assert_eq!(outcome.active_revision(), &last_good);
    assert_eq!(regen.calls.get(), 0);
    Ok(())
}
