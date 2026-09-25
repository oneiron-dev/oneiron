//! Immutable baseline and verdict rows, and structural contract diffs.
use super::{
    CommandOutput, ContractBaseline, ContractDiff, ContractSnapshot, ContractSpec, ContractVerdict,
    invalid, rust_public_names, safe_path,
};
use crate::{
    Vault,
    error::{Error, Result},
};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
use std::path::Path;

pub struct ContractOracle<'a> {
    vault: &'a Vault,
}

impl<'a> ContractOracle<'a> {
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }

    pub fn capture(
        spec: &ContractSpec,
        root: &Path,
        outputs: BTreeMap<String, CommandOutput>,
    ) -> Result<ContractSnapshot> {
        if outputs
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            != spec.outputs
        {
            return Err(invalid(
                "all and only declared command outputs must be observed",
            ));
        }
        let mut snapshot = ContractSnapshot {
            outputs,
            ..ContractSnapshot::default()
        };
        for (name, path) in &spec.rust_crates {
            snapshot
                .public_names
                .extend(rust_public_names(root, name, path)?);
        }
        for (name, path) in &spec.schemas {
            let bytes = std::fs::read(safe_path(root, path)?)?;
            if bytes.len() > 8 * 1024 * 1024 {
                return Err(invalid("schema exceeds oracle limit"));
            }
            let schema = serde_json::from_slice(&bytes)
                .map_err(|_| invalid("contract schema is invalid JSON"))?;
            snapshot.schemas.insert(name.clone(), schema);
        }
        Ok(snapshot)
    }

    /// Baseline identities are content hashes. There is no mutable replace-baseline door.
    pub fn record_baseline(
        &self,
        spec: ContractSpec,
        snapshot: ContractSnapshot,
    ) -> Result<ContractBaseline> {
        validate_snapshot(&spec, &snapshot)?;
        let id = digest(&("oneiron:contract-baseline:v1", &spec, &snapshot))?;
        let baseline = ContractBaseline {
            schema_version: 1,
            id: id.clone(),
            spec,
            snapshot,
        };
        self.put("baseline", &id, &baseline)?;
        Ok(baseline)
    }

    pub fn baseline(&self, id: &str) -> Result<Option<ContractBaseline>> {
        let row: Option<ContractBaseline> = self.get("baseline", id)?;
        if let Some(row) = &row {
            if row.schema_version != 1
                || row.id != id
                || digest(&("oneiron:contract-baseline:v1", &row.spec, &row.snapshot))? != id
            {
                return Err(Error::CorruptedIndex("contract baseline identity"));
            }
            validate_snapshot(&row.spec, &row.snapshot)?;
        }
        Ok(row)
    }

    pub fn compare_and_record(
        &self,
        baseline_id: &str,
        candidate: &str,
        snapshot: &ContractSnapshot,
        tests_passed: bool,
    ) -> Result<ContractVerdict> {
        let baseline = self
            .baseline(baseline_id)?
            .ok_or_else(|| invalid("contract baseline not found"))?;
        // Missing output/schema observations are diffs, never a green partial check.
        let mut diffs = Vec::new();
        for name in baseline
            .snapshot
            .public_names
            .difference(&snapshot.public_names)
        {
            diffs.push(ContractDiff::RemovedPublicName { name: name.clone() });
        }
        for name in baseline.spec.schemas.keys() {
            schema_diff(
                name,
                "",
                baseline.snapshot.schemas.get(name),
                snapshot.schemas.get(name),
                &mut diffs,
            );
        }
        for name in &baseline.spec.outputs {
            let before = baseline.snapshot.outputs.get(name);
            let after = snapshot.outputs.get(name);
            if before != after {
                diffs.push(ContractDiff::OutputDrift {
                    contract: name.clone(),
                    before: before.cloned(),
                    after: after.cloned(),
                });
            }
        }
        let mut verdict = ContractVerdict {
            schema_version: 1,
            id: String::new(),
            baseline_id: baseline_id.to_owned(),
            candidate: candidate.to_owned(),
            tests_passed,
            diffs,
        };
        verdict.id = verdict_digest(&verdict)?;
        self.put("verdict", &verdict.id, &verdict)?;
        Ok(verdict)
    }

    pub fn verdict(&self, id: &str) -> Result<Option<ContractVerdict>> {
        let row: Option<ContractVerdict> = self.get("verdict", id)?;
        if let Some(row) = &row
            && (row.schema_version != 1 || row.id != id || verdict_digest(row)? != id)
        {
            return Err(Error::CorruptedIndex("contract verdict identity"));
        }
        Ok(row)
    }

    fn put<T: Serialize>(&self, family: &str, id: &str, value: &T) -> Result<()> {
        let key = key(family, id)?;
        let bytes =
            rmp_serde::to_vec_named(value).map_err(|_| invalid("oracle row encoding failed"))?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err(invalid("oracle row exceeds limit"));
        }
        let mut txn = self.vault.store.env.write_txn()?;
        if let Some(prior) = self.vault.store.vault_meta.get(&txn, &key)? {
            if prior.as_ref() != bytes.as_slice() {
                return Err(Error::CorruptedIndex("immutable oracle row differs"));
            }
        } else {
            self.vault.store.vault_meta.put(&mut txn, &key, &bytes)?;
        }
        txn.commit()?;
        Ok(())
    }

    fn get<T: DeserializeOwned>(&self, family: &str, id: &str) -> Result<Option<T>> {
        let key = key(family, id)?;
        let txn = self.vault.store.env.read_txn()?;
        self.vault
            .store
            .vault_meta
            .get(&txn, &key)?
            .map(|bytes| {
                rmp_serde::from_slice(&bytes)
                    .map_err(|_| Error::CorruptedIndex("contract oracle row"))
            })
            .transpose()
    }
}

fn validate_snapshot(spec: &ContractSpec, snapshot: &ContractSnapshot) -> Result<()> {
    if spec.schemas.keys().ne(snapshot.schemas.keys())
        || spec.outputs.iter().ne(snapshot.outputs.keys())
    {
        return Err(invalid(
            "baseline must observe exactly the declared contracts",
        ));
    }
    Ok(())
}
fn key(family: &str, id: &str) -> Result<Vec<u8>> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("oracle id must be a content digest"));
    }
    Ok(format!("contract_oracle:{family}:v1:{id}").into_bytes())
}
fn digest(value: &impl Serialize) -> Result<String> {
    let bytes =
        rmp_serde::to_vec_named(value).map_err(|_| invalid("oracle digest encoding failed"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}
fn verdict_digest(row: &ContractVerdict) -> Result<String> {
    digest(&(
        "oneiron:contract-verdict:v1",
        &row.baseline_id,
        &row.candidate,
        row.tests_passed,
        &row.diffs,
    ))
}
fn schema_diff(
    name: &str,
    pointer: &str,
    before: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
    diffs: &mut Vec<ContractDiff>,
) {
    if before == after {
        return;
    }
    if let (Some(serde_json::Value::Object(left)), Some(serde_json::Value::Object(right))) =
        (before, after)
    {
        let keys: std::collections::BTreeSet<_> = left.keys().chain(right.keys()).collect();
        for key in keys {
            let escaped = key.replace('~', "~0").replace('/', "~1");
            schema_diff(
                name,
                &format!("{pointer}/{escaped}"),
                left.get(key),
                right.get(key),
                diffs,
            );
        }
    } else {
        diffs.push(ContractDiff::SchemaDrift {
            contract: name.to_owned(),
            pointer: pointer.to_owned(),
            before: before.cloned(),
            after: after.cloned(),
        });
    }
}
