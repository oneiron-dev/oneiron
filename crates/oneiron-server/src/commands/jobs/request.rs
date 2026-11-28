//! What `oneiron jobs run` sends: where it may run (the machines the vault shows and their node
//! template's digest), the pin (pass 33 5.1: template, commit, contract, entry, arguments and
//! resources) and the order (`--key` to `intent_key`, `--host` to `limits.machines`).

use std::collections::BTreeMap;
use std::path::Path;

use oneiron::EntityId;
use oneiron::job_workload::{
    DeviceClaim, DeviceKind, NetworkMode, OutputDecl, ResourceRequest, ScopeKind, Sharing,
    WorkloadPin, WorkloadPinRequest,
};
use oneiron::verbs::{MachineExecution, MachineExecutionReply};
use oneiron::work_order::{
    EndKind, OrderCharge, OrderClass, OrderLimits, OrderWishes, WaitRule, WorkOrderRequest,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::cli::JobsRunArgs;

/// Where the order may run, as the vault's issuer read its machines now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Placement {
    /// The machines `--host` named, in its order; empty when it named none.
    pub(super) machines: Vec<EntityId>,
    /// The digest of the template on the machines it may run on.
    pub(super) template_digest: String,
    /// Every machine's shown name, for the end line.
    pub(super) names: BTreeMap<EntityId, String>,
}

/// The machines `hosts` names in `reply` (by shown name or id), and the digest of `template` on
/// them; with no host named, on every machine whose node answered and holds it.
///
/// # Errors
///
/// What is refused before anything is sent: a host no machine is, a name two machines show,
/// a named machine whose node did not answer or does not hold the template, no machine that
/// holds it, or two digests of it.
pub(super) fn placement(
    reply: &MachineExecutionReply,
    hosts: &[String],
    template: &str,
) -> Result<Placement, String> {
    let names = machine_names(reply);
    let known: Vec<(EntityId, &MachineExecution)> = reply
        .machines
        .iter()
        .filter_map(|machine| Some((EntityId::from_hex(&machine.machine).ok()?, machine)))
        .collect();
    let mut named = Vec::new();
    for host in hosts {
        let matches: Vec<_> = known
            .iter()
            .filter(|(id, machine)| {
                id.to_hex() == host.to_ascii_lowercase()
                    || machine.name.as_deref() == Some(host.as_str())
            })
            .collect();
        match matches.as_slice() {
            [] => {
                return Err(format!(
                    "no machine the vault holds a job grant for is {host:?}"
                ));
            }
            [one] => named.push(*one),
            _ => {
                return Err(format!(
                    "{host:?} names {} machines; name it by its id",
                    matches.len()
                ));
            }
        }
    }
    let mut digests = BTreeMap::new();
    let chosen: Vec<&(EntityId, &MachineExecution)> = if named.is_empty() {
        known.iter().collect()
    } else {
        named.clone()
    };
    for (id, machine) in chosen {
        let offer = machine
            .node
            .answer
            .as_ref()
            .filter(|_| machine.node.state == "answered")
            .map(|answer| answer.templates.iter().find(|offer| offer.name == template));
        match offer {
            Some(Some(offer)) => {
                digests.insert(offer.digest.clone(), *id);
            }
            _ if named.is_empty() => {}
            None => {
                return Err(format!(
                    "{}'s node is {}: {}",
                    names[id],
                    machine.node.state,
                    machine
                        .node
                        .refusal
                        .as_deref()
                        .or(machine.node.error.as_deref())
                        .or(machine.node.not_asked.as_deref())
                        .unwrap_or("no answer")
                ));
            }
            Some(None) => {
                return Err(format!(
                    "{}'s node holds no template {template:?}",
                    names[id]
                ));
            }
        }
    }
    let mut digests = digests.into_keys();
    match (digests.next(), digests.next()) {
        (Some(template_digest), None) => Ok(Placement {
            machines: named.iter().map(|(id, _)| *id).collect(),
            template_digest,
            names,
        }),
        (None, _) => Err(format!(
            "no machine's node holds the template {template:?} now"
        )),
        (Some(_), Some(_)) => Err(format!(
            "the machines hold two digests of the template {template:?}; name one with --host"
        )),
    }
}

/// Each machine's shown name, else its id, by its id.
pub(super) fn machine_names(reply: &MachineExecutionReply) -> BTreeMap<EntityId, String> {
    reply
        .machines
        .iter()
        .filter_map(|machine| {
            let id = EntityId::from_hex(&machine.machine).ok()?;
            Some((id, machine.name.clone().unwrap_or_else(|| id.to_hex())))
        })
        .collect()
}

/// The pin request `args` asks for, on a template of `template_digest`, whose contract hashes
/// to `contract_sha256`.
///
/// # Errors
///
/// A size, duration, GPU claim, network or project that does not parse.
pub(super) fn pin_request(
    args: &JobsRunArgs,
    template_digest: &str,
    contract_sha256: &str,
) -> anyhow::Result<WorkloadPinRequest> {
    let project = args
        .project
        .as_deref()
        .map(|project| {
            EntityId::from_hex(project.trim())
                .map(|id| id.to_hex())
                .map_err(|_| anyhow::anyhow!("--project is a PROJECT's id, 32 hex"))
        })
        .transpose()?;
    let network: NetworkMode = serde_json::from_value(json!(args.network))
        .map_err(|_| anyhow::anyhow!("--network is none or host"))?;
    let devices = args
        .gpus
        .iter()
        .map(String::as_str)
        .map(gpu_claim)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let outputs = args
        .outputs
        .iter()
        .map(|name| (name, false))
        .chain(args.returnable_outputs.iter().map(|name| (name, true)))
        .map(|(name, returnable)| OutputDecl {
            name: name.clone(),
            returnable,
        })
        .collect();
    Ok(WorkloadPinRequest {
        pin: WorkloadPin {
            template: args.template.clone(),
            template_digest: template_digest.to_owned(),
            commit: args.commit.clone(),
            contract_sha256: contract_sha256.to_owned(),
            contract_path: args.contract.clone(),
            entry: args.entry.clone(),
            args: args.args.clone(),
            request: ResourceRequest {
                cpu_threads: args.threads,
                memory_mib: size_mib("--mem", &args.mem)?,
                disk_mib: size_mib("--disk", &args.disk)?,
                devices,
                maximum_secs: duration_secs(&args.timeout)?,
            },
            scope: ScopeKind::Host,
            network,
            outputs,
        },
        project,
        check_in_ref: None,
    })
}

/// The order of the pinned `workload` that `args` asks for, limited to `machines`.
///
/// # Errors
///
/// A class or retry end that does not parse.
pub(super) fn order_request(
    args: &JobsRunArgs,
    workload: &str,
    machines: &[EntityId],
) -> anyhow::Result<WorkOrderRequest> {
    let class: OrderClass = serde_json::from_value(json!(args.class))
        .map_err(|_| anyhow::anyhow!("--class is interactive, normal or background"))?;
    let retry_on = args
        .retry_on
        .iter()
        .map(String::as_str)
        .map(retry_end)
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(WorkOrderRequest {
        workload: workload.to_owned(),
        charge: OrderCharge::Offer {
            name: args.offer.clone(),
        },
        limits: OrderLimits {
            machines: Vec::new(),
            ..OrderLimits::default()
        },
        wishes: OrderWishes::default(),
        class,
        wait: if args.no_wait {
            WaitRule::No
        } else {
            WaitRule::Open
        },
        retry_on,
        result: None,
        intent_key: args.key.clone(),
        after: None,
        group: None,
    })
}

/// `exited:<code>`, or an end's own name.
fn retry_end(end: &str) -> anyhow::Result<EndKind> {
    let refused = || anyhow::anyhow!("--retry-on {end:?} is exited:<code> or an end's name");
    match end.split_once(':') {
        Some(("exited", code)) => Ok(EndKind::Exited {
            code: code.parse().map_err(|_| refused())?,
        }),
        Some(_) => Err(refused()),
        None if end == "exited" => Err(refused()),
        None => serde_json::from_value(json!({ "kind": end })).map_err(|_| refused()),
    }
}

/// `COUNT[:MIN-MEMORY-MIB[:FEATURE,...]]`: one exclusive GPU claim.
fn gpu_claim(claim: &str) -> anyhow::Result<DeviceClaim> {
    let refused = || anyhow::anyhow!("--gpu {claim:?} is COUNT[:MIN-MEMORY-MIB[:FEATURE,...]]");
    let mut parts = claim.splitn(3, ':');
    let count = parts
        .next()
        .and_then(|count| count.parse::<u32>().ok())
        .filter(|count| *count > 0)
        .ok_or_else(refused)?;
    let memory_mib = match parts.next() {
        Some(mib) => mib.parse().map_err(|_| refused())?,
        None => 0,
    };
    let features = parts
        .next()
        .map(|features| {
            features
                .split(',')
                .filter(|feature| !feature.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(DeviceClaim {
        kind: DeviceKind::Gpu,
        count,
        memory_mib,
        features,
        sharing: Sharing::Exclusive,
    })
}

/// A size in fleet's form, `28G`, `512M` or `1T` (binary units), in MiB.
pub(super) fn size_mib(flag: &str, size: &str) -> anyhow::Result<u64> {
    let refused = || anyhow::anyhow!("{flag} {size:?} is a size such as 28G, 512M or 1T");
    let size = size.trim();
    let digits = size.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let unit = &size[digits.len()..];
    let mib_per = match unit.to_ascii_uppercase().as_str() {
        "M" | "MB" | "MIB" => 1,
        "G" | "GB" | "GIB" => 1_024,
        "T" | "TB" | "TIB" => 1_024 * 1_024,
        _ => return Err(refused()),
    };
    let amount: u64 = digits.parse().map_err(|_| refused())?;
    amount
        .checked_mul(mib_per)
        .filter(|mib| *mib > 0)
        .ok_or_else(refused)
}

/// A duration in fleet's form, `3h`, `90m`, `1h30m`, `600s` or plain seconds; never 0.
pub(super) fn duration_secs(duration: &str) -> anyhow::Result<u64> {
    let refused =
        || anyhow::anyhow!("--timeout {duration:?} is a duration such as 3h, 90m or 600s");
    let duration = duration.trim();
    if let Ok(secs) = duration.parse::<u64>() {
        return (secs > 0).then_some(secs).ok_or_else(refused);
    }
    let mut total: u64 = 0;
    let mut digits = String::new();
    for c in duration.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let per = match c {
            'd' => 86_400,
            'h' => 3_600,
            'm' => 60,
            's' => 1,
            _ => return Err(refused()),
        };
        let amount: u64 = digits.parse().map_err(|_| refused())?;
        digits.clear();
        total = amount
            .checked_mul(per)
            .and_then(|secs| total.checked_add(secs))
            .ok_or_else(refused)?;
    }
    (digits.is_empty() && total > 0)
        .then_some(total)
        .ok_or_else(refused)
}

/// The sha256 (lower hex) of `contract` as `commit` holds it in the checkout `repo`: the digest
/// the node checks before it launches (pass 33 design 7.4).
///
/// # Errors
///
/// A commit that is not 40 lower hex, a path that is empty or begins with `-`, or a git that
/// does not answer the blob.
pub(super) fn contract_sha256(repo: &Path, commit: &str, contract: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        commit.len() == 40
            && commit
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "--commit is a code revision of 40 lower-hex characters"
    );
    anyhow::ensure!(
        !contract.is_empty() && !contract.starts_with('-'),
        "--contract is a path in the commit"
    );
    let output = oneiron_spawn::command("git")
        .arg("-C")
        .arg(repo)
        .arg("cat-file")
        .arg("blob")
        .arg(format!("{commit}:{contract}"))
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| anyhow::anyhow!("run git: {error}"))?;
    anyhow::ensure!(
        output.status.success(),
        "git has no {contract} at {commit} in {}: {}",
        repo.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(sha256_hex(&output.stdout))
}

/// The sha256 of `bytes`, lower hex.
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    oneiron_hex::encode(&Sha256::digest(bytes))
}
