//! This machine's key custody to its residence home (KS-4A2, FIX 5685): the
//! residence member of the required target set, on the steady pass.
//!
//! The home a machine's socket proves becomes the member
//! `residence:<home machine hex>`, registered before its first upload. When
//! a residence member is behind the local log position (or holds a head
//! sealed without the data key, FIX 5791), the machine seals a batch, asks
//! what the home holds of its lineage (`residence.custody.status`), ships
//! the frames it lacks (`residence.custody.frames`), stages the head in parts
//! (`residence.custody.put`) and commits it (`residence.custody.commit`). The
//! home answers the ack it persisted; the journal keeps it only when it names
//! that batch exactly and the home attests as the machine its socket proved.
//! A home out of reach, refusing or moved stays pending by name, and the next
//! pass retries. A home already holding a newer head of this machine's own
//! log (a newer pass committed it) is nothing to ship and nothing pending:
//! that pass acks it (FIX 6394). The owner drains a residence member this
//! machine left through `drain_custody_residence_member_as`, which the home
//! answers with its sweep ack; until then it stays a pending member. With
//! nothing in custody, or every residence member current, it dials nothing.

use std::sync::Arc;

use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ResidenceRpc, refused, residence_budgets};
use crate::Vault;
use crate::authority::PeerMachine;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::store::custody_protocol::{
    AckPosition, AckRecord, CustodyBatch, DrainAck, EvidenceKind, PendingCode, TargetId,
    TargetKind, TargetPending, TargetSpec,
};
use crate::sync::client::SyncClientConfig;
use crate::sync::residence::SEALED_BUNDLE_PUT_PART_MAX;
use crate::sync::transport::TransportError;

/// What the home holds of this machine's lineage.
#[derive(Deserialize)]
struct HeldReply {
    #[serde(default)]
    seq: Option<u64>,
    #[serde(default)]
    position: Option<AckPosition>,
}

impl HeldReply {
    /// Whether the home's head is a later one of `batch`'s own log, which
    /// a newer pass committed and acks (FIX 6394).
    fn covers(&self, batch: &CustodyBatch) -> bool {
        self.position
            .as_ref()
            .and_then(AckPosition::position)
            .is_some_and(|held| batch.covered_by(&held))
    }
}

/// What an upload left.
enum Uploaded {
    /// The home's ack of the batch.
    Acked(CustodyBatch, AckRecord),
    /// The home holds a newer head of this log: nothing to note.
    Covered,
}

#[derive(Deserialize)]
struct StagedReply {
    staged: u64,
}

#[derive(Deserialize)]
struct CommitReply {
    ack: AckRecord,
}

#[derive(Deserialize)]
struct DrainReply {
    ack: DrainAck,
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}

fn stopped() -> TransportError {
    TransportError::Storage("custody relay work stopped".into())
}

fn pending(code: PendingCode, detail: &str) -> TargetPending {
    TargetPending {
        code,
        detail: detail.to_owned(),
    }
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> crate::Result<T> + Send + 'static,
) -> Result<T, TransportError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| stopped())?
        .map_err(storage)
}

async fn batch_for(
    vault: &Arc<Vault>,
    spec: TargetSpec,
) -> Result<Option<CustodyBatch>, TransportError> {
    let vault = Arc::clone(vault);
    blocking(move || vault.custody_batch_for(&spec)).await
}

async fn note(
    vault: &Arc<Vault>,
    spec: TargetSpec,
    why: TargetPending,
) -> Result<(), TransportError> {
    let vault = Arc::clone(vault);
    blocking(move || vault.note_custody_pending(spec.id(), &why)).await
}

async fn note_all(
    vault: &Arc<Vault>,
    owed: Vec<(TargetSpec, CustodyBatch)>,
    code: PendingCode,
    detail: &str,
) -> Result<(), TransportError> {
    for (spec, _) in owed {
        note(vault, spec, pending(code, detail)).await?;
    }
    Ok(())
}

/// One relay pass: see the module notes.
pub(crate) async fn relay_custody(
    vault: &Arc<Vault>,
    config: &SyncClientConfig,
) -> Result<(), TransportError> {
    if config.federation_peer.is_some()
        || config.residence_selector.is_none()
        || !vault
            .local_machine()
            .map_err(storage)?
            .is_some_and(|machine| machine.mine)
    {
        return Ok(());
    }
    let held = Arc::clone(vault);
    let Some(members) = blocking(move || held.store.custody_members(TargetKind::Residence)).await?
    else {
        return Ok(());
    };
    let first = members.is_empty();
    let mut owed = Vec::new();
    for spec in members {
        if let Some(batch) = batch_for(vault, spec.clone()).await? {
            owed.push((spec, batch));
        }
    }
    if !first && owed.is_empty() {
        return Ok(());
    }
    let connected = match residence_budgets(vault) {
        Ok(budgets) => ResidenceRpc::connect(vault, config, budgets).await,
        Err(error) => Err(error),
    };
    let (mut rpc, home) = match connected {
        Ok(Some(rpc)) => match rpc.home {
            PeerMachine::Proven { machine, .. } => (rpc, machine),
            PeerMachine::Unknown => {
                let why = "the residence home proved no machine on its socket";
                return note_all(vault, owed, PendingCode::Denied, why).await;
            }
        },
        Ok(None) => {
            let why = "the residence home is out of reach; the next pass retries";
            return note_all(vault, owed, PendingCode::Offline, why).await;
        }
        Err(_) => {
            let why = "the residence home refused this machine's socket";
            return note_all(vault, owed, PendingCode::Denied, why).await;
        }
    };
    let spec = TargetSpec::residence(home);
    let mut batch = None;
    for (member, member_batch) in owed {
        if member.id() == spec.id() {
            batch = Some(member_batch);
        } else {
            let why = "this machine's residence home is another machine now";
            note(vault, member, pending(PendingCode::Offline, why)).await?;
        }
    }
    let batch = match batch {
        Some(batch) => batch,
        None => match batch_for(vault, spec.clone()).await? {
            Some(batch) => batch,
            None => return Ok(()),
        },
    };
    let (batch, ack) = match upload(&mut rpc, batch, home).await? {
        Ok(Uploaded::Acked(batch, ack)) => (batch, ack),
        Ok(Uploaded::Covered) => return Ok(()),
        Err(why) => return note(vault, spec, why).await,
    };
    let accepted = Arc::clone(vault);
    let refused_ack = blocking(move || {
        Ok(accepted
            .accept_custody_ack(&batch, &ack)
            .err()
            .map(|error| error.to_string()))
    })
    .await?;
    match refused_ack {
        None => Ok(()),
        Some(detail) => note(vault, spec, pending(PendingCode::Failed, &detail)).await,
    }
}

/// Drains residence member `target`, approved by `owner` (FIX 5843): begun,
/// the home empties the lineage's heads on the proven socket and answers
/// its sweep ack, committed here. The set's new revision. Any error leaves
/// the member fenced for a retry, which begins the same drain again.
pub async fn drain_custody_residence_member_as(
    vault: &Arc<Vault>,
    config: &SyncClientConfig,
    owner: &AuthenticatedOwner,
    target: &TargetId,
) -> Result<u64, TransportError> {
    let begun = Arc::clone(vault);
    let begin_owner = owner.clone();
    let begin_target = target.clone();
    let ticket =
        blocking(move || begun.begin_custody_member_drain_as(&begin_owner, &begin_target)).await?;
    let budgets = residence_budgets(vault)?;
    let Some(mut rpc) = ResidenceRpc::connect(vault, config, budgets).await? else {
        return Err(TransportError::Storage("home node offline".into()));
    };
    let PeerMachine::Proven { machine: home, .. } = rpc.home else {
        return Err(refused());
    };
    let params = json!({
        "targetId": ticket.target_id.as_str(),
        "setRevision": ticket.set_revision,
        "position": AckPosition::of(&ticket.position),
        "operationId": crate::entity_id::bytes_to_hex_lower(&ticket.operation_id),
        "token": base64::engine::general_purpose::STANDARD.encode(ticket.token.expose()),
    });
    let ack = match rpc.call("residence.custody.drain", params).await? {
        Ok(reply) => {
            serde_json::from_value::<DrainReply>(reply)
                .map_err(|_| refused())?
                .ack
        }
        Err(_) => return Err(refused()),
    };
    let residence = TargetSpec::residence(home);
    if ack.target_id != ticket.target_id.as_str()
        || ack.target_id != residence.id().as_str()
        || ack.set_revision != ticket.set_revision
        || ack.position != AckPosition::of(&ticket.position)
        || ack.operation_id != crate::entity_id::bytes_to_hex_lower(&ticket.operation_id)
        || ack.evidence.kind != EvidenceKind::ResidenceSweep
    {
        return Err(refused());
    }
    let committed = Arc::clone(vault);
    let commit_owner = owner.clone();
    blocking(move || committed.commit_custody_member_drain_as(&commit_owner, &ack)).await
}

/// What the home holds of `lineage`; `None` when it refused the read.
async fn home_held(
    rpc: &mut ResidenceRpc,
    lineage: &Value,
) -> Result<Option<HeldReply>, TransportError> {
    match rpc
        .call("residence.custody.status", lineage.clone())
        .await?
    {
        Ok(reply) => Ok(Some(
            serde_json::from_value::<HeldReply>(reply).map_err(|_| refused())?,
        )),
        Err(_) => Ok(None),
    }
}

/// Ships `batch` to the home `home`: the frames it lacks, the head in parts,
/// then the commit. `Ok(Err(_))` says why the home stays pending; an ack
/// that is not the home's own `ResidenceSweep` for this target never comes
/// back.
async fn upload(
    rpc: &mut ResidenceRpc,
    batch: CustodyBatch,
    home: EntityId,
) -> Result<Result<Uploaded, TargetPending>, TransportError> {
    let (vault_hex, namespace_hex) = batch.lineage().to_hex();
    let lineage = json!({"vault": vault_hex, "namespace": namespace_hex});
    let Some(held) = home_held(rpc, &lineage).await? else {
        let why = "the residence home refused its custody status read";
        return Ok(Err(pending(PendingCode::Denied, why)));
    };
    if held.covers(&batch) {
        return Ok(Ok(Uploaded::Covered));
    }
    let after = held.seq.unwrap_or(0);
    if after > batch.position().seq {
        let why = "the residence home holds a newer custody position: another writer moved it";
        return Ok(Err(pending(PendingCode::Moved, why)));
    }
    let (batch, frames) = tokio::task::spawn_blocking(move || {
        let frames = batch.frames_after(after);
        (batch, frames)
    })
    .await
    .map_err(|_| stopped())?;
    // The frames in calls no larger than a sealed bundle part.
    let mut groups: Vec<Vec<Value>> = Vec::new();
    let mut size = SEALED_BUNDLE_PUT_PART_MAX;
    for (seq, frame) in frames.map_err(storage)? {
        if size.saturating_add(frame.len()) > SEALED_BUNDLE_PUT_PART_MAX {
            groups.push(Vec::new());
            size = 0;
        }
        size = size.saturating_add(frame.len());
        let encoded = base64::engine::general_purpose::STANDARD.encode(frame);
        if let Some(group) = groups.last_mut() {
            group.push(json!([seq, encoded]));
        }
    }
    for frames in groups {
        let params = json!({"vault": vault_hex, "namespace": namespace_hex, "frames": frames});
        if rpc.call("residence.custody.frames", params).await?.is_err() {
            let why = "the residence home refused a custody log frame";
            return Ok(Err(pending(PendingCode::Denied, why)));
        }
    }
    let operation = crate::entity_id::bytes_to_hex_lower(&batch.operation_id());
    let mut offset = 0u64;
    for part in batch.head().chunks(SEALED_BUNDLE_PUT_PART_MAX) {
        let params = json!({
            "vault": vault_hex,
            "namespace": namespace_hex,
            "operation": operation,
            "offset": offset,
            "part": base64::engine::general_purpose::STANDARD.encode(part),
        });
        let staged = match rpc.call("residence.custody.put", params).await? {
            Ok(reply) => serde_json::from_value::<StagedReply>(reply).map_err(|_| refused())?,
            Err(_) => {
                let why = "the residence home refused a custody head part";
                return Ok(Err(pending(PendingCode::Denied, why)));
            }
        };
        offset = offset.saturating_add(part.len() as u64);
        if staged.staged < offset {
            return Err(refused());
        }
    }
    let params = json!({
        "setRevision": batch.set_revision(),
        "position": AckPosition::of(&batch.position()),
        "headObjectId": crate::entity_id::bytes_to_hex_lower(&batch.head_object_id()),
        "operationId": operation,
    });
    let ack = match rpc.call("residence.custody.commit", params).await? {
        Ok(reply) => {
            serde_json::from_value::<CommitReply>(reply)
                .map_err(|_| refused())?
                .ack
        }
        Err(_) => {
            // A newer pass's commit may have landed since the status read:
            // the home refuses an older head under its lock (FIX 6394).
            if home_held(rpc, &lineage)
                .await?
                .is_some_and(|held| held.covers(&batch))
            {
                return Ok(Ok(Uploaded::Covered));
            }
            let why = "the residence home refused the custody commit";
            return Ok(Err(pending(PendingCode::Failed, why)));
        }
    };
    if ack.attester != home.to_hex()
        || ack.evidence.kind != EvidenceKind::ResidenceSweep
        || ack.target_id != TargetSpec::residence(home).id().as_str()
    {
        let why = "the residence home's ack is not its own sweep of this target";
        return Ok(Err(pending(PendingCode::Failed, why)));
    }
    Ok(Ok(Uploaded::Acked(batch, ack)))
}
