//! The carrier's session on one connection: the hello, then turns. Each end
//! sends its sets and reads an ack for each transfer; it takes the other
//! end's sets, publishes each whole, and acks each transfer once the set is
//! durable or why it is not. Each end holds only its own local locks, and
//! only for a local commit, never across a round trip.

pub(super) use super::link::Link;
use super::link::SourceReadError;
use super::local::{self, Staged};
use super::scan::{OutOp, OutSet};
use super::source_check;
use super::store::{Cached, Received, Version};
use super::{Carrier, Mode};
use oneiron_vault_contract::vm_outbox::{
    VM_OUTBOX_WIRE_REVISION, VmOutboxAck, VmOutboxDeferral, VmOutboxDescriptor, VmOutboxFrame,
    VmOutboxKind, VmOutboxMember, VmOutboxOperation, VmOutboxOutcome, VmOutboxRefusal,
    VmOutboxSide,
};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Arc;

/// One transfer the other end sent, taken and waiting for its set.
struct Taken {
    descriptor: VmOutboxDescriptor,
    member: Option<VmOutboxMember>,
    plan: Plan,
}

enum Plan {
    /// Answered without a change here: refused, deferred, or already held.
    Answer(VmOutboxOutcome),
    /// Boxed: a staged put holds its running hasher.
    Put(Box<Staged>),
    Remove,
}

impl Carrier {
    /// The guest's session: its hello, then turns until the connection ends
    /// or the end drains. Each turn opens with the engine's registered
    /// backup label, once there is one, so the host learns a registration
    /// made after the session began.
    pub(super) fn guest_session<S: Read + Write>(
        &mut self,
        link: &mut Link<S>,
        vault: &str,
    ) -> anyhow::Result<()> {
        link.send(&VmOutboxFrame::Hello {
            wire_revision: VM_OUTBOX_WIRE_REVISION,
            vault: vault.to_owned(),
        })?;
        link.flush()?;
        match link.read()? {
            Some(VmOutboxFrame::Welcome { wire_revision })
                if wire_revision == VM_OUTBOX_WIRE_REVISION => {}
            Some(VmOutboxFrame::Refused { code, detail, .. }) => {
                anyhow::bail!("the host refused the outbox carrier ({code:?}): {detail}")
            }
            _ => anyhow::bail!("the host answered the outbox carrier's hello out of turn"),
        }
        loop {
            if !self.gate.proceed() {
                return Ok(());
            }
            if let Some(label) = self.roots.backup_label() {
                link.send(&VmOutboxFrame::BackupRegistered { label })?;
            }
            let sent = self.send_sets(link)?;
            link.send(&VmOutboxFrame::Pull)?;
            link.flush()?;
            let mut taken = false;
            loop {
                match link.read()? {
                    Some(VmOutboxFrame::Transfer(first)) => {
                        self.receive_set(link, first)?;
                        taken = true;
                    }
                    Some(VmOutboxFrame::Done) => break,
                    None => anyhow::bail!("the host closed the outbox carrier"),
                    Some(_) => anyhow::bail!("the host sent an outbox frame out of turn"),
                }
            }
            if !sent && !taken && !self.gate.idle() {
                return Ok(());
            }
        }
    }

    /// The host's session for the VM bound to `vault`, until the guest
    /// closes the connection. A hello naming another vault is refused; a
    /// backup label the welcomed guest names is kept for `vault` before
    /// anything after it is taken. While one it names is not kept, the
    /// session's backup sets wait and its other kinds go on.
    pub(super) fn host_session<S: Read + Write>(
        &mut self,
        link: &mut Link<S>,
        vault: &str,
    ) -> anyhow::Result<()> {
        let refusal = match link.read()? {
            None => return Ok(()),
            Some(VmOutboxFrame::Hello {
                wire_revision,
                vault: named,
            }) => {
                if wire_revision != VM_OUTBOX_WIRE_REVISION {
                    Some((
                        VmOutboxRefusal::UnsupportedRevision,
                        format!("the host speaks wire revision {VM_OUTBOX_WIRE_REVISION}"),
                    ))
                } else if named != vault {
                    Some((
                        VmOutboxRefusal::WrongVault,
                        "this port is bound to another vault".to_owned(),
                    ))
                } else {
                    None
                }
            }
            Some(_) => anyhow::bail!("the guest opened the outbox carrier without a hello"),
        };
        if let Some((code, detail)) = refusal {
            link.send(&VmOutboxFrame::Refused {
                wire_revision: VM_OUTBOX_WIRE_REVISION,
                code,
                detail,
            })?;
            return link.flush();
        }
        link.send(&VmOutboxFrame::Welcome {
            wire_revision: VM_OUTBOX_WIRE_REVISION,
        })?;
        link.flush()?;
        // A session's backup sets go until a label named in it is not kept.
        self.backup_wait = None;
        loop {
            match link.read()? {
                None => return Ok(()),
                Some(VmOutboxFrame::BackupRegistered { label }) => {
                    self.bind_backup_label(vault, label);
                }
                Some(VmOutboxFrame::Transfer(first)) => self.receive_set(link, first)?,
                Some(VmOutboxFrame::Pull) => {
                    if self.gate.proceed() {
                        self.send_sets(link)?;
                    }
                    link.send(&VmOutboxFrame::Done)?;
                    link.flush()?;
                }
                Some(_) => anyhow::bail!("the guest sent an outbox frame out of turn"),
            }
        }
    }

    /// Sends each set this end has; `true` when any went. Once a set's
    /// records do not write, its kind's later sets wait with it.
    fn send_sets<S: Read + Write>(&mut self, link: &mut Link<S>) -> anyhow::Result<bool> {
        let mut sent = false;
        for set in self.outgoing() {
            if !self.gate.proceed() {
                break;
            }
            if self.record_waits(set.kind).is_some() {
                continue;
            }
            sent |= self.send_set(link, set)?;
        }
        Ok(sent)
    }

    /// One set: each put's file held first, identities recorded before a
    /// byte goes, then the transfers, then one ack each. When an identity
    /// does not record, none of the set goes: what was recorded is kept, the
    /// set is paced and its kind waits on its records. When a put's file
    /// does not open, none of the set goes either and nothing is recorded:
    /// the set is paced, and the session and the other sets go on.
    fn send_set<S: Read + Write>(
        &mut self,
        link: &mut Link<S>,
        set: OutSet,
    ) -> anyhow::Result<bool> {
        let Ok(Some(root)) = self.roots.open(set.kind) else {
            return Ok(false);
        };
        let mut ready: Vec<(OutOp, Option<File>)> = Vec::new();
        for op in set.ops {
            if op.operation == VmOutboxOperation::Remove {
                ready.push((op, None));
                continue;
            }
            // A put whose file changed or went since its scan waits for the
            // next scan; one whose file does not open holds back its set.
            match local::open_member(&root, &op.member, Some(self.owner)) {
                Ok(Some((file, stamp))) if Some(stamp) == op.stamp => {
                    ready.push((op, Some(file)));
                }
                Ok(_) => {}
                Err(error) => {
                    drop(ready);
                    if let VmOutboxOutcome::Deferred {
                        code,
                        bound,
                        detail,
                    } = self.io_outcome(set.kind, &error)
                    {
                        self.say(
                            set.kind,
                            &op.member,
                            &format!(
                                "its set waits: it does not open ({code:?}) on {bound}: {detail}"
                            ),
                        );
                    }
                    self.pace(set.kind, &set.set);
                    return Ok(false);
                }
            }
        }
        if ready.is_empty() {
            return Ok(false);
        }
        let transfers = match self.prepare(set.kind, &set.set, ready) {
            Ok(transfers) => transfers,
            Err(error) => {
                self.records_failed(set.kind, Some(&set.set), &error);
                return Ok(false);
            }
        };
        for (descriptor, file) in &transfers {
            link.send(&VmOutboxFrame::Transfer(descriptor.clone()))?;
            if let Some(file) = file
                && let Err(error) = link.send_data(file, descriptor.length)
            {
                // Its frame has started, so the session ends; a member that
                // did not read paces its set first, so the next session
                // sends the kinds after it (FIX 7892).
                if let Some(read) = error.downcast_ref::<SourceReadError>() {
                    let what = format!(
                        "its set {} waits: it did not read as it was sent: {read}",
                        set.set
                    );
                    self.say(set.kind, &descriptor.member, &what);
                    self.pace(set.kind, &set.set);
                }
                return Err(error);
            }
        }
        link.flush()?;
        let mut again = false;
        for (descriptor, _) in &transfers {
            let ack = match link.read()? {
                Some(VmOutboxFrame::Ack(ack)) if ack.answers(descriptor) => ack,
                _ => anyhow::bail!("the other end did not ack an outbox transfer in order"),
            };
            again |= source_check::paces(&ack.outcome);
            self.take_ack(descriptor, ack);
        }
        if again {
            self.pace(set.kind, &set.set);
        } else {
            self.paced.remove(&(set.kind, set.set));
        }
        Ok(true)
    }

    /// Records `ready`, the members of `kind`'s `set` in their order, under
    /// this end's gate: fresh transfer ids reserved first, then each one's
    /// transfer as sent and not acked, before any goes. A reservation or
    /// record that does not write is returned, and what was written before
    /// it is kept: a reserved id is not handed out again, and a recorded
    /// transfer is replayed with its identity.
    fn prepare(
        &mut self,
        kind: VmOutboxKind,
        set: &str,
        ready: Vec<(OutOp, Option<File>)>,
    ) -> std::io::Result<Vec<(VmOutboxDescriptor, Option<File>)>> {
        let gate = Arc::clone(&self.gate);
        let held = gate.hold();
        let last = ready.len().saturating_sub(1);
        let fresh = ready.iter().filter(|(op, _)| op.replay.is_none()).count() as u64;
        let mut next = if fresh > 0 {
            self.store.allocate(fresh)?
        } else {
            0
        };
        let mut transfers = Vec::with_capacity(ready.len());
        for (index, (op, file)) in ready.into_iter().enumerate() {
            let transfer_id = op.replay.unwrap_or_else(|| {
                next += 1;
                next - 1
            });
            let descriptor = VmOutboxDescriptor {
                wire_revision: VM_OUTBOX_WIRE_REVISION,
                transfer_id,
                kind,
                member: op.member,
                revision: op.revision,
                length: if file.is_some() { op.version.length } else { 0 },
                blake3: op.version.blake3,
                operation: op.operation,
                expected_digest: op.expected,
                set_id: set.to_owned(),
                commit_set: index == last,
            };
            let mut record = self.store.get(kind, &descriptor.member);
            record.floor = record.floor.max(descriptor.revision);
            record.pending = Some(VmOutboxDescriptor {
                commit_set: false,
                ..descriptor.clone()
            });
            self.store.put(kind, &descriptor.member, record)?;
            transfers.push((descriptor, file));
        }
        drop(held);
        Ok(transfers)
    }

    /// Records the other end's answer to `transfer`: a durable one is the
    /// agreed version and retires the retransmission state, a deferral keeps
    /// it and writes nothing, a refusal drops it and is not sent again until
    /// the member changes, but a put whose bytes did not hash to its digest
    /// on arrival is read again and resent at its set's pacing (FIX 11075).
    /// A durable or refused answer that does not record stands, and its exact
    /// record is kept to write again: the kind waits on its carrier records
    /// both ways until that record is written, before its next scan, and the
    /// session goes on to the set's other acks (FIX 7624).
    fn take_ack(&mut self, transfer: &VmOutboxDescriptor, ack: VmOutboxAck) {
        let (kind, member) = (transfer.kind, transfer.member.as_str());
        let gate = Arc::clone(&self.gate);
        let held = gate.hold();
        let mut record = self.store.get(kind, member);
        match ack.outcome {
            VmOutboxOutcome::Durable => {
                record.revision = record.revision.max(transfer.revision);
                record.agreed = (transfer.operation == VmOutboxOperation::Put).then(|| Version {
                    blake3: transfer.blake3.clone(),
                    length: transfer.length,
                });
                record.pending = None;
                record.refused = None;
                self.settled(kind, member);
            }
            VmOutboxOutcome::Deferred {
                code,
                bound,
                detail,
            } => {
                self.say(
                    kind,
                    member,
                    &format!("deferred ({code:?}) on {bound}: {detail}"),
                );
                return;
            }
            VmOutboxOutcome::Refused { code, detail } => {
                self.say(kind, member, &format!("refused ({code:?}): {detail}"));
                record.pending = None;
                if !source_check::recheck(&mut record, transfer, code) {
                    record.refused = Some(format!(
                        "{}:{}",
                        operation_name(transfer.operation),
                        transfer.blake3
                    ));
                }
            }
        }
        if let Err(error) = self.store.put(kind, member, record.clone()) {
            self.received_failed(kind, member, record, &error);
        }
        drop(held);
    }

    /// Takes one set the other end sends, `first` its first transfer, and
    /// answers each of its transfers.
    fn receive_set<S: Read + Write>(
        &mut self,
        link: &mut Link<S>,
        first: VmOutboxDescriptor,
    ) -> anyhow::Result<()> {
        let (kind, set_id) = (first.kind, first.set_id.clone());
        let root = self.roots.open(kind);
        let mut taken = Vec::new();
        let mut next = first;
        loop {
            anyhow::ensure!(
                next.kind == kind && next.set_id == set_id,
                "an outbox set changed its kind or id before its commit"
            );
            let last = next.commit_set;
            taken.push(self.take(link, next, &root)?);
            if last {
                break;
            }
            next = match link.read()? {
                Some(VmOutboxFrame::Transfer(transfer)) => transfer,
                _ => anyhow::bail!("an outbox set ended before its commit"),
            };
        }
        let acks = self.commit(kind, root.ok().flatten(), taken);
        for ack in acks {
            link.send(&VmOutboxFrame::Ack(ack))?;
        }
        link.flush()
    }

    /// Reads one transfer and stages a put, or decides its answer outright.
    fn take<S: Read + Write>(
        &mut self,
        link: &mut Link<S>,
        descriptor: VmOutboxDescriptor,
        root: &std::io::Result<Option<File>>,
    ) -> anyhow::Result<Taken> {
        let put = descriptor.operation == VmOutboxOperation::Put;
        let answered = |link: &mut Link<S>,
                        descriptor: VmOutboxDescriptor,
                        member: Option<VmOutboxMember>,
                        outcome: VmOutboxOutcome| {
            if put {
                link.read_data(descriptor_length(&descriptor), None)?;
            }
            anyhow::Ok(Taken {
                descriptor,
                member,
                plan: Plan::Answer(outcome),
            })
        };
        let member = match descriptor.validate(self.side.peer()) {
            Ok(member) => member,
            Err(outcome) => return answered(link, descriptor, None, outcome),
        };
        if let Some(outcome) = self.decide(&descriptor, &member, root) {
            return answered(link, descriptor, Some(member), outcome);
        }
        let Ok(Some(root)) = root else {
            let outcome = VmOutboxOutcome::deferred(
                VmOutboxDeferral::TargetUnavailable,
                &format!("this end's {} root", descriptor.kind),
                "this end has no root for the kind yet",
            );
            return answered(link, descriptor, Some(member), outcome);
        };
        if !put {
            return Ok(Taken {
                descriptor,
                member: Some(member),
                plan: Plan::Remove,
            });
        }
        let mut staged =
            match Staged::new(root, &descriptor.member, self.owner, descriptor.transfer_id) {
                Ok(staged) => staged,
                Err(error) => {
                    let outcome = self.io_outcome(descriptor.kind, &error);
                    return answered(link, descriptor, Some(member), outcome);
                }
            };
        if let Some(error) = link.read_data(descriptor.length, Some(&mut staged))? {
            drop(staged);
            let outcome = self.io_outcome(descriptor.kind, &error);
            return Ok(answer(descriptor, member, outcome));
        }
        if staged.version().blake3 != descriptor.blake3 {
            drop(staged);
            let outcome = VmOutboxOutcome::refused(
                VmOutboxRefusal::DigestMismatch,
                "the bytes do not hash to the transfer's digest",
            );
            return Ok(answer(descriptor, member, outcome));
        }
        Ok(Taken {
            descriptor,
            member: Some(member),
            plan: Plan::Put(Box::new(staged)),
        })
    }

    /// The answer `transfer` gets without a change here, if it gets one: a
    /// replay of one taken before, one a newer change already passed, or one
    /// with nowhere to go yet, a backup set's while the label the guest
    /// last named is not kept and one of a kind waiting on this end's
    /// carrier records included.
    fn decide(
        &self,
        transfer: &VmOutboxDescriptor,
        member: &VmOutboxMember,
        root: &std::io::Result<Option<File>>,
    ) -> Option<VmOutboxOutcome> {
        if !self.roots.takes(transfer.kind, &transfer.member) {
            return Some(VmOutboxOutcome::deferred(
                VmOutboxDeferral::TargetUnavailable,
                "the registered backup plan",
                "this end carries no backup of that label yet",
            ));
        }
        if let Some(waits) = self
            .backup_waits(transfer.kind)
            .or_else(|| self.record_waits(transfer.kind))
        {
            return Some(waits.clone());
        }
        let record = self.store.get(transfer.kind, &transfer.member);
        if let Some(received) = &record.received
            && received.transfer_id == transfer.transfer_id
        {
            let same = received.blake3 == transfer.blake3 && received.revision == transfer.revision;
            return Some(if same {
                VmOutboxOutcome::Durable
            } else {
                VmOutboxOutcome::refused(
                    VmOutboxRefusal::IdentityConflict,
                    "that transfer id was taken with other content",
                )
            });
        }
        // A newer change stands; at one revision the origin's change wins.
        let newer = transfer.revision > record.revision
            || (transfer.revision == record.revision && member.origin == self.side.peer());
        if !newer {
            return Some(VmOutboxOutcome::Durable);
        }
        match root {
            Ok(Some(_)) => None,
            Ok(None) => Some(VmOutboxOutcome::deferred(
                VmOutboxDeferral::TargetUnavailable,
                &format!("this end's {} root", transfer.kind),
                "this end has no root for the kind yet",
            )),
            Err(error) => Some(self.io_outcome(transfer.kind, error)),
        }
    }

    /// A local failure as a deferral naming its bound.
    fn io_outcome(&self, kind: VmOutboxKind, error: &std::io::Error) -> VmOutboxOutcome {
        let side = self.side_name();
        local_deferral(
            error,
            &format!("free space on the {side}'s {kind} filesystem"),
            &format!("the {side}'s {kind} root"),
        )
    }

    /// A carrier record that did not write, as a deferral naming this end's
    /// record store, not a kind's root.
    pub(super) fn records_outcome(&self, error: &std::io::Error) -> VmOutboxOutcome {
        let side = self.side_name();
        local_deferral(
            error,
            &format!("free space on the {side}'s carrier record filesystem"),
            &format!("the {side}'s carrier records"),
        )
    }

    fn side_name(&self) -> &'static str {
        match self.side {
            VmOutboxSide::Guest => "guest",
            VmOutboxSide::Host => "host",
        }
    }

    /// Publishes a taken set whole, in its order, under this end's gate and,
    /// for training, its outbox lock; or publishes none of it. Returns one
    /// ack per transfer.
    fn commit(
        &mut self,
        kind: VmOutboxKind,
        root: Option<File>,
        taken: Vec<Taken>,
    ) -> Vec<VmOutboxAck> {
        let gate = Arc::clone(&self.gate);
        let held = gate.hold();
        let lock = match (&root, kind) {
            (Some(root), VmOutboxKind::Training) => local::lock_training(root),
            _ => Ok(None),
        };
        let blocked = if *held == Mode::Draining {
            Some(VmOutboxOutcome::deferred(
                VmOutboxDeferral::Draining,
                "this end's stop",
                "the carrier denies new transfers while it stops",
            ))
        } else if let Err(error) = &lock {
            Some(self.io_outcome(kind, error))
        } else {
            taken.iter().find_map(|item| match &item.plan {
                Plan::Answer(VmOutboxOutcome::Durable) => None,
                Plan::Answer(_) => Some(VmOutboxOutcome::deferred(
                    VmOutboxDeferral::SetIncomplete,
                    &format!("the set's member {}", item.descriptor.member),
                    "another transfer of the set was not taken",
                )),
                Plan::Put(_) | Plan::Remove => None,
            })
        };
        let checked = match (&blocked, &root) {
            (None, Some(root)) => self.check_local(root, &taken),
            _ => Vec::new(),
        };
        let mismatch = checked.iter().any(Option::is_some);
        // A retirement refused here, the member's origin, for a copy the
        // other end does not know offers this end's copy again (FIX 6686).
        for (item, check) in taken.iter().zip(&checked) {
            let origin = item
                .member
                .as_ref()
                .is_some_and(|member| member.origin == self.side);
            let unknown = matches!(
                check,
                Some(VmOutboxOutcome::Refused {
                    code: VmOutboxRefusal::ExpectedDigestMismatch,
                    ..
                })
            );
            if origin && unknown {
                self.reoffer(kind, &item.descriptor.member);
            }
        }
        let mut acks = Vec::with_capacity(taken.len());
        for (index, item) in taken.into_iter().enumerate() {
            let outcome = match item.plan {
                Plan::Answer(outcome) => outcome,
                plan if blocked.is_some() || mismatch => {
                    if let Plan::Put(staged) = plan {
                        drop(staged);
                    }
                    checked
                        .get(index)
                        .cloned()
                        .flatten()
                        .or_else(|| blocked.clone())
                        .unwrap_or_else(|| {
                            VmOutboxOutcome::deferred(
                                VmOutboxDeferral::SetIncomplete,
                                "the set's local versions",
                                "another member of the set holds a version this end does not know",
                            )
                        })
                }
                plan => match root.as_ref() {
                    Some(root) => self.apply(root, &item.descriptor, item.member.as_ref(), plan),
                    None => VmOutboxOutcome::Durable,
                },
            };
            acks.push(VmOutboxAck::answering(&item.descriptor, outcome));
        }
        drop(lock);
        drop(held);
        acks
    }

    /// Per transfer, a refusal when this end holds a version of its member
    /// the transfer does not name and the carrier never agreed on.
    fn check_local(&self, root: &File, taken: &[Taken]) -> Vec<Option<VmOutboxOutcome>> {
        taken
            .iter()
            .map(|item| {
                if matches!(item.plan, Plan::Answer(_)) {
                    return None;
                }
                let transfer = &item.descriptor;
                let record = self.store.get(transfer.kind, &transfer.member);
                let held = match local::open_member(root, &transfer.member, None) {
                    Ok(Some((file, stamp))) => match &record.cached {
                        Some(cached) if cached.stamp == stamp => {
                            Some(cached.version.blake3.clone())
                        }
                        _ => local::digest(&file).ok().map(|version| version.blake3),
                    },
                    _ => return None,
                }?;
                let known = Some(&held) == transfer.expected_digest.as_ref()
                    || record
                        .agreed
                        .as_ref()
                        .is_some_and(|agreed| agreed.blake3 == held)
                    || (transfer.operation == VmOutboxOperation::Put && held == transfer.blake3);
                (!known).then(|| {
                    VmOutboxOutcome::refused(
                        VmOutboxRefusal::ExpectedDigestMismatch,
                        "this end holds a version of the member the transfer does not name",
                    )
                })
            })
            .collect()
    }

    /// Makes one checked change and records it before it is acked. When its
    /// record does not write, the change stays made, the transfer is
    /// deferred on this end's carrier records and its kind waits on them
    /// until that record is written again (FIX 7891).
    fn apply(
        &mut self,
        root: &File,
        transfer: &VmOutboxDescriptor,
        member: Option<&VmOutboxMember>,
        plan: Plan,
    ) -> VmOutboxOutcome {
        let protected = member.is_some_and(|member| member.protected);
        let published = match plan {
            Plan::Put(staged) => (*staged).publish(self.owner, protected).map(Some),
            Plan::Remove => local::remove(root, transfer.kind, &transfer.member).map(|()| None),
            Plan::Answer(outcome) => return outcome,
        };
        let stamp = match published {
            Ok(stamp) => stamp,
            Err(error) => return self.io_outcome(transfer.kind, &error),
        };
        let mut record = self.store.get(transfer.kind, &transfer.member);
        record.revision = record.revision.max(transfer.revision);
        let version = (transfer.operation == VmOutboxOperation::Put).then(|| Version {
            blake3: transfer.blake3.clone(),
            length: transfer.length,
        });
        record.cached = stamp
            .zip(version.clone())
            .map(|(stamp, version)| Cached { stamp, version });
        record.agreed = version;
        record.received = Some(Received {
            transfer_id: transfer.transfer_id,
            revision: transfer.revision,
            blake3: transfer.blake3.clone(),
        });
        if record
            .pending
            .as_ref()
            .is_some_and(|pending| pending.revision <= transfer.revision)
        {
            record.pending = None;
        }
        record.refused = None;
        match self
            .store
            .put(transfer.kind, &transfer.member, record.clone())
        {
            Ok(()) => {
                self.received_written(transfer.kind, &transfer.member);
                VmOutboxOutcome::Durable
            }
            Err(error) => {
                self.received_failed(transfer.kind, &transfer.member, record, &error);
                self.records_outcome(&error)
            }
        }
    }
}

/// `error` as a deferral: on `full` when its filesystem is full, else on
/// `bound`.
fn local_deferral(error: &std::io::Error, full: &str, bound: &str) -> VmOutboxOutcome {
    if matches!(error.raw_os_error(), Some(libc::ENOSPC | libc::EDQUOT)) {
        return VmOutboxOutcome::deferred(
            VmOutboxDeferral::Capacity,
            full,
            "the filesystem is full; the work is kept",
        );
    }
    VmOutboxOutcome::deferred(VmOutboxDeferral::Io, bound, &error.to_string())
}

/// The bytes a transfer's line says follow it: none for a remove.
fn descriptor_length(descriptor: &VmOutboxDescriptor) -> u64 {
    match descriptor.operation {
        VmOutboxOperation::Put => descriptor.length,
        VmOutboxOperation::Remove => 0,
    }
}

/// A transfer whose data was read, answered without a change.
fn answer(
    descriptor: VmOutboxDescriptor,
    member: VmOutboxMember,
    outcome: VmOutboxOutcome,
) -> Taken {
    Taken {
        descriptor,
        member: Some(member),
        plan: Plan::Answer(outcome),
    }
}

fn operation_name(operation: VmOutboxOperation) -> &'static str {
    match operation {
        VmOutboxOperation::Put => "put",
        VmOutboxOperation::Remove => "remove",
    }
}
