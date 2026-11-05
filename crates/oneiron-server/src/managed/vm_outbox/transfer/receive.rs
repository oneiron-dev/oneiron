//! Descriptor-only admission and body receipt for one complete carrier set.

use super::{
    Carrier, Link, Plan, Staged, Taken, VmOutboxDescriptor, VmOutboxFrame, VmOutboxOperation,
    VmOutboxOutcome, VmOutboxRefusal, descriptor_length, set_incomplete,
};
use std::fs::File;
use std::io::{Read, Write};

impl Carrier {
    /// Offers are collected and staged as one set before a go permits any
    /// body. An early failure answers the whole set without reading data.
    pub(super) fn receive_set<S: Read + Write>(
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
            taken.push(self.prepare_take(next, &root));
            if last {
                break;
            }
            next = match link.read()? {
                Some(VmOutboxFrame::Offer(transfer)) => transfer,
                _ => anyhow::bail!("an outbox set ended before its commit"),
            };
        }
        if set_incomplete(&taken).is_none() {
            link.send(&VmOutboxFrame::Go)?;
            link.flush()?;
            for item in &mut taken {
                self.read_taken(link, item)?;
            }
        }
        let acks = self.commit(kind, root.ok().flatten(), taken);
        for ack in acks {
            link.send(&VmOutboxFrame::Ack(ack))?;
        }
        link.flush()
    }

    /// The original descriptor judgement, with a put's real staging file
    /// allocated before any body is requested. That same file reaches land.
    fn prepare_take(
        &self,
        descriptor: VmOutboxDescriptor,
        root: &std::io::Result<Option<File>>,
    ) -> Taken {
        let answered = |descriptor, member, outcome| Taken {
            descriptor,
            member,
            plan: Plan::Answer(outcome),
        };
        let member = match descriptor.validate(self.side.peer()) {
            Ok(member) => member,
            Err(outcome) => return answered(descriptor, None, outcome),
        };
        if let Some(outcome) = self.decide(&descriptor, &member, root) {
            return answered(descriptor, Some(member), outcome);
        }
        let Ok(Some(root)) = root else {
            let outcome = VmOutboxOutcome::deferred(
                super::VmOutboxDeferral::TargetUnavailable,
                &format!("this end's {} root", descriptor.kind),
                "this end has no root for the kind yet",
            );
            return answered(descriptor, Some(member), outcome);
        };
        if descriptor.operation != VmOutboxOperation::Put {
            return Taken {
                descriptor,
                member: Some(member),
                plan: Plan::Remove,
            };
        }
        let staged = Staged::new(root, &descriptor.member, self.owner, descriptor.transfer_id)
            .and_then(|staged| {
                staged.reserve(descriptor.length)?;
                Ok(staged)
            });
        let plan = match staged {
            Ok(staged) => Plan::Put(Box::new(staged)),
            Err(error) => Plan::Answer(self.io_outcome(descriptor.kind, &error)),
        };
        Taken {
            descriptor,
            member: Some(member),
            plan,
        }
    }

    /// Reads exactly the offered put bodies after a go. Already-answered
    /// members are drained as before; a failed stage still drains its body.
    fn read_taken<S: Read + Write>(
        &self,
        link: &mut Link<S>,
        item: &mut Taken,
    ) -> anyhow::Result<()> {
        if item.descriptor.operation != VmOutboxOperation::Put {
            return Ok(());
        }
        let Plan::Put(staged) = &mut item.plan else {
            link.read_data(descriptor_length(&item.descriptor), None)?;
            return Ok(());
        };
        let outcome = match link.read_data(item.descriptor.length, Some(staged.as_mut()))? {
            Some(error) => Some(self.io_outcome(item.descriptor.kind, &error)),
            None if staged.version().blake3 != item.descriptor.blake3 => {
                Some(VmOutboxOutcome::refused(
                    VmOutboxRefusal::DigestMismatch,
                    "the bytes do not hash to the transfer's digest",
                ))
            }
            None => None,
        };
        if let Some(outcome) = outcome {
            item.plan = Plan::Answer(outcome);
        }
        Ok(())
    }
}
