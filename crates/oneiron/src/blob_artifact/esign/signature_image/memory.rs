pub(super) fn native_admission(
    input: u64,
) -> impl FnMut(
    super::SignatureImagePlan,
    u64,
) -> std::result::Result<(), crate::host_memory::MemoryRefusal> {
    let memory = crate::host_memory::MachineMemory::process();
    let mut lease = memory.empty_lease();
    move |plan: super::SignatureImagePlan, header_allocated: u64| {
        if header_allocated != 0 {
            lease.materialized(header_allocated, header_allocated);
            return Ok(());
        }
        let target = plan
            .peak_bytes(input)
            .unwrap_or(u64::MAX)
            .saturating_sub(input);
        // The decoder has been dropped before a full-plan callback. Release
        // its reservation too before joining the shared FIFO line again.
        drop(std::mem::replace(&mut lease, memory.empty_lease()));
        lease = memory.lease_untimed(target, &|| false)?;
        Ok(())
    }
}

pub(super) fn refused(refusal: crate::host_memory::MemoryRefusal) -> crate::Error {
    match refusal {
        crate::host_memory::MemoryRefusal::Floor { needed, available } => {
            crate::Error::Artifact(crate::error::ArtifactError::MemoryFloorRefused {
                detail: format!(
                    "signature image needs {needed} bytes, only {available} fit past the reserve"
                ),
            })
        }
        crate::host_memory::MemoryRefusal::WaitedOut { needed, waited } => {
            crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("signature image waited {waited:?} for {needed} bytes"),
            ))
        }
    }
}
