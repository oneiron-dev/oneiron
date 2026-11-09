//! Native OCI sessions in a no-NIC Firecracker VM. The OCI digest is bound
//! by host configuration to a pinned, bootable rootfs containing the guest agent.

use super::launch;
use super::refused;
use crate::{
    Result,
    code_sandbox::{
        SandboxGuestTier,
        microvm::{ExecutionBudget, GuestImage, MicroVmHandle},
    },
};
use oneiron_container::{
    EgressRelay, FenceProof, GuestSeccomp, GuestSpec, SessionLease, SessionManifest,
    SessionTransport, image_release,
};
use serde::Deserialize;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    ffi::OsString,
    io::{Read, Write},
    path::PathBuf,
    process::Child,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

