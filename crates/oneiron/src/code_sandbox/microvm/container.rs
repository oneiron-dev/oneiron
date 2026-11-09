//! OCI code and browser sessions on Linux hosts without a usable microVM.

use super::{backend::backend_error, *};
use crate::Result;
use crate::code_sandbox::{SandboxBoundaryContract, SandboxMountTable, SandboxProposalWrite};
use crate::engine_executor::{CANCEL_POLL_SLICE, StepCancellation};
use oneiron_container::{
    ContainerRuntime, EgressRelay, GuestLimits, GuestSeccomp, GuestSession, GuestSpec, ImageRef,
    SessionManifest, SessionTransport,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

