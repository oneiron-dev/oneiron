//! The bootstrap's half of a vault VM's guest network (FIX 6808,
//! [`oneiron_vault_contract::vm::VmGuestNetworkConfig`]): the one NIC the
//! host attached, set up from the config drive's view of the supervisor's
//! plan while the bootstrap is root, before the vault's key goes in and
//! before any engine or companion starts.
//!
//! The NIC is the one link whose MAC is the plan's, never a name such as
//! `eth0`; none, or more than one, refuses the boot. IPv6 is turned off on it
//! before it comes up, since revision 1 is IPv4 only, so it takes no
//! link-local address and sends nothing over IPv6; the kernel's IPv6
//! elsewhere is left as it is. Loopback and the NIC come up, the NIC takes
//! the plan's address and prefix, and the default route goes through the
//! plan's gateway, each a route netlink request whose answer is checked
//! ([`netlink`]). The nameservers are written to [`VM_RUNTIME_RESOLV_CONF`],
//! root's on the runtime tmpfs, which is bind-mounted over the image's empty
//! `/etc/resolv.conf`; with none the image's file stays empty, and the guest
//! has no resolver. Nothing here runs a tool, binds a listener or reaches the
//! host: the TAP, its rules and every address are the supervisor's.

mod netlink;

use oneiron_vault_contract::vm::{VmGuestNetworkConfig, parse_vm_guest_mac};
use std::ffi::CString;
use std::fmt;
use std::io::{self, Write as _};
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

/// The guest's resolver file, root's, on the runtime tmpfs.
const VM_RUNTIME_RESOLV_CONF: &str = "/run/oneiron-net/resolv.conf";
/// Its directory, made on each boot that sets up a resolver.
const RUNTIME_DIR: &str = "/run/oneiron-net";
/// The image's resolver file: empty and regular, as the builder stages it.
const RESOLV_CONF: &str = "/etc/resolv.conf";
/// The kernel's per-link IPv6 switches; not there when it has no IPv6.
const IPV6_CONF: &str = "/proc/sys/net/ipv6/conf";

/// The step of the guest's network setup that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VmNetworkStage {
    /// Finding the NIC, turning its IPv6 off, and bringing it and loopback
    /// up.
    Link,
    /// The NIC's IPv4 address and prefix.
    Address,
    /// The default route through the gateway.
    Route,
    /// The resolver file and its mount.
    Dns,
}

impl fmt::Display for VmNetworkStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Link => "link",
            Self::Address => "address",
            Self::Route => "route",
            Self::Dns => "DNS",
        })
    }
}

/// Why the guest's network setup refused the boot.
#[derive(Debug, thiserror::Error)]
#[error("the guest network's {stage} step")]
pub(super) struct VmNetworkError {
    stage: VmNetworkStage,
    source: io::Error,
}

/// A failure of `stage`.
fn at(stage: VmNetworkStage) -> impl FnOnce(io::Error) -> VmNetworkError {
    move |source| VmNetworkError { stage, source }
}

/// Sets up the guest's NIC as `plan`, already validated, says: found by its
/// MAC, its IPv6 off, up with loopback, its address, the default route, then
/// the resolver.
pub(super) fn configure(plan: &VmGuestNetworkConfig) -> Result<(), VmNetworkError> {
    use VmNetworkStage::{Address, Dns, Link, Route};
    let mac =
        parse_vm_guest_mac(&plan.guest_mac).map_err(|fault| at(Link)(io::Error::other(fault)))?;
    let mut route = netlink::Route::open().map_err(at(Link))?;
    let links = route.links().map_err(at(Link))?;
    let mut matching = links.iter().filter(|link| link.mac == Some(mac));
    let nic = match (matching.next(), matching.next()) {
        (Some(nic), None) => nic,
        (None, _) => return Err(at(Link)(io::Error::other("no link has the plan's MAC"))),
        (Some(_), Some(_)) => {
            return Err(at(Link)(io::Error::other(
                "more than one link has the plan's MAC",
            )));
        }
    };
    let loopback = links
        .iter()
        .find(|link| link.loopback)
        .ok_or_else(|| at(Link)(io::Error::other("the guest has no loopback link")))?;
    ipv6_off(&nic.name).map_err(at(Link))?;
    route.set_up(loopback.index).map_err(at(Link))?;
    route.set_up(nic.index).map_err(at(Link))?;
    route
        .add_address(nic.index, plan.guest_ipv4, plan.prefix_len)
        .map_err(at(Address))?;
    route
        .add_default_route(nic.index, plan.gateway)
        .map_err(at(Route))?;
    resolver(&plan.dns_servers).map_err(at(Dns))
}

/// Turns IPv6 off on the link `name` through its sysctl switch, before the
/// link comes up. A kernel without IPv6 has no switch, and needs none.
fn ipv6_off(name: &str) -> io::Result<()> {
    match std::fs::metadata(IPV6_CONF) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::other("the NIC has no usable interface name"));
    }
    std::fs::OpenOptions::new()
        .write(true)
        .open(format!("{IPV6_CONF}/{name}/disable_ipv6"))?
        .write_all(b"1\n")
}

/// Writes `servers` as the resolver file, root's and readable by every UID,
/// and bind-mounts it over the image's empty one. With no servers the
/// image's file stays as it is.
fn resolver(servers: &[Ipv4Addr]) -> io::Result<()> {
    if servers.is_empty() {
        return Ok(());
    }
    std::fs::create_dir(RUNTIME_DIR)?;
    std::fs::set_permissions(RUNTIME_DIR, std::fs::Permissions::from_mode(0o755))?;
    let body: String = servers
        .iter()
        .map(|server| format!("nameserver {server}\n"))
        .collect();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(VM_RUNTIME_RESOLV_CONF)?;
    file.write_all(body.as_bytes())?;
    file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    drop(file);
    let source = CString::new(VM_RUNTIME_RESOLV_CONF)?;
    let target = CString::new(RESOLV_CONF)?;
    // SAFETY: both pointers are NUL-terminated strings that outlive the
    // call, and a bind mount takes no filesystem type or data.
    let mounted = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if mounted != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
