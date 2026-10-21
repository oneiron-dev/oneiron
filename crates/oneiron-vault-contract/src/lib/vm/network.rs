//! A vault VM's guest network (FIX 6808): the one NIC a supervisor may
//! attach to a vault VM for its outbound IPv4, as two views of one plan.
//!
//! The supervisor owns the host side: it makes the vault's TAP and installs
//! its forwarding, its masquerade and its ingress drops before the VMM
//! starts, and it chooses every name and address. The engine takes two
//! views of that one plan and defaults none of it. The host's VM profile
//! names the TAP and the MAC the guest's NIC takes on it
//! ([`VmTapAttachment`]), which the VMM attaches as the guest's one network
//! interface. The guest's config drive holds
//! [`VM_GUEST_NETWORK_FILE`](crate::vm::VM_GUEST_NETWORK_FILE)
//! ([`VmGuestNetworkConfig`]): the same MAC, the guest's IPv4 address and
//! prefix, its gateway and its nameservers, which the root bootstrap sets up
//! before the vault's key goes in. Revision 1
//! ([`VM_NETWORK_REVISION`](crate::vm::VM_NETWORK_REVISION)) is IPv4 only:
//! IPv6 is off on this NIC. Every key of both is required, and an empty
//! nameserver list gives the guest no resolver.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Linux's interface-name bound (`IFNAMSIZ`), its terminating NUL excluded.
const MAX_TAP_NAME_BYTES: usize = 15;

/// The host's view, the VM profile's `network`: the TAP the supervisor made
/// for this vault, and the MAC the guest's NIC takes on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmTapAttachment {
    /// The TAP's name on the host, up and ruled before the VMM starts.
    pub tap_name: String,
    /// The guest NIC's MAC ([`parse_vm_guest_mac`]), the one the guest's
    /// view names too.
    pub guest_mac: String,
}

impl VmTapAttachment {
    /// Why the VMM cannot attach this, if it cannot: a TAP name that is not
    /// a Linux interface name, or a MAC not in its form.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !interface_name(&self.tap_name) {
            return Err("the TAP name is not a Linux interface name");
        }
        parse_vm_guest_mac(&self.guest_mac)?;
        Ok(())
    }
}

/// The guest's view, the config drive's
/// [`VM_GUEST_NETWORK_FILE`](crate::vm::VM_GUEST_NETWORK_FILE): one JSON
/// object of exactly these keys, at most
/// [`MAX_VM_CONFIG_FILE_BYTES`](crate::vm::MAX_VM_CONFIG_FILE_BYTES).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmGuestNetworkConfig {
    /// The MAC of the NIC to set up: the host attachment's.
    pub guest_mac: String,
    /// The guest's address on that NIC.
    pub guest_ipv4: Ipv4Addr,
    /// The on-link prefix's length, 1 to 31.
    pub prefix_len: u8,
    /// The default route's next hop, on the guest's link: the host's end of
    /// the TAP.
    pub gateway: Ipv4Addr,
    /// The guest's nameservers, in order; empty for none.
    pub dns_servers: Vec<Ipv4Addr>,
}

impl VmGuestNetworkConfig {
    /// Why the guest cannot set this up, if it cannot: a MAC not in its
    /// form, a prefix length outside 1 to 31, a guest address or gateway
    /// that is not unicast, the same address twice, a gateway off the
    /// guest's prefix, either one the prefix's network or broadcast address,
    /// or a nameserver that is not unicast.
    pub fn validate(&self) -> Result<(), &'static str> {
        parse_vm_guest_mac(&self.guest_mac)?;
        if !(1..=31).contains(&self.prefix_len) {
            return Err("the prefix length is not 1 to 31");
        }
        if !unicast(self.guest_ipv4) || !unicast(self.gateway) {
            return Err("the guest address or the gateway is not a unicast address");
        }
        if self.guest_ipv4 == self.gateway {
            return Err("the guest address is the gateway's");
        }
        let host = u32::MAX >> self.prefix_len;
        let (guest, gateway) = (u32::from(self.guest_ipv4), u32::from(self.gateway));
        if (guest & !host) != (gateway & !host) {
            return Err("the gateway is not on the guest's prefix");
        }
        // A /31 has no network or broadcast address; a wider prefix has both.
        if self.prefix_len < 31
            && [guest, gateway]
                .into_iter()
                .any(|address| (address & host) == 0 || (address & host) == host)
        {
            return Err("an address is its prefix's network or broadcast address");
        }
        if !self.dns_servers.iter().all(|server| unicast(*server)) {
            return Err("a nameserver is not a unicast address");
        }
        Ok(())
    }
}

/// A guest NIC's MAC as both views spell it: six two-digit hex octets in
/// either case, joined by `:`, unicast and not all zero. Its octets.
pub fn parse_vm_guest_mac(text: &str) -> Result<[u8; 6], &'static str> {
    const MALFORMED: &str = "the guest MAC is not six two-digit hex octets joined by ':'";
    let mut octets = [0u8; 6];
    let mut parts = text.split(':');
    for octet in &mut octets {
        let part = parts
            .next()
            .filter(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or(MALFORMED)?;
        *octet = u8::from_str_radix(part, 16).map_err(|_| MALFORMED)?;
    }
    if parts.next().is_some() {
        return Err(MALFORMED);
    }
    if octets[0] & 1 != 0 {
        return Err("the guest MAC is a multicast address");
    }
    if octets == [0; 6] {
        return Err("the guest MAC is all zero");
    }
    Ok(octets)
}

/// A Linux interface name: 1 to 15 bytes of printable ASCII, with no `/` or
/// `:`, and neither `.` nor `..`.
fn interface_name(name: &str) -> bool {
    (1..=MAX_TAP_NAME_BYTES).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'/' && byte != b':')
}

/// An address a NIC, a route or a resolver can use: not unspecified,
/// broadcast, multicast or loopback (the guest's loopback is its own, where
/// nothing of the plan runs).
fn unicast(address: Ipv4Addr) -> bool {
    !(address.is_unspecified()
        || address.is_broadcast()
        || address.is_multicast()
        || address.is_loopback())
}
