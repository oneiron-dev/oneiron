//! Address checks shared by SSRF-guarded fetches and the sandbox proxy.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Only globally routable addresses, with mapped/NAT64 IPv4 normalized.
#[must_use]
pub fn global_address(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => embedded_v4(&v6).map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    is_global(ip)
}

fn embedded_v4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let seg = v6.segments();
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        let o = v6.octets();
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
}

fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)))
        }
        // Global unicast is 2000::/3; outside it nothing is global (the
        // NAT64 and v4-mapped forms were judged as v4 above). Inside it,
        // the special-purpose blocks are dropped.
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            let special = match seg[0] {
                // 2001::/23 (Teredo, ORCHID, benchmarking and the rest) and
                // 2001:db8::/32 (documentation).
                0x2001 => seg[1] < 0x0200 || seg[1] == 0x0db8,
                // 6to4.
                0x2002 => true,
                // 3fff::/20 (documentation) and the retired 6bone; no
                // registry holds any of 3ff0::/12.
                0x3ff0..=0x3fff => true,
                _ => false,
            };
            (seg[0] & 0xe000) == 0x2000 && !special
        }
    }
}
