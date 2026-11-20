//! A hosted node's egress guard admits the private networks its hosting
//! operator names (HOSTED-EGRESS-OPERATOR-SETTING), and nothing else: an
//! admitted network never admits infrastructure inside it, and with none
//! admitted the guard refuses today's set (RFC1918, CGNAT, ULA). The
//! managed-boot flag that carries the setting is pinned in oneiron-server's
//! `tests/hosted_egress_private_networks.rs`.
//!
//! `cargo test --locked -p oneiron-web-fetch --test hosted_egress_private_networks`.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};

use oneiron_web_fetch::web_fetch::{
    HostedEgressGuard, HostedEgressRefusal, HostedPrivateNetwork, HostedPrivateOrigin,
};

/// One address of the node's own, refused as infrastructure on every guard.
const NODE: &str = "10.1.2.3";

fn ip(text: &str) -> IpAddr {
    text.parse().expect("a test address")
}

fn guard(networks: &[HostedPrivateNetwork]) -> HostedEgressGuard {
    HostedEgressGuard::new(|| BTreeSet::from([ip(NODE)]), BTreeSet::new())
        .with_private_networks(networks.iter().copied().collect())
}

/// One address in each private network, every spelling the guard unwraps.
const RFC1918: [&str; 4] = ["10.0.0.5", "172.16.0.1", "192.168.1.1", "::ffff:10.0.0.5"];
const CGNAT: [&str; 3] = ["100.64.0.1", "100.127.255.254", "64:ff9b::6440:101"];
const ULA: [&str; 2] = ["fd12:3456::1", "fc00::1"];

/// Infrastructure, some of it inside an admittable network: the node's own
/// address (RFC1918); Alibaba Cloud's metadata endpoint and Tailscale's node
/// address (CGNAT); the AWS (metadata and EKS Pod Identity), Google Cloud,
/// Oracle Cloud, Scaleway and Akamai IPv6 metadata endpoints and Tailscale's
/// IPv6 node address (ULA).
const INFRASTRUCTURE: [&str; 15] = [
    NODE,
    "100.100.100.200",
    "100.100.100.100",
    "fd00:ec2::254",
    "fd00:ec2::23",
    "fd20:ce::254",
    "fd00:c1::a9fe:a9fe",
    "fd00:42::42",
    "fd00:a9fe:a9fe::1",
    "fd7a:115c:a1e0::53",
    "127.0.0.1",
    "169.254.169.254",
    "0.0.0.0",
    "::1",
    "fe80::1",
];

#[test]
fn the_default_refusal_set_is_todays() {
    let fresh = HostedEgressGuard::new(|| BTreeSet::from([ip(NODE)]), BTreeSet::new());
    for refusing in [fresh, guard(&[])] {
        for private in RFC1918.into_iter().chain(CGNAT).chain(ULA) {
            assert_eq!(
                refusing.refuses(ip(private)),
                Some(HostedEgressRefusal::PrivateNetwork),
                "{private}"
            );
        }
        for infrastructure in INFRASTRUCTURE {
            assert_eq!(
                refusing.refuses(ip(infrastructure)),
                Some(HostedEgressRefusal::Infrastructure),
                "{infrastructure}"
            );
        }
        assert_eq!(refusing.refuses(ip("93.184.216.34")), None);
    }
}

#[test]
fn an_operator_who_admits_private_networks_reaches_them_but_never_infrastructure() {
    let all = guard(&[
        HostedPrivateNetwork::Rfc1918,
        HostedPrivateNetwork::Cgnat,
        HostedPrivateNetwork::Ula,
    ]);
    for private in RFC1918.into_iter().chain(CGNAT).chain(ULA) {
        assert_eq!(all.refuses(ip(private)), None, "{private}");
        all.check_request("https://intranet.example/", ip(private))
            .unwrap_or_else(|error| panic!("{private}: {error}"));
    }
    for infrastructure in INFRASTRUCTURE {
        assert_eq!(
            all.refuses(ip(infrastructure)),
            Some(HostedEgressRefusal::Infrastructure),
            "an admitted network admits no infrastructure: {infrastructure}"
        );
        assert!(
            all.check_request("https://intranet.example/", ip(infrastructure))
                .is_err(),
            "{infrastructure}"
        );
    }
}

#[test]
fn each_network_admits_only_itself() {
    let cases: [(HostedPrivateNetwork, &[&str]); 3] = [
        (HostedPrivateNetwork::Rfc1918, &RFC1918),
        (HostedPrivateNetwork::Cgnat, &CGNAT),
        (HostedPrivateNetwork::Ula, &ULA),
    ];
    for (admitted, inside) in cases {
        let one = guard(&[admitted]);
        for (other, addresses) in cases {
            for address in addresses {
                let expected = (other != admitted).then_some(HostedEgressRefusal::PrivateNetwork);
                assert_eq!(
                    one.refuses(ip(address)),
                    expected,
                    "{address} with only {admitted} admitted"
                );
            }
        }
        // One name's answers: an admitted address beside one the operator
        // did not admit refuses the name, and infrastructure wins over both.
        let outside = if admitted == HostedPrivateNetwork::Ula {
            RFC1918[0]
        } else {
            ULA[0]
        };
        assert_eq!(
            one.refuses_resolved("intranet.example", [ip(inside[0]), ip(outside)]),
            Some(HostedEgressRefusal::PrivateNetwork),
            "{admitted}"
        );
        assert_eq!(
            one.refuses_resolved("intranet.example", [ip(inside[0])]),
            None,
            "{admitted}"
        );
        assert_eq!(
            one.refuses_resolved("intranet.example", [ip(inside[0]), ip("169.254.169.254")]),
            Some(HostedEgressRefusal::Infrastructure),
            "{admitted}"
        );
    }
}

#[test]
fn admitted_networks_and_listed_origins_stand_together() {
    let origin: HostedPrivateOrigin = "https://wiki.corp.example".parse().unwrap();
    let both = HostedEgressGuard::new(BTreeSet::new, BTreeSet::from([origin]))
        .with_private_networks(BTreeSet::from([HostedPrivateNetwork::Cgnat]));
    // The listed origin's name still reaches an RFC1918 answer the networks
    // do not admit; any other name does not.
    assert_eq!(
        both.refuses_resolved("wiki.corp.example", [ip("10.0.0.5")]),
        None
    );
    assert_eq!(
        both.refuses_resolved("other.corp.example", [ip("10.0.0.5")]),
        Some(HostedEgressRefusal::PrivateNetwork)
    );
    // The admitted network is reached by address, under any name.
    assert_eq!(
        both.refuses_resolved("other.corp.example", [ip("100.64.0.1")]),
        None
    );
    assert_eq!(both.refuses(ip("100.64.0.1")), None);
}

#[test]
fn a_private_network_parses_only_its_three_spellings() {
    for (spelling, network) in [
        ("rfc1918", HostedPrivateNetwork::Rfc1918),
        ("cgnat", HostedPrivateNetwork::Cgnat),
        ("ula", HostedPrivateNetwork::Ula),
    ] {
        assert_eq!(spelling.parse::<HostedPrivateNetwork>(), Ok(network));
        assert_eq!(network.to_string(), spelling);
        assert_eq!(network.as_str(), spelling);
    }
    for refused in [
        "",
        "RFC1918",
        "Cgnat",
        " ula",
        "ula ",
        "10.0.0.0/8",
        "fc00::/7",
        "private",
        "all",
        "cgnat,ula",
    ] {
        assert!(
            refused.parse::<HostedPrivateNetwork>().is_err(),
            "{refused:?} names no private network"
        );
    }
}

#[test]
fn an_ipv6_spelling_of_an_admitted_ipv4_network_is_judged_as_itself() {
    let rfc1918 = guard(&[HostedPrivateNetwork::Rfc1918]);
    let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0005));
    assert_eq!(rfc1918.refuses(mapped), None);
    // The node's own address stays infrastructure in every spelling.
    let node_mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a01, 0x0203));
    assert_eq!(
        rfc1918.refuses(node_mapped),
        Some(HostedEgressRefusal::Infrastructure)
    );
}
