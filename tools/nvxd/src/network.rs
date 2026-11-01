//! The VM's network, from the three switches the engine passes: `--network`, `--private-networks`
//! and `--ingress`.
//!
//! Outbound is open to everything, except that the guest is kept off the networks the user's
//! machine happens to sit in: the private and link-local ranges (the company network, the home
//! LAN, a cloud host's metadata address) unless private networks are allowed. The guest's own
//! gateway is the one exception, because it answers DNS. Inbound and the host's own loopback stay
//! closed, unless `ingress_host_loopback` publishes the guest's listeners on host loopback.

use nvx::host::network::{
    Access, Destination, EgressRule, HostLoopback, NetworkPolicy, PortSelector, Protocol,
};
use nvx::host::sandbox::SandboxNetwork;

/// The guest's address on OpenVMM's portable network profile; its gateway is `10.0.0.1`.
const GUEST_NETWORK: &str = "10.0.0.2/24";
const GUEST_GATEWAY_V4: &str = "10.0.0.1/32";
const GUEST_GATEWAY_V6: &str = "fd00::a00:1/128";
/// The one port of the gateway the guest may keep using when host loopback is published.
const DNS_PORT: u16 = 53;

/// The network of a VM, or `None` for a guest with loopback only.
pub fn network(
    egress: bool,
    ingress_host_loopback: bool,
    private_networks_allow: bool,
) -> Result<Option<SandboxNetwork>, String> {
    if !egress {
        return Ok(None);
    }
    let mut policy = NetworkPolicy::new(Access::Allow);
    if ingress_host_loopback {
        // OpenVMM's one switch for host loopback works both ways: the host reaches the guest's
        // listeners on its own loopback, and the guest reaches the host's loopback services
        // through the gateway. Only the first is wanted, so the gateway is closed to the guest on
        // every port but DNS.
        policy.host_loopback = HostLoopback::Allow;
        for gateway in [GUEST_GATEWAY_V4, GUEST_GATEWAY_V6] {
            let mut rule = EgressRule::to(gateway);
            for protocol in [Protocol::Tcp, Protocol::Udp] {
                for (from, to) in [(1u16, DNS_PORT - 1), (DNS_PORT + 1, 65535)] {
                    rule.ports.push(PortSelector {
                        protocol,
                        port: Some(from),
                        end_port: Some(to),
                    });
                }
            }
            policy = policy.with_deny(rule);
        }
    } else {
        policy.host_loopback = HostLoopback::Deny;
    }
    if !private_networks_allow {
        policy = policy.with_deny(EgressRule {
            to: vec![
                destination("10.0.0.0/8", &["10.0.0.1"]),
                destination("172.16.0.0/12", &[]),
                destination("192.168.0.0/16", &[]),
                destination("169.254.0.0/16", &[]),
                destination("100.64.0.0/10", &[]),
                destination("fc00::/7", &["fd00::a00:1"]),
                destination("fe80::/10", &[]),
            ],
            ports: Vec::new(),
        });
    }
    SandboxNetwork::new(GUEST_NETWORK, policy)
        .map(Some)
        .map_err(|error| format!("the network policy is refused: {error}"))
}

fn destination(cidr: &str, except: &[&str]) -> Destination {
    Destination {
        cidr: cidr.to_owned(),
        except: except.iter().map(|value| (*value).to_owned()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_egress_means_no_network() {
        assert!(network(false, false, false).unwrap().is_none());
        assert!(network(false, true, true).unwrap().is_none());
    }

    #[test]
    fn every_combination_is_accepted_by_the_plan() {
        for ingress in [false, true] {
            for private in [false, true] {
                let network = network(true, ingress, private).unwrap().expect("a network");
                let policy = network.policy();
                assert_eq!(policy.egress, Access::Allow);
                assert_eq!(policy.ingress, Access::Deny);
                let rules = policy.deny.rules.len();
                assert_eq!(rules, usize::from(!private) + 2 * usize::from(ingress));
                assert_eq!(
                    policy.host_loopback,
                    if ingress { HostLoopback::Allow } else { HostLoopback::Deny }
                );
            }
        }
    }

    #[test]
    fn private_ranges_spare_the_gateway() {
        let network = network(true, false, false).unwrap().unwrap();
        let rule = &network.policy().deny.rules[0];
        assert_eq!(rule.to[0].cidr, "10.0.0.0/8");
        assert_eq!(rule.to[0].except, vec!["10.0.0.1".to_owned()]);
    }
}
