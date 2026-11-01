//! Network primitives that do not depend on the host: IP networks in CIDR notation and their
//! subtraction, which egress rules use, the forms of a VM's hostname and guest network address,
//! and the gateway of a guest network.

pub mod cidr;

pub use cidr::Cidr;

/// Returns whether `hostname` is a lowercase RFC 1123 label of up to 63 characters.
pub fn is_valid_hostname(hostname: &str) -> bool {
    let bytes = hostname.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes.first() != Some(&b'-')
        && bytes.last() != Some(&b'-')
}

/// Returns whether `value` is a static guest address that OpenVMM accepts: an IPv4
/// `ADDRESS/PREFIX` with a /1 to /30 prefix and an address other than the network's own, its
/// broadcast address, and the gateway, which is its first address.
pub fn is_valid_guest_network(value: &str) -> bool {
    guest_address(value).is_some()
}

/// Returns the gateway of a static guest address that [`is_valid_guest_network`] accepts: the
/// first address of its network, at which OpenVMM presents the guest's gateway. Returns `None`
/// for any other value.
pub fn guest_gateway(value: &str) -> Option<std::net::Ipv4Addr> {
    let (address, mask) = guest_address(value)?;
    Some(std::net::Ipv4Addr::from((address & mask) + 1))
}

/// Returns the address and the network mask of a static guest address that
/// [`is_valid_guest_network`] accepts.
fn guest_address(value: &str) -> Option<(u32, u32)> {
    let (address, prefix_text) = value.split_once('/')?;
    let address = address.parse::<std::net::Ipv4Addr>().ok()?;
    let prefix =
        cidr::parse_prefix_length(prefix_text).filter(|prefix| (1..=30).contains(prefix))?;
    let mask = u32::MAX << (32 - u32::from(prefix));
    let host = u32::from(address);
    let network = host & mask;
    (![network, network | !mask, network + 1].contains(&host)).then_some((host, mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_networks_follow_openvmm_rules() {
        for valid in ["10.0.0.2/24", "192.168.7.10/30", "172.16.0.200/16"] {
            assert!(is_valid_guest_network(valid), "{valid}");
        }
        for invalid in [
            "10.0.0.0/24",
            "10.0.0.255/24",
            "10.0.0.1/24",
            "10.0.0.5/30",
            "10.0.0.2",
            "10.0.0.2/31",
            "10.0.0.2/024",
            "fd00::2/64",
        ] {
            assert!(!is_valid_guest_network(invalid), "{invalid}");
            assert_eq!(guest_gateway(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn the_gateway_is_the_first_address_of_the_guest_network() {
        for (network, gateway) in [
            ("10.0.0.2/24", [10, 0, 0, 1]),
            ("192.168.7.10/30", [192, 168, 7, 9]),
            ("172.16.0.200/16", [172, 16, 0, 1]),
            ("10.255.255.254/8", [10, 0, 0, 1]),
        ] {
            assert_eq!(
                guest_gateway(network),
                Some(std::net::Ipv4Addr::from(gateway)),
                "{network}"
            );
        }
    }

    #[test]
    fn hostnames_are_lowercase_labels() {
        assert!(is_valid_hostname("nvx-sandbox"));
        for invalid in ["", "-a", "a-", "A", "a.b", &"a".repeat(64)] {
            assert!(!is_valid_hostname(invalid), "{invalid:?}");
        }
    }
}
