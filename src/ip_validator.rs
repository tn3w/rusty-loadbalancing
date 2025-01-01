use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


pub fn is_valid_public_ip(ip_address: &str) -> bool {
    let ip = match ip_address.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match ip {
        IpAddr::V4(ipv4) => is_valid_public_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_valid_public_ipv6(ipv6),
    }
}

fn is_valid_public_ipv4(ip: Ipv4Addr) -> bool {
    !(
        ip.is_private()           || // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        ip.is_loopback()          || // 127.0.0.0/8
        ip.is_link_local()        || // 169.254.0.0/16
        ip.is_broadcast()         || // 255.255.255.255
        ip.is_documentation()     || // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        ip.is_unspecified()       || // 0.0.0.0
        ip.is_multicast()         || // 224.0.0.0/4
        ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0 || // 192.0.0.0/24
        ip.octets()[0] == 198 && ip.octets()[1] == 18 && ip.octets()[2] == 0    // 198.18.0.0/15
    )
}

fn is_valid_public_ipv6(ip: Ipv6Addr) -> bool {
    !(
        ip.is_loopback()          || // ::1
        ip.is_unspecified()       || // ::
        ip.is_multicast()         || // ff00::/8
        is_documentation_ipv6(ip) || // 2001:db8::/32
        is_unique_local(ip)       || // fc00::/7
        is_link_local(ip)            // fe80::/10
    )
}

fn is_unique_local(ip: Ipv6Addr) -> bool {
    let first_byte = ip.octets()[0];
    first_byte & 0xfe == 0xfc
}

fn is_link_local(ip: Ipv6Addr) -> bool {
    let first_byte = ip.octets()[0];
    let second_byte = ip.octets()[1];
    first_byte == 0xfe && (second_byte & 0xc0) == 0x80
}

fn is_documentation_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0xdb8
}

pub fn strip_port(input: &str) -> String {
    if let Some(start_bracket) = input.find('[') {
        if let Some(end_bracket) = input[start_bracket..].find(']') {
            let end_pos = start_bracket + end_bracket + 1;
            if input.len() > end_pos && input.as_bytes()[end_pos] == b':' {
                return input[..end_pos].to_string();
            }
            return input.to_string();
        }
    }
    
    match input.rfind(':') {
        Some(pos) if input[pos+1..].chars().all(|c| c.is_ascii_digit()) => input[..pos].to_string(),
        _ => input.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_public_ipv4() {
        assert!(is_valid_public_ip("203.0.114.0"));
        assert!(is_valid_public_ip("8.8.8.8"));
        assert!(is_valid_public_ip("1.1.1.1"));
    }

    #[test]
    fn test_invalid_ipv4() {
        assert!(!is_valid_public_ip("10.0.0.1"));        // Private
        assert!(!is_valid_public_ip("127.0.0.1"));       // Loopback
        assert!(!is_valid_public_ip("192.168.1.1"));     // Private
        assert!(!is_valid_public_ip("169.254.0.1"));     // Link local
        assert!(!is_valid_public_ip("224.0.0.1"));       // Multicast
        assert!(!is_valid_public_ip("0.0.0.0"));         // Unspecified
        assert!(!is_valid_public_ip("255.255.255.255")); // Broadcast
        assert!(!is_valid_public_ip("not an ip"));       // Invalid format
    }

    #[test]
    fn test_valid_public_ipv6() {
        assert!(is_valid_public_ip("2001:0db7:85a3:0000:0000:8a2e:0370:7334")); // Valid public address
        assert!(is_valid_public_ip("2606:4700:4700::1111")); // Cloudflare DNS
        assert!(is_valid_public_ip("2404:6800:4003:c00::64")); // Google
    }

    #[test]
    fn test_invalid_ipv6() {
        assert!(!is_valid_public_ip("::1"));                 // Loopback
        assert!(!is_valid_public_ip("::\""));                // Unspecified
        assert!(!is_valid_public_ip("fe80::1234:5678"));     // Link-local
        assert!(!is_valid_public_ip("fc00::1"));             // Unique local
        assert!(!is_valid_public_ip("ff00::1"));             // Multicast
        assert!(!is_valid_public_ip("2001:db8::1"));         // Documentation
    }

    #[test]
    fn test_strip_port() {
        assert_eq!(strip_port("example.com:8080"), "example.com");
        assert_eq!(strip_port("127.0.0.1:80"), "127.0.0.1");
        assert_eq!(strip_port("[2001:db8::1]:8080"), "[2001:db8::1]");
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(strip_port("sub.example.com:443"), "sub.example.com");
    }
}