use super::*;
use std::net::{IpAddr, Ipv6Addr};

pub(super) fn request_host<B>(request: &Request<B>) -> Option<&str> {
    request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri().host())
}

pub(super) fn is_localhost_host(host: &str) -> bool {
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Some(hostname) = strip_unbracketed_host_port(host)
        && hostname.eq_ignore_ascii_case("localhost")
    {
        return true;
    }
    if let Some(ip) = parse_host_ip(host) {
        return ip_is_loopback(ip);
    }
    false
}

fn parse_host_ip(host: &str) -> Option<IpAddr> {
    if let Some(stripped) = strip_bracketed_ipv6_host(host) {
        return stripped.parse().ok();
    }
    if let Ok(ip) = host.parse() {
        return Some(ip);
    }
    if host.matches(':').count() == 1 {
        let (hostname, port) = host.rsplit_once(':')?;
        if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) {
            return hostname.parse().ok();
        }
    }
    None
}

fn strip_unbracketed_host_port(host: &str) -> Option<&str> {
    if host.matches(':').count() != 1 {
        return None;
    }
    let (hostname, port) = host.rsplit_once(':')?;
    (!hostname.is_empty() && !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .then_some(hostname)
}

fn strip_bracketed_ipv6_host(host: &str) -> Option<&str> {
    let rest = host.strip_prefix('[')?;
    let (inside, after) = rest.split_once(']')?;
    if after.is_empty()
        || after
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Some(inside);
    }
    None
}

fn ip_is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ipv6_mapped_ipv4(ip).is_some_and(|ip| ip.is_loopback())
        }
    }
}

fn ipv6_mapped_ipv4(ip: Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    ip.to_ipv4_mapped()
}
