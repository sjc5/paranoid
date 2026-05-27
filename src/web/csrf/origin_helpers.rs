use super::*;
use url::{Host, Url};

pub(super) fn normalize_allowed_origins(origins: Vec<String>) -> Result<Vec<String>, Error> {
    let mut normalized = Vec::new();
    normalized
        .try_reserve_exact(origins.len())
        .map_err(|_| Error::AllocationFailed)?;
    for origin in origins {
        normalized.push(normalize_exact_origin(&origin, "AllowedOrigin")?);
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

pub(super) fn normalize_request_origin_header(
    header: &str,
    label: &'static str,
) -> Result<String, Error> {
    if label == "Referer" {
        normalize_referer_origin(header, label)
    } else {
        normalize_exact_origin(header, label)
    }
}

#[cfg(test)]
pub(super) fn normalize_origin(origin: &str, label: &'static str) -> Result<String, Error> {
    normalize_exact_origin(origin, label)
}

fn normalize_exact_origin(origin: &str, label: &'static str) -> Result<String, Error> {
    let parsed = Url::parse(origin).map_err(|source| Error::CsrfOriginParse { label, source })?;
    reject_unsupported_origin_parts(&parsed, label)?;
    normalized_scheme_host_port(&parsed, label)
}

fn normalize_referer_origin(referer: &str, label: &'static str) -> Result<String, Error> {
    let parsed = Url::parse(referer).map_err(|source| Error::CsrfOriginParse { label, source })?;
    reject_credentials(&parsed, label)?;
    normalized_scheme_host_port(&parsed, label)
}

fn normalized_scheme_host_port(parsed: &Url, label: &'static str) -> Result<String, Error> {
    let scheme = parsed.scheme().to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err(Error::CsrfOriginUnsupportedScheme { label, scheme });
    }
    let host = parsed
        .host()
        .ok_or(Error::CsrfOriginMissingHost { label })?;
    let host = normalized_host(host);
    let mut normalized = String::new();
    normalized
        .try_reserve_exact(scheme.len() + 3 + host.len() + 6)
        .map_err(|_| Error::AllocationFailed)?;
    normalized.push_str(&scheme);
    normalized.push_str("://");
    normalized.push_str(&host);
    if let Some(port) = parsed.port() {
        normalized.push(':');
        normalized.push_str(&port.to_string());
    }
    Ok(normalized)
}

fn reject_unsupported_origin_parts(parsed: &Url, label: &'static str) -> Result<(), Error> {
    reject_credentials(parsed, label)?;
    if parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.cannot_be_a_base()
    {
        return Err(Error::CsrfOriginContainsNonOriginParts { label });
    }
    Ok(())
}

fn reject_credentials(parsed: &Url, label: &'static str) -> Result<(), Error> {
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::CsrfOriginContainsNonOriginParts { label });
    }
    Ok(())
}

fn normalized_host(host: Host<&str>) -> String {
    match host {
        Host::Domain(domain) => domain.to_ascii_lowercase(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => format!("[{ip}]"),
    }
}
