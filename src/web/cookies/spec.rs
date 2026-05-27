use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CookieSpec {
    pub(super) name: String,
    path: String,
    domain: Option<String>,
    secure: bool,
    same_site: CookieSameSite,
    http_only: bool,
    partitioned: bool,
    max_age: Option<CookieMaxAgeSeconds>,
    scope: CookieScopeKind,
}

impl CookieSpec {
    pub(super) fn new(
        manager: &CookieManager,
        scope: CookieScope,
        config: CookieConfigParts,
        http_only_mode: CookieHttpOnlyMode,
    ) -> Result<Self, Error> {
        let same_site = manager.resolve_same_site(config.same_site);
        let http_only = match http_only_mode {
            CookieHttpOnlyMode::Encrypted => manager.resolve_http_only(config.http_only),
            CookieHttpOnlyMode::ClientReadable => false,
        };
        let partitioned = manager.resolve_partitioned(config.partitioned);
        let secure = !manager.is_development();

        match scope {
            CookieScope::HostOnly => {
                let name = manager.final_host_only_name(&config.name)?;
                Ok(Self {
                    name,
                    path: "/".to_owned(),
                    domain: None,
                    secure,
                    same_site,
                    http_only,
                    partitioned,
                    max_age: config.max_age,
                    scope: CookieScopeKind::HostOnly,
                })
            }
            CookieScope::NonHostOnly { path, domain } => {
                validate_unprefixed_cookie_name(&config.name)?;
                validate_cookie_name(&config.name)?;
                let path = normalize_path(path)?;
                let domain = normalize_domain(domain)?;
                Ok(Self {
                    name: config.name,
                    path,
                    domain,
                    secure,
                    same_site,
                    http_only,
                    partitioned,
                    max_age: config.max_age,
                    scope: CookieScopeKind::NonHostOnly,
                })
            }
        }
    }

    pub(super) fn cookie_with_value(&self, value: String) -> Result<Cookie<'static>, Error> {
        validate_cookie_value(&value)?;
        let mut cookie = Cookie::new(self.name.clone(), value);
        self.apply_attributes(&mut cookie);
        http::HeaderValue::from_str(&cookie.to_string()).map_err(|_| Error::InvalidCookieValue)?;
        Ok(cookie)
    }

    pub(super) fn deletion_cookie(&self) -> Cookie<'static> {
        let mut cookie = Cookie::new(self.name.clone(), "");
        self.apply_attributes(&mut cookie);
        cookie.set_max_age(cookie::time::Duration::ZERO);
        cookie
    }

    pub(super) fn parse_from_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<Cookie<'static>, Error> {
        self.parse_from_headers(request.headers())
    }

    pub(super) fn parse_from_headers(&self, headers: &HeaderMap) -> Result<Cookie<'static>, Error> {
        let mut found = None;
        for header in headers.get_all(COOKIE) {
            let cookie_header = header.to_str().map_err(Error::CookieHeaderDecode)?;
            self.collect_matching_cookie(cookie_header, &mut found)?;
        }
        found.ok_or_else(|| Error::MissingCookie {
            name: self.name.clone(),
        })
    }

    pub(super) fn parse_from_cookie_header(
        &self,
        cookie_header: &str,
    ) -> Result<Cookie<'static>, Error> {
        let mut found = None;
        self.collect_matching_cookie(cookie_header, &mut found)?;
        found.ok_or_else(|| Error::MissingCookie {
            name: self.name.clone(),
        })
    }

    fn collect_matching_cookie(
        &self,
        cookie_header: &str,
        found: &mut Option<Cookie<'static>>,
    ) -> Result<(), Error> {
        for parsed in Cookie::split_parse(cookie_header) {
            let parsed = parsed.map_err(Error::CookieParse)?;
            if parsed.name() == self.name {
                if found.is_some() {
                    return Err(Error::DuplicateCookie {
                        name: self.name.clone(),
                    });
                }
                *found = Some(parsed.into_owned());
            }
        }
        Ok(())
    }

    fn apply_attributes(&self, cookie: &mut Cookie<'static>) {
        cookie.set_path(self.path.clone());
        if let Some(domain) = &self.domain {
            cookie.set_domain(domain.clone());
        }
        cookie.set_secure(self.secure);
        cookie.set_same_site(SameSite::from(self.same_site));
        cookie.set_http_only(self.http_only);
        cookie.set_partitioned(self.partitioned);
        if let Some(max_age) = self.max_age {
            cookie.set_max_age(max_age.as_cookie_duration());
        }
    }

    pub(super) fn associated_data(&self) -> Result<Vec<u8>, Error> {
        let domain = self.domain.as_deref().unwrap_or("");
        let parts = [
            COOKIE_ASSOCIATED_DATA_CONTEXT,
            self.name.as_bytes(),
            self.path.as_bytes(),
            domain.as_bytes(),
            &[self.scope.associated_data_byte()],
        ];
        let capacity = parts
            .iter()
            .map(|part| std::mem::size_of::<u64>() + part.len())
            .sum();
        let mut associated_data = public_vec_with_capacity(capacity)?;
        for part in parts {
            associated_data.extend_from_slice(&(part.len() as u64).to_be_bytes());
            associated_data.extend_from_slice(part);
        }
        Ok(associated_data)
    }

    pub(super) fn scope_label(&self) -> &'static str {
        match self.scope {
            CookieScopeKind::HostOnly => "host-only",
            CookieScopeKind::NonHostOnly => "non-host-only",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CookieScope {
    HostOnly,
    NonHostOnly {
        path: String,
        domain: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CookieScopeKind {
    HostOnly,
    NonHostOnly,
}

impl CookieScopeKind {
    fn associated_data_byte(self) -> u8 {
        match self {
            Self::HostOnly => 1,
            Self::NonHostOnly => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CookieHttpOnlyMode {
    Encrypted,
    ClientReadable,
}

pub(super) fn validate_unprefixed_cookie_name(name: &str) -> Result<(), Error> {
    if name.starts_with(HOST_PREFIX) {
        return Err(Error::ManagedCookieNamePrefix {
            prefix: HOST_PREFIX,
        });
    }
    if name.starts_with(DEV_PREFIX) {
        return Err(Error::ManagedCookieNamePrefix { prefix: DEV_PREFIX });
    }
    validate_cookie_name(name)
}

pub(super) fn validate_cookie_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::EmptyCookieName);
    }

    let mut probe = String::new();
    probe
        .try_reserve_exact(name.len() + 2)
        .map_err(|_| Error::AllocationFailed)?;
    probe.push_str(name);
    probe.push_str("=x");
    let parsed = Cookie::parse(probe).map_err(|_| Error::InvalidCookieName)?;
    if parsed.name() != name || parsed.value() != "x" {
        return Err(Error::InvalidCookieName);
    }
    Ok(())
}

pub(super) fn validate_cookie_value(value: &str) -> Result<(), Error> {
    let mut probe = String::new();
    probe
        .try_reserve_exact(2 + value.len())
        .map_err(|_| Error::AllocationFailed)?;
    probe.push_str("x=");
    probe.push_str(value);
    let parsed = Cookie::parse(probe).map_err(|_| Error::InvalidCookieValue)?;
    if parsed.name() != "x" || parsed.value() != value {
        return Err(Error::InvalidCookieValue);
    }
    Ok(())
}

fn normalize_path(path: String) -> Result<String, Error> {
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        path
    };
    if !path.starts_with('/') {
        return Err(Error::InvalidCookiePath);
    }
    validate_cookie_path(&path)?;
    Ok(path)
}

fn normalize_domain(domain: Option<String>) -> Result<Option<String>, Error> {
    let Some(domain) = domain else {
        return Ok(None);
    };
    if domain.is_empty() {
        return Ok(None);
    }
    let domain = domain
        .strip_prefix('.')
        .unwrap_or(&domain)
        .to_ascii_lowercase();
    validate_cookie_domain(&domain)?;
    Ok(Some(domain))
}

fn validate_cookie_path(path: &str) -> Result<(), Error> {
    if path.bytes().all(is_safe_cookie_attribute_byte) {
        Ok(())
    } else {
        Err(Error::InvalidCookiePath)
    }
}

fn validate_cookie_domain(domain: &str) -> Result<(), Error> {
    if domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.split('.').any(invalid_cookie_domain_label)
    {
        return Err(Error::InvalidCookieDomain);
    }
    Ok(())
}

fn invalid_cookie_domain_label(label: &str) -> bool {
    label.is_empty()
        || label.starts_with('-')
        || label.ends_with('-')
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_safe_cookie_attribute_byte(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7e) && byte != b';'
}

pub(super) fn missing_cookie_to_none<T>(result: Result<T, Error>) -> Result<Option<T>, Error> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Error::MissingCookie { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}
