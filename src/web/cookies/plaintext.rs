use super::*;

#[derive(Clone)]
pub(super) struct PlaintextCookie {
    spec: CookieSpec,
}

impl PlaintextCookie {
    pub(super) fn new(
        manager: &CookieManager,
        scope: CookieScope,
        config: CookieConfigParts,
    ) -> Result<Self, Error> {
        Ok(Self {
            spec: CookieSpec::new(manager, scope, config, CookieHttpOnlyMode::ClientReadable)?,
        })
    }

    pub(super) fn name(&self) -> &str {
        &self.spec.name
    }

    pub(super) fn new_cookie(&self, value: &str) -> Result<Cookie<'static>, Error> {
        self.spec.cookie_with_value(value.to_owned())
    }

    pub(super) fn get_from_cookie<T>(&self, cookie: &Cookie<'_>) -> Result<T, Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        if cookie.name() != self.name() {
            return Err(Error::CookieNameMismatch {
                expected: self.name().to_owned(),
                actual: cookie.name().to_owned(),
            });
        }
        self.parse_cookie_value(cookie.value())
    }

    pub(super) fn parse_cookie_value<T>(&self, value: &str) -> Result<T, Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        value
            .parse()
            .map_err(|error: T::Err| Error::ClientReadableCookieParse {
                message: error.to_string(),
            })
    }

    pub(super) fn get_from_cookie_header<T>(&self, cookie_header: &str) -> Result<T, Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        let parsed = self.spec.parse_from_cookie_header(cookie_header)?;
        self.get_from_cookie(&parsed)
    }

    pub(super) fn get_optional_from_cookie_header<T>(
        &self,
        cookie_header: &str,
    ) -> Result<Option<T>, Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        missing_cookie_to_none(self.get_from_cookie_header(cookie_header))
    }

    pub(super) fn get_from_request<T, B>(&self, request: &Request<B>) -> Result<T, Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        let parsed = self.spec.parse_from_request(request)?;
        self.get_from_cookie(&parsed)
    }

    pub(super) fn get_from_headers<T>(&self, headers: &HeaderMap) -> Result<T, Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        let parsed = self.spec.parse_from_headers(headers)?;
        self.get_from_cookie(&parsed)
    }

    pub(super) fn get_optional_from_headers<T>(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<T>, Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        missing_cookie_to_none(self.get_from_headers(headers))
    }

    pub(super) fn get_optional_from_request<T, B>(
        &self,
        request: &Request<B>,
    ) -> Result<Option<T>, Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        missing_cookie_to_none(self.get_from_request(request))
    }

    pub(super) fn deletion_cookie(&self) -> Cookie<'static> {
        self.spec.deletion_cookie()
    }
}

impl fmt::Debug for PlaintextCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaintextCookie")
            .field("name", &self.spec.name)
            .field("scope", &self.spec.scope_label())
            .finish()
    }
}
