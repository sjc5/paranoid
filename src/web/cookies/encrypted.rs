use super::*;

#[derive(Clone)]
pub(super) struct EncryptedCookie {
    manager: CookieManager,
    spec: CookieSpec,
    associated_data: Vec<u8>,
}

impl EncryptedCookie {
    pub(super) fn new(
        manager: &CookieManager,
        scope: CookieScope,
        config: CookieConfigParts,
    ) -> Result<Self, Error> {
        let spec = CookieSpec::new(manager, scope, config, CookieHttpOnlyMode::Encrypted)?;
        let associated_data = spec.associated_data()?;
        Ok(Self {
            manager: manager.clone(),
            spec,
            associated_data,
        })
    }

    pub(super) fn name(&self) -> &str {
        &self.spec.name
    }

    pub(super) fn new_cookie<T>(&self, payload: &T) -> Result<Cookie<'static>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        let keyset = self.manager.encrypted_cookie_keyset()?;
        let encrypted = encrypt(&keyset, payload, &self.associated_data)?;
        let encoded_value = encrypted.to_base64_url()?.into_exposed_string();
        self.spec.cookie_with_value(encoded_value)
    }

    pub(super) fn decode_cookie_value<T>(&self, value: &str) -> Result<T, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        if value.is_empty() {
            return Err(Error::EmptyCookieValue);
        }
        let encrypted: Encrypted<T> = Base64Url::parse_str(value)?.decode()?;
        let keyset = self.manager.encrypted_cookie_keyset()?;
        Ok(decrypt(&keyset, &encrypted, &self.associated_data)?)
    }

    pub(super) fn get_from_cookie<T>(&self, cookie: &Cookie<'_>) -> Result<T, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        self.ensure_cookie_name_matches(cookie)?;
        self.decode_cookie_value(cookie.value())
    }

    pub(super) fn get_from_cookie_header<T>(&self, cookie_header: &str) -> Result<T, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        let parsed = self.spec.parse_from_cookie_header(cookie_header)?;
        self.get_from_cookie(&parsed)
    }

    pub(super) fn get_optional_from_cookie_header<T>(
        &self,
        cookie_header: &str,
    ) -> Result<Option<T>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        missing_cookie_to_none(self.get_from_cookie_header(cookie_header))
    }

    pub(super) fn parse_from_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<Cookie<'static>, Error> {
        self.spec.parse_from_request(request)
    }

    pub(super) fn get_from_headers<T>(&self, headers: &HeaderMap) -> Result<T, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        let parsed = self.spec.parse_from_headers(headers)?;
        self.get_from_cookie(&parsed)
    }

    pub(super) fn get_optional_from_headers<T>(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<T>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        missing_cookie_to_none(self.get_from_headers(headers))
    }

    pub(super) fn get_from_request<T, B>(&self, request: &Request<B>) -> Result<T, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        let parsed = self.spec.parse_from_request(request)?;
        self.get_from_cookie(&parsed)
    }

    pub(super) fn get_optional_from_request<T, B>(
        &self,
        request: &Request<B>,
    ) -> Result<Option<T>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        missing_cookie_to_none(self.get_from_request(request))
    }

    pub(super) fn deletion_cookie(&self) -> Cookie<'static> {
        self.spec.deletion_cookie()
    }

    fn ensure_cookie_name_matches(&self, cookie: &Cookie<'_>) -> Result<(), Error> {
        if cookie.name() != self.name() {
            return Err(Error::CookieNameMismatch {
                expected: self.name().to_owned(),
                actual: cookie.name().to_owned(),
            });
        }
        Ok(())
    }
}

impl fmt::Debug for EncryptedCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedCookie")
            .field("name", &self.spec.name)
            .field("scope", &self.spec.scope_label())
            .finish()
    }
}
