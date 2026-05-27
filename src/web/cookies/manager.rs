use super::*;

/// SameSite setting for cookies emitted by this crate.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum CookieSameSite {
    /// `SameSite=Lax`.
    #[default]
    Lax,
    /// `SameSite=Strict`.
    Strict,
    /// `SameSite=None`.
    None,
}

impl From<CookieSameSite> for SameSite {
    fn from(value: CookieSameSite) -> Self {
        match value {
            CookieSameSite::Lax => Self::Lax,
            CookieSameSite::Strict => Self::Strict,
            CookieSameSite::None => Self::None,
        }
    }
}

/// Positive cookie `Max-Age` in whole seconds.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CookieMaxAgeSeconds(NonZeroU64);

impl CookieMaxAgeSeconds {
    /// Creates a positive whole-second cookie max-age.
    pub fn new(seconds: u64) -> Result<Self, Error> {
        let seconds = NonZeroU64::new(seconds).ok_or(Error::CookieMaxAgeSecondsZero)?;
        if seconds.get() > MAX_COOKIE_MAX_AGE_SECONDS {
            return Err(Error::CookieMaxAgeSecondsTooLarge {
                seconds: seconds.get(),
                max: MAX_COOKIE_MAX_AGE_SECONDS,
            });
        }
        Ok(Self(seconds))
    }

    /// Returns the configured whole-second cookie max-age.
    pub fn get(self) -> u64 {
        self.0.get()
    }

    pub(super) fn as_cookie_duration(self) -> cookie::time::Duration {
        cookie::time::Duration::seconds(self.0.get() as i64)
    }
}

/// Cookie manager configuration.
pub struct CookieManagerConfig {
    /// Returns the current latest-first cookie keyset.
    pub get_keyset: Arc<dyn Fn() -> Result<Arc<Keyset>, Error> + Send + Sync + 'static>,
    /// Returns whether emitted cookies should use development behavior.
    pub is_development: Arc<dyn Fn() -> bool + Send + Sync + 'static>,
    /// Default `SameSite` setting when a cookie config does not override it.
    pub default_same_site: CookieSameSite,
    /// Default `Partitioned` setting when a cookie config does not override it.
    pub default_partitioned: bool,
}

impl CookieManagerConfig {
    /// Creates cookie manager configuration from a live keyset callback.
    pub fn new(
        get_keyset: impl Fn() -> Result<Arc<Keyset>, Error> + Send + Sync + 'static,
    ) -> Self {
        Self {
            get_keyset: Arc::new(get_keyset),
            is_development: Arc::new(|| false),
            default_same_site: CookieSameSite::Lax,
            default_partitioned: true,
        }
    }

    /// Creates cookie manager configuration from a fixed in-memory keyset.
    pub fn from_keyset(keyset: Keyset) -> Self {
        let keyset = Arc::new(keyset);
        Self::new(move || Ok(keyset.clone()))
    }
}

impl fmt::Debug for CookieManagerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieManagerConfig")
            .field("get_keyset", &"[callback]")
            .field("is_development", &"[callback]")
            .field("default_same_site", &self.default_same_site)
            .field("default_partitioned", &self.default_partitioned)
            .finish()
    }
}

/// Environment-aware cookie policy and key access.
#[derive(Clone)]
pub struct CookieManager {
    inner: Arc<CookieManagerInner>,
}

struct CookieManagerInner {
    get_keyset: Arc<dyn Fn() -> Result<Arc<Keyset>, Error> + Send + Sync + 'static>,
    is_development: Arc<dyn Fn() -> bool + Send + Sync + 'static>,
    default_same_site: CookieSameSite,
    default_partitioned: bool,
}

impl CookieManager {
    /// Creates a cookie manager from explicit policy and key defaults.
    pub fn new(config: CookieManagerConfig) -> Self {
        Self {
            inner: Arc::new(CookieManagerInner {
                get_keyset: config.get_keyset,
                is_development: config.is_development,
                default_same_site: config.default_same_site,
                default_partitioned: config.default_partitioned,
            }),
        }
    }

    /// Creates a production-mode cookie manager from a fixed in-memory keyset.
    pub fn from_keyset(keyset: Keyset) -> Self {
        Self::new(CookieManagerConfig::from_keyset(keyset))
    }

    /// Returns whether this manager is configured for development behavior.
    pub fn is_development(&self) -> bool {
        (self.inner.is_development)()
    }

    /// Creates a host-only encrypted cookie helper.
    pub fn secure_cookie<T>(&self, config: SecureCookieConfig) -> Result<SecureCookie<T>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        Ok(SecureCookie {
            encrypted: EncryptedCookie::new(self, CookieScope::HostOnly, config.into_parts())?,
            payload: PhantomData,
        })
    }

    /// Creates a non-host-only encrypted cookie helper.
    pub fn secure_cookie_non_host_only<T>(
        &self,
        config: SecureCookieNonHostOnlyConfig,
    ) -> Result<SecureCookieNonHostOnly<T>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        let SecureCookieNonHostOnlyConfig {
            name,
            path,
            domain,
            max_age,
            same_site,
            partitioned,
        } = config;
        Ok(SecureCookieNonHostOnly {
            encrypted: EncryptedCookie::new(
                self,
                CookieScope::NonHostOnly { path, domain },
                CookieConfigParts {
                    name,
                    max_age,
                    same_site,
                    partitioned,
                    http_only: None,
                },
            )?,
            payload: PhantomData,
        })
    }

    /// Creates a host-only client-readable cookie helper.
    pub fn client_readable_cookie<T>(
        &self,
        config: ClientReadableCookieConfig,
    ) -> Result<ClientReadableCookie<T>, Error>
    where
        T: FromStr + fmt::Display,
        T::Err: fmt::Display,
    {
        Ok(ClientReadableCookie {
            plaintext: PlaintextCookie::new(self, CookieScope::HostOnly, config.into_parts())?,
            value: PhantomData,
        })
    }

    /// Creates a non-host-only client-readable cookie helper.
    pub fn client_readable_cookie_non_host_only<T>(
        &self,
        config: ClientReadableCookieNonHostOnlyConfig,
    ) -> Result<ClientReadableCookieNonHostOnly<T>, Error>
    where
        T: FromStr + fmt::Display,
        T::Err: fmt::Display,
    {
        let ClientReadableCookieNonHostOnlyConfig {
            name,
            path,
            domain,
            max_age,
            same_site,
            partitioned,
        } = config;
        Ok(ClientReadableCookieNonHostOnly {
            plaintext: PlaintextCookie::new(
                self,
                CookieScope::NonHostOnly { path, domain },
                CookieConfigParts {
                    name,
                    max_age,
                    same_site,
                    partitioned,
                    http_only: None,
                },
            )?,
            value: PhantomData,
        })
    }

    pub(super) fn encrypted_cookie_keyset(&self) -> Result<Keyset, Error> {
        Ok((self.inner.get_keyset)()?.derive_child_keyset(ENCRYPTED_COOKIE_CHILD_PURPOSE)?)
    }

    pub(super) fn final_host_only_name(&self, name: &str) -> Result<String, Error> {
        validate_unprefixed_cookie_name(name)?;
        let prefix = if self.is_development() {
            DEV_PREFIX
        } else {
            HOST_PREFIX
        };
        let mut final_name = String::new();
        final_name
            .try_reserve_exact(prefix.len() + name.len())
            .map_err(|_| Error::AllocationFailed)?;
        final_name.push_str(prefix);
        final_name.push_str(name);
        validate_cookie_name(&final_name)?;
        Ok(final_name)
    }

    pub(super) fn resolve_same_site(&self, configured: Option<CookieSameSite>) -> CookieSameSite {
        configured.unwrap_or(self.inner.default_same_site)
    }

    pub(super) fn resolve_partitioned(&self, configured: Option<bool>) -> bool {
        configured.unwrap_or(self.inner.default_partitioned) && !self.is_development()
    }

    pub(super) fn resolve_http_only(&self, configured: Option<bool>) -> bool {
        configured.unwrap_or(true)
    }

    pub(crate) fn secure_cookie_with_http_only<T>(
        &self,
        config: SecureCookieConfig,
        http_only: bool,
    ) -> Result<SecureCookie<T>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        Ok(SecureCookie {
            encrypted: EncryptedCookie::new(
                self,
                CookieScope::HostOnly,
                config.into_parts_with_http_only(Some(http_only)),
            )?,
            payload: PhantomData,
        })
    }
}

impl fmt::Debug for CookieManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieManager")
            .field("is_development", &self.is_development())
            .field("default_same_site", &self.inner.default_same_site)
            .field("default_partitioned", &self.inner.default_partitioned)
            .finish()
    }
}
