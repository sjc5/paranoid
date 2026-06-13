use super::*;

#[derive(Debug)]
pub(crate) enum MountedAuthHttpServiceError {
    Body(MountedAuthHttpBodyError),
    Route(MountedAuthRouteServiceError),
    SystemTimeBeforeUnixEpoch,
}

impl From<MountedAuthHttpBodyError> for MountedAuthHttpServiceError {
    fn from(error: MountedAuthHttpBodyError) -> Self {
        Self::Body(error)
    }
}

impl From<MountedAuthRouteServiceError> for MountedAuthHttpServiceError {
    fn from(error: MountedAuthRouteServiceError) -> Self {
        Self::Route(error)
    }
}

/// Error returned when mounted auth runtime configuration is incomplete.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthRuntimeError {
    FullAuthenticationOutOfBandMethodNotConfigured,
    NoSessionCredentialRecoveryFlowNotConfigured,
    AdminSupportStaffAuthorizerNotConfigured,
    DurableEffectWorkerIntegrationsNotConfigured,
    DurableEffectWorkerIntegrationsRequiredForConfiguredRoutes,
    MethodRegistryRequiredForConfiguredRoutes,
    InvalidRouteMountPath(&'static str),
    ConfiguredMethodNotRegistered {
        family: ProofFamily,
        method_label: String,
    },
    ConfiguredMethodLacksMountedRouteCapability {
        family: ProofFamily,
        method_label: String,
        route_family: &'static str,
        capability: &'static str,
    },
    MountedRoutesRequireMethodCapability {
        route_family: &'static str,
        capability: &'static str,
    },
}

impl fmt::Display for MountedAuthRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullAuthenticationOutOfBandMethodNotConfigured => {
                write!(
                    f,
                    "auth core: full-authentication out-of-band method is not configured"
                )
            }
            Self::NoSessionCredentialRecoveryFlowNotConfigured => {
                write!(
                    f,
                    "auth core: no-session credential recovery flow is not configured"
                )
            }
            Self::AdminSupportStaffAuthorizerNotConfigured => {
                write!(
                    f,
                    "auth core: admin support staff authorizer is not configured"
                )
            }
            Self::DurableEffectWorkerIntegrationsNotConfigured => {
                write!(
                    f,
                    "auth core: durable-effect worker integrations are not configured"
                )
            }
            Self::DurableEffectWorkerIntegrationsRequiredForConfiguredRoutes => {
                write!(
                    f,
                    "auth core: configured mounted auth routes require durable-effect worker integrations"
                )
            }
            Self::MethodRegistryRequiredForConfiguredRoutes => {
                write!(
                    f,
                    "auth core: configured mounted auth routes require an auth method registry"
                )
            }
            Self::InvalidRouteMountPath(reason) => {
                write!(f, "auth core: invalid auth route mount path: {reason}")
            }
            Self::ConfiguredMethodNotRegistered {
                family,
                method_label,
            } => {
                write!(
                    f,
                    "auth core: mounted auth config references unregistered method {family:?}/{method_label}"
                )
            }
            Self::ConfiguredMethodLacksMountedRouteCapability {
                family,
                method_label,
                route_family,
                capability,
            } => {
                write!(
                    f,
                    "auth core: mounted auth {route_family} require method {family:?}/{method_label} to support {capability}"
                )
            }
            Self::MountedRoutesRequireMethodCapability {
                route_family,
                capability,
            } => {
                write!(
                    f,
                    "auth core: mounted auth {route_family} require a registered method that supports {capability}"
                )
            }
        }
    }
}

impl std::error::Error for MountedAuthRuntimeError {}

/// Error returned by the private mounted auth route service.
#[derive(Debug)]
pub(crate) enum MountedAuthRouteServiceError {
    Runtime(MountedAuthRuntimeError),
    CredentialLifecycle(MountedCredentialLifecycleServiceError),
    SubjectLifecycle(MountedSubjectLifecycleServiceError),
    AdminSupport(MountedAdminSupportServiceError),
    HttpBody(MountedAuthHttpBodyError),
    RouteNotFound {
        method: Method,
        path: String,
    },
    RouteBodyMismatch {
        route_kind: &'static str,
        body_kind: &'static str,
    },
}

impl From<MountedAuthRuntimeError> for MountedAuthRouteServiceError {
    fn from(error: MountedAuthRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<MountedCredentialLifecycleServiceError> for MountedAuthRouteServiceError {
    fn from(error: MountedCredentialLifecycleServiceError) -> Self {
        Self::CredentialLifecycle(error)
    }
}

impl From<MountedSubjectLifecycleServiceError> for MountedAuthRouteServiceError {
    fn from(error: MountedSubjectLifecycleServiceError) -> Self {
        Self::SubjectLifecycle(error)
    }
}

impl From<MountedAdminSupportServiceError> for MountedAuthRouteServiceError {
    fn from(error: MountedAdminSupportServiceError) -> Self {
        Self::AdminSupport(error)
    }
}

impl From<MountedAuthHttpBodyError> for MountedAuthRouteServiceError {
    fn from(error: MountedAuthHttpBodyError) -> Self {
        Self::HttpBody(error)
    }
}

impl fmt::Display for MountedAuthRouteServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => write!(f, "{error}"),
            Self::CredentialLifecycle(error) => write!(f, "{error}"),
            Self::SubjectLifecycle(error) => write!(f, "{error}"),
            Self::AdminSupport(error) => write!(f, "{error}"),
            Self::HttpBody(error) => write!(f, "{error}"),
            Self::RouteNotFound { method, path } => {
                write!(
                    f,
                    "auth core: mounted auth route not found for {method} {path}"
                )
            }
            Self::RouteBodyMismatch {
                route_kind,
                body_kind,
            } => write!(
                f,
                "auth core: mounted auth route body mismatch: route expects {route_kind}, body is {body_kind}"
            ),
        }
    }
}

impl std::error::Error for MountedAuthRouteServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::CredentialLifecycle(error) => Some(error),
            Self::SubjectLifecycle(error) => Some(error),
            Self::AdminSupport(error) => Some(error),
            Self::HttpBody(error) => Some(error),
            Self::RouteNotFound { .. } => None,
            Self::RouteBodyMismatch { .. } => None,
        }
    }
}

/// Error returned while parsing collected HTTP body bytes for mounted auth routes.
#[derive(Debug)]
pub(crate) enum MountedAuthHttpBodyError {
    UnsupportedContentType {
        expected: &'static str,
        actual: Option<String>,
    },
    BodyTooLong {
        input_name: &'static str,
        actual_bytes: usize,
        max_bytes: usize,
    },
    InvalidJson {
        input_name: &'static str,
        source: serde_json::Error,
    },
    UnexpectedBody {
        input_name: &'static str,
        actual_bytes: usize,
    },
    UnexpectedFieldForDisabledOption {
        field_name: &'static str,
        option_name: &'static str,
    },
    BodyRead {
        source: String,
    },
    UnknownWeakProofGateKind {
        value: String,
    },
    UnknownApplicationSubjectDataLifecycleAction {
        value: String,
    },
    UnknownCredentialLifecycleAction {
        value: String,
    },
    EncodedFieldTooLong {
        field_name: &'static str,
        actual_bytes: usize,
        max_bytes: usize,
    },
    InvalidBase64Url {
        field_name: &'static str,
        source: data_encoding::DecodeError,
    },
    NonCanonicalBase64Url {
        field_name: &'static str,
    },
    DecodedFieldTooLong {
        field_name: &'static str,
        actual_bytes: usize,
        max_bytes: usize,
    },
}

impl fmt::Display for MountedAuthHttpBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedContentType { expected, actual } => {
                let actual = actual.as_deref().unwrap_or("missing");
                write!(
                    f,
                    "auth core: mounted auth request body requires content-type {expected}, got {actual}"
                )
            }
            Self::BodyTooLong {
                input_name,
                actual_bytes,
                max_bytes,
            } => write!(
                f,
                "auth core: mounted auth {input_name} is {actual_bytes} bytes, maximum is {max_bytes}"
            ),
            Self::InvalidJson { input_name, .. } => {
                write!(f, "auth core: mounted auth {input_name} is not valid JSON")
            }
            Self::UnexpectedBody {
                input_name,
                actual_bytes,
            } => write!(
                f,
                "auth core: mounted auth {input_name} must be empty, got {actual_bytes} bytes"
            ),
            Self::UnexpectedFieldForDisabledOption {
                field_name,
                option_name,
            } => write!(
                f,
                "auth core: mounted auth body field {field_name} is only allowed when {option_name} is enabled"
            ),
            Self::BodyRead { .. } => {
                write!(f, "auth core: mounted auth request body could not be read")
            }
            Self::UnknownWeakProofGateKind { value } => write!(
                f,
                "auth core: mounted auth request body contains unknown weak-proof gate kind {value}"
            ),
            Self::UnknownApplicationSubjectDataLifecycleAction { value } => write!(
                f,
                "auth core: mounted auth request body contains unknown application subject data lifecycle action {value}"
            ),
            Self::UnknownCredentialLifecycleAction { value } => write!(
                f,
                "auth core: mounted auth request body contains unknown credential lifecycle action {value}"
            ),
            Self::EncodedFieldTooLong {
                field_name,
                actual_bytes,
                max_bytes,
            } => write!(
                f,
                "auth core: mounted auth body field {field_name} is {actual_bytes} bytes, maximum is {max_bytes}"
            ),
            Self::InvalidBase64Url { field_name, .. } => write!(
                f,
                "auth core: mounted auth body field {field_name} is not canonical base64url"
            ),
            Self::NonCanonicalBase64Url { field_name } => write!(
                f,
                "auth core: mounted auth body field {field_name} is not canonical base64url"
            ),
            Self::DecodedFieldTooLong {
                field_name,
                actual_bytes,
                max_bytes,
            } => write!(
                f,
                "auth core: mounted auth body field {field_name} decodes to {actual_bytes} bytes, maximum is {max_bytes}"
            ),
        }
    }
}

impl std::error::Error for MountedAuthHttpBodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidJson { source, .. } => Some(source),
            Self::InvalidBase64Url { source, .. } => Some(source),
            Self::UnsupportedContentType { .. }
            | Self::BodyTooLong { .. }
            | Self::BodyRead { .. }
            | Self::UnknownWeakProofGateKind { .. }
            | Self::UnknownApplicationSubjectDataLifecycleAction { .. }
            | Self::UnknownCredentialLifecycleAction { .. }
            | Self::UnexpectedBody { .. }
            | Self::UnexpectedFieldForDisabledOption { .. }
            | Self::EncodedFieldTooLong { .. }
            | Self::NonCanonicalBase64Url { .. }
            | Self::DecodedFieldTooLong { .. } => None,
        }
    }
}
