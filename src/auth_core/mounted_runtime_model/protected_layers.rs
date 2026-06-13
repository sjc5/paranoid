use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedAuthRequestState {
    outcome: MountedAuthRequestResolutionOutcome,
}

impl MountedAuthRequestState {
    pub(crate) fn from_request_resolution_outcome(
        outcome: Outcome,
    ) -> Result<Self, MountedAuthRequestResolutionError> {
        let outcome = match outcome {
            Outcome::Authenticated(authenticated) => {
                MountedAuthRequestResolutionOutcome::Authenticated {
                    subject_id: authenticated.subject_id,
                    session_id: authenticated.session_id,
                    source: authenticated.source,
                    step_up_is_fresh: authenticated.step_up_is_fresh,
                }
            }
            Outcome::NeedsStepUp {
                session_id,
                subject_id,
            } => MountedAuthRequestResolutionOutcome::NeedsStepUp {
                subject_id,
                session_id,
            },
            Outcome::NeedsActiveProofFromTrustedDevice {
                device_credential_id,
                subject_id,
            } => MountedAuthRequestResolutionOutcome::NeedsActiveProofFromTrustedDevice {
                subject_id,
                device_credential_id,
            },
            Outcome::NeedsFullAuthentication => {
                MountedAuthRequestResolutionOutcome::NeedsFullAuthentication
            }
            _ => return Err(MountedAuthRequestResolutionError::UnexpectedRuntimeOutcome),
        };
        Ok(Self { outcome })
    }

    pub(crate) const fn outcome(&self) -> &MountedAuthRequestResolutionOutcome {
        &self.outcome
    }

    pub(crate) const fn authenticated_subject_id(&self) -> Option<&SubjectId> {
        match &self.outcome {
            MountedAuthRequestResolutionOutcome::Authenticated { subject_id, .. } => {
                Some(subject_id)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthRequestResolutionOutcome {
    Authenticated {
        subject_id: SubjectId,
        session_id: SessionId,
        source: AuthenticationSource,
        step_up_is_fresh: bool,
    },
    NeedsStepUp {
        subject_id: SubjectId,
        session_id: SessionId,
    },
    NeedsActiveProofFromTrustedDevice {
        subject_id: SubjectId,
        device_credential_id: TrustedDeviceCredentialId,
    },
    NeedsFullAuthentication,
}

async fn execute_mounted_auth_request_resolution(
    runtime: &PostgresAuthWebRuntime,
    headers: &HeaderMap,
    request_kind: RequestKind,
    now: UnixSeconds,
) -> Result<(MountedAuthRequestState, AuthSetCookieHeaders), MountedAuthRequestResolutionStepError>
{
    let execution = runtime
        .execute_request_resolution_from_headers(headers, ResolveRequestInput { now, request_kind })
        .await
        .map_err(MountedAuthRequestResolutionStepError::Auth)?;
    let (outcome, set_cookie_headers) = execution.into_parts();
    let request_state = MountedAuthRequestState::from_request_resolution_outcome(outcome)
        .map_err(MountedAuthRequestResolutionStepError::RequestResolution)?;
    Ok((request_state, set_cookie_headers))
}

#[derive(Debug)]
pub(crate) enum MountedAuthRequestResolutionStepError {
    Auth(AuthPostgresWebRuntimeExecutionError),
    RequestResolution(MountedAuthRequestResolutionError),
}

impl fmt::Display for MountedAuthRequestResolutionStepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "{error}"),
            Self::RequestResolution(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for MountedAuthRequestResolutionStepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Auth(error) => Some(error),
            Self::RequestResolution(error) => Some(error),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MountedAuthRequestResolutionLayer<'a> {
    runtime: &'a PostgresAuthWebRuntime,
    request_kind: RequestKind,
    now_source: MountedAuthHttpNowSource,
}

impl<'a> MountedAuthRequestResolutionLayer<'a> {
    pub(crate) const fn new(
        runtime: &'a PostgresAuthWebRuntime,
        request_kind: RequestKind,
    ) -> Self {
        Self {
            runtime,
            request_kind,
            now_source: MountedAuthHttpNowSource::System,
        }
    }

    #[cfg(test)]
    pub(crate) const fn with_fixed_now_for_tests(mut self, now: UnixSeconds) -> Self {
        self.now_source = MountedAuthHttpNowSource::Fixed(now);
        self
    }
}

impl<'a, S> Layer<S> for MountedAuthRequestResolutionLayer<'a> {
    type Service = MountedAuthRequestResolutionService<'a, S>;

    fn layer(&self, inner: S) -> Self::Service {
        MountedAuthRequestResolutionService {
            inner,
            runtime: self.runtime,
            request_kind: self.request_kind,
            now_source: self.now_source,
        }
    }
}

#[derive(Clone)]
pub(crate) struct MountedAuthRequestResolutionService<'a, S> {
    inner: S,
    runtime: &'a PostgresAuthWebRuntime,
    request_kind: RequestKind,
    now_source: MountedAuthHttpNowSource,
}

type MountedAuthRequestResolutionServiceFuture<'a, ResponseBody, InnerError> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    Response<ResponseBody>,
                    MountedAuthRequestResolutionServiceError<InnerError>,
                >,
            > + 'a,
    >,
>;

impl<'a, S, RequestBody, ResponseBody> Service<Request<RequestBody>>
    for MountedAuthRequestResolutionService<'a, S>
where
    S: Service<Request<RequestBody>, Response = Response<ResponseBody>> + Clone + 'a,
    S::Future: 'a,
    RequestBody: 'a,
    ResponseBody: 'a,
{
    type Response = Response<ResponseBody>;
    type Error = MountedAuthRequestResolutionServiceError<S::Error>;
    type Future = MountedAuthRequestResolutionServiceFuture<'a, ResponseBody, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(MountedAuthRequestResolutionServiceError::Inner)
    }

    fn call(&mut self, request: Request<RequestBody>) -> Self::Future {
        let runtime = self.runtime;
        let request_kind = self.request_kind;
        let now_source = self.now_source;
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let now = now_source
                .now()
                .map_err(MountedAuthRequestResolutionServiceError::from)?;
            let (mut parts, body) = request.into_parts();
            let (request_state, set_cookie_headers) =
                execute_mounted_auth_request_resolution(runtime, &parts.headers, request_kind, now)
                    .await
                    .map_err(MountedAuthRequestResolutionServiceError::from_step_error)?;
            parts.extensions.insert(request_state);
            let mut response = inner
                .call(Request::from_parts(parts, body))
                .await
                .map_err(MountedAuthRequestResolutionServiceError::Inner)?;
            set_cookie_headers.append_to_headers(response.headers_mut());
            Ok(response)
        })
    }
}

#[derive(Debug)]
pub(crate) enum MountedAuthRequestResolutionServiceError<InnerError> {
    Auth(AuthPostgresWebRuntimeExecutionError),
    RequestResolution(MountedAuthRequestResolutionError),
    Inner(InnerError),
}

impl<InnerError> MountedAuthRequestResolutionServiceError<InnerError> {
    fn from_step_error(error: MountedAuthRequestResolutionStepError) -> Self {
        match error {
            MountedAuthRequestResolutionStepError::Auth(error) => Self::Auth(error),
            MountedAuthRequestResolutionStepError::RequestResolution(error) => {
                Self::RequestResolution(error)
            }
        }
    }
}

impl<InnerError> From<MountedAuthHttpServiceError>
    for MountedAuthRequestResolutionServiceError<InnerError>
{
    fn from(error: MountedAuthHttpServiceError) -> Self {
        match error {
            MountedAuthHttpServiceError::SystemTimeBeforeUnixEpoch => Self::RequestResolution(
                MountedAuthRequestResolutionError::SystemTimeBeforeUnixEpoch,
            ),
            MountedAuthHttpServiceError::Body(_) | MountedAuthHttpServiceError::Route(_) => {
                Self::RequestResolution(MountedAuthRequestResolutionError::UnexpectedRuntimeOutcome)
            }
        }
    }
}

impl<InnerError: fmt::Display> fmt::Display
    for MountedAuthRequestResolutionServiceError<InnerError>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "{error}"),
            Self::RequestResolution(error) => write!(f, "{error}"),
            Self::Inner(error) => write!(f, "{error}"),
        }
    }
}

impl<InnerError> std::error::Error for MountedAuthRequestResolutionServiceError<InnerError>
where
    InnerError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Auth(error) => Some(error),
            Self::RequestResolution(error) => Some(error),
            Self::Inner(error) => Some(error),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthRequestResolutionError {
    UnexpectedRuntimeOutcome,
    SystemTimeBeforeUnixEpoch,
}

impl fmt::Display for MountedAuthRequestResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedRuntimeOutcome => {
                write!(
                    f,
                    "auth core: unexpected mounted request resolution outcome"
                )
            }
            Self::SystemTimeBeforeUnixEpoch => {
                write!(f, "auth core: system time is before the Unix epoch")
            }
        }
    }
}

impl std::error::Error for MountedAuthRequestResolutionError {}

/// Policy for one protected application route mounted behind Paranoid auth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MountedAuthProtectedRoutePolicy {
    request_kind: RequestKind,
    requirement: MountedAuthRouteRequirement,
}

impl MountedAuthProtectedRoutePolicy {
    pub(crate) const fn authenticated_subject_for_safe_read() -> Self {
        Self {
            request_kind: RequestKind::SafeRead,
            requirement: MountedAuthRouteRequirement::AuthenticatedSubject,
        }
    }

    pub(crate) const fn authenticated_subject_for_state_changing_request() -> Self {
        Self {
            request_kind: RequestKind::StateChanging,
            requirement: MountedAuthRouteRequirement::AuthenticatedSubject,
        }
    }

    pub(crate) const fn fresh_step_up_for_sensitive_request() -> Self {
        Self {
            request_kind: RequestKind::Sensitive,
            requirement: MountedAuthRouteRequirement::FreshStepUp,
        }
    }

    pub(crate) const fn request_kind(self) -> RequestKind {
        self.request_kind
    }

    pub(crate) const fn requirement(self) -> MountedAuthRouteRequirement {
        self.requirement
    }
}

/// Auth requirement enforced by a mounted application route layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthRouteRequirement {
    AuthenticatedSubject,
    FreshStepUp,
}

impl MountedAuthRouteRequirement {
    fn enforce(
        self,
        state: Option<&MountedAuthRequestState>,
    ) -> Result<(), MountedAuthRouteRequirementError> {
        let state = state.ok_or(MountedAuthRouteRequirementError::MissingRequestState)?;
        match (self, state.outcome()) {
            (
                Self::AuthenticatedSubject,
                MountedAuthRequestResolutionOutcome::Authenticated { .. },
            ) => Ok(()),
            (
                Self::FreshStepUp,
                MountedAuthRequestResolutionOutcome::Authenticated {
                    step_up_is_fresh: true,
                    ..
                },
            ) => Ok(()),
            (
                Self::FreshStepUp,
                MountedAuthRequestResolutionOutcome::Authenticated {
                    subject_id,
                    session_id,
                    step_up_is_fresh: false,
                    ..
                },
            )
            | (
                _,
                MountedAuthRequestResolutionOutcome::NeedsStepUp {
                    subject_id,
                    session_id,
                },
            ) => Err(MountedAuthRouteRequirementError::NeedsStepUp {
                subject_id: subject_id.clone(),
                session_id: session_id.clone(),
            }),
            (_, MountedAuthRequestResolutionOutcome::NeedsFullAuthentication) => {
                Err(MountedAuthRouteRequirementError::NeedsFullAuthentication)
            }
            (
                _,
                MountedAuthRequestResolutionOutcome::NeedsActiveProofFromTrustedDevice {
                    subject_id,
                    device_credential_id,
                },
            ) => Err(
                MountedAuthRouteRequirementError::NeedsActiveProofFromTrustedDevice {
                    subject_id: subject_id.clone(),
                    device_credential_id: device_credential_id.clone(),
                },
            ),
        }
    }
}

/// Layer that enforces a mounted auth route requirement from request extensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MountedAuthRouteRequirementLayer {
    requirement: MountedAuthRouteRequirement,
}

impl MountedAuthRouteRequirementLayer {
    pub(crate) const fn new(requirement: MountedAuthRouteRequirement) -> Self {
        Self { requirement }
    }

    pub(crate) const fn requirement(self) -> MountedAuthRouteRequirement {
        self.requirement
    }
}

impl<S> Layer<S> for MountedAuthRouteRequirementLayer {
    type Service = MountedAuthRouteRequirementService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MountedAuthRouteRequirementService {
            inner,
            requirement: self.requirement,
        }
    }
}

#[derive(Clone)]
pub(crate) struct MountedAuthRouteRequirementService<S> {
    inner: S,
    requirement: MountedAuthRouteRequirement,
}

type MountedAuthRouteRequirementServiceFuture<'a, ResponseBody, InnerError> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    Response<ResponseBody>,
                    MountedAuthRouteRequirementServiceError<InnerError>,
                >,
            > + 'a,
    >,
>;

impl<S, RequestBody, ResponseBody> Service<Request<RequestBody>>
    for MountedAuthRouteRequirementService<S>
where
    S: Service<Request<RequestBody>, Response = Response<ResponseBody>> + Clone + 'static,
    S::Future: 'static,
    RequestBody: 'static,
    ResponseBody: 'static,
{
    type Response = Response<ResponseBody>;
    type Error = MountedAuthRouteRequirementServiceError<S::Error>;
    type Future = MountedAuthRouteRequirementServiceFuture<'static, ResponseBody, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(MountedAuthRouteRequirementServiceError::Inner)
    }

    fn call(&mut self, request: Request<RequestBody>) -> Self::Future {
        let requirement = self.requirement;
        let mut inner = self.inner.clone();
        Box::pin(async move {
            requirement
                .enforce(request.extensions().get::<MountedAuthRequestState>())
                .map_err(MountedAuthRouteRequirementServiceError::Requirement)?;
            inner
                .call(request)
                .await
                .map_err(MountedAuthRouteRequirementServiceError::Inner)
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthRouteRequirementError {
    MissingRequestState,
    NeedsFullAuthentication,
    NeedsStepUp {
        subject_id: SubjectId,
        session_id: SessionId,
    },
    NeedsActiveProofFromTrustedDevice {
        subject_id: SubjectId,
        device_credential_id: TrustedDeviceCredentialId,
    },
}

impl fmt::Display for MountedAuthRouteRequirementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequestState => {
                write!(f, "auth core: mounted auth request state is missing")
            }
            Self::NeedsFullAuthentication => {
                write!(f, "auth core: mounted route requires full authentication")
            }
            Self::NeedsStepUp { .. } => {
                write!(f, "auth core: mounted route requires fresh step-up")
            }
            Self::NeedsActiveProofFromTrustedDevice { .. } => {
                write!(
                    f,
                    "auth core: mounted route requires active proof from trusted device"
                )
            }
        }
    }
}

impl std::error::Error for MountedAuthRouteRequirementError {}

#[derive(Debug)]
pub(crate) enum MountedAuthRouteRequirementServiceError<InnerError> {
    Requirement(MountedAuthRouteRequirementError),
    Inner(InnerError),
}

impl<InnerError: fmt::Display> fmt::Display
    for MountedAuthRouteRequirementServiceError<InnerError>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requirement(error) => write!(f, "{error}"),
            Self::Inner(error) => write!(f, "{error}"),
        }
    }
}

impl<InnerError> std::error::Error for MountedAuthRouteRequirementServiceError<InnerError>
where
    InnerError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Requirement(error) => Some(error),
            Self::Inner(error) => Some(error),
        }
    }
}

/// Layer that resolves a request and enforces a mounted auth route requirement together.
#[derive(Clone, Copy)]
pub(crate) struct MountedAuthProtectedRouteLayer<'a> {
    runtime: &'a PostgresAuthWebRuntime,
    policy: MountedAuthProtectedRoutePolicy,
    now_source: MountedAuthHttpNowSource,
}

impl<'a> MountedAuthProtectedRouteLayer<'a> {
    pub(crate) const fn new(
        runtime: &'a PostgresAuthWebRuntime,
        policy: MountedAuthProtectedRoutePolicy,
    ) -> Self {
        Self {
            runtime,
            policy,
            now_source: MountedAuthHttpNowSource::System,
        }
    }

    #[cfg(test)]
    pub(crate) const fn with_fixed_now_for_tests(mut self, now: UnixSeconds) -> Self {
        self.now_source = MountedAuthHttpNowSource::Fixed(now);
        self
    }
}

impl<'a, S> Layer<S> for MountedAuthProtectedRouteLayer<'a> {
    type Service = MountedAuthProtectedRouteService<'a, S>;

    fn layer(&self, inner: S) -> Self::Service {
        MountedAuthProtectedRouteService {
            inner,
            runtime: self.runtime,
            policy: self.policy,
            now_source: self.now_source,
        }
    }
}

#[derive(Clone)]
pub(crate) struct MountedAuthProtectedRouteService<'a, S> {
    inner: S,
    runtime: &'a PostgresAuthWebRuntime,
    policy: MountedAuthProtectedRoutePolicy,
    now_source: MountedAuthHttpNowSource,
}

type MountedAuthProtectedRouteServiceFuture<'a, ResponseBody, InnerError> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    Response<ResponseBody>,
                    MountedAuthProtectedRouteServiceError<InnerError>,
                >,
            > + 'a,
    >,
>;

impl<'a, S, RequestBody, ResponseBody> Service<Request<RequestBody>>
    for MountedAuthProtectedRouteService<'a, S>
where
    S: Service<Request<RequestBody>, Response = Response<ResponseBody>> + Clone + 'a,
    S::Future: 'a,
    RequestBody: 'a,
    ResponseBody: 'a,
{
    type Response = Response<ResponseBody>;
    type Error = MountedAuthProtectedRouteServiceError<S::Error>;
    type Future = MountedAuthProtectedRouteServiceFuture<'a, ResponseBody, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(MountedAuthProtectedRouteServiceError::Inner)
    }

    fn call(&mut self, request: Request<RequestBody>) -> Self::Future {
        let runtime = self.runtime;
        let policy = self.policy;
        let now_source = self.now_source;
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let now = now_source
                .now()
                .map_err(MountedAuthProtectedRouteServiceError::from_http_now_error)?;
            let (mut parts, body) = request.into_parts();
            let (request_state, set_cookie_headers) = execute_mounted_auth_request_resolution(
                runtime,
                &parts.headers,
                policy.request_kind(),
                now,
            )
            .await
            .map_err(MountedAuthProtectedRouteServiceError::from_step_error)?;
            policy
                .requirement()
                .enforce(Some(&request_state))
                .map_err(MountedAuthProtectedRouteServiceError::Requirement)?;
            parts.extensions.insert(request_state);
            let mut response = inner
                .call(Request::from_parts(parts, body))
                .await
                .map_err(MountedAuthProtectedRouteServiceError::Inner)?;
            set_cookie_headers.append_to_headers(response.headers_mut());
            Ok(response)
        })
    }
}

#[derive(Debug)]
pub(crate) enum MountedAuthProtectedRouteServiceError<InnerError> {
    Auth(AuthPostgresWebRuntimeExecutionError),
    RequestResolution(MountedAuthRequestResolutionError),
    Requirement(MountedAuthRouteRequirementError),
    Inner(InnerError),
}

impl<InnerError> MountedAuthProtectedRouteServiceError<InnerError> {
    fn from_step_error(error: MountedAuthRequestResolutionStepError) -> Self {
        match error {
            MountedAuthRequestResolutionStepError::Auth(error) => Self::Auth(error),
            MountedAuthRequestResolutionStepError::RequestResolution(error) => {
                Self::RequestResolution(error)
            }
        }
    }

    fn from_http_now_error(error: MountedAuthHttpServiceError) -> Self {
        match error {
            MountedAuthHttpServiceError::SystemTimeBeforeUnixEpoch => Self::RequestResolution(
                MountedAuthRequestResolutionError::SystemTimeBeforeUnixEpoch,
            ),
            MountedAuthHttpServiceError::Body(_) | MountedAuthHttpServiceError::Route(_) => {
                Self::RequestResolution(MountedAuthRequestResolutionError::UnexpectedRuntimeOutcome)
            }
        }
    }
}

impl<InnerError: fmt::Display> fmt::Display for MountedAuthProtectedRouteServiceError<InnerError> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "{error}"),
            Self::RequestResolution(error) => write!(f, "{error}"),
            Self::Requirement(error) => write!(f, "{error}"),
            Self::Inner(error) => write!(f, "{error}"),
        }
    }
}

impl<InnerError> std::error::Error for MountedAuthProtectedRouteServiceError<InnerError>
where
    InnerError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Auth(error) => Some(error),
            Self::RequestResolution(error) => Some(error),
            Self::Requirement(error) => Some(error),
            Self::Inner(error) => Some(error),
        }
    }
}

/// Application hook that maps an authenticated Paranoid subject into app-owned context.
pub(crate) trait MountedAuthApplicationSubjectMapper {
    type ApplicationSubject: Clone + Send + Sync + 'static;
    type Error: fmt::Display + 'static;

    fn map_application_subject<'a>(
        &'a self,
        request: MountedAuthApplicationSubjectMappingRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Self::ApplicationSubject, Self::Error>> + 'a>>;
}

/// Authenticated Paranoid subject facts available to app subject mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedAuthApplicationSubjectMappingRequest {
    subject_id: SubjectId,
    session_id: SessionId,
    source: AuthenticationSource,
    step_up_is_fresh: bool,
}

impl MountedAuthApplicationSubjectMappingRequest {
    fn from_request_state(
        state: Option<&MountedAuthRequestState>,
    ) -> Result<Self, MountedAuthRouteRequirementError> {
        MountedAuthRouteRequirement::AuthenticatedSubject.enforce(state)?;
        let Some(MountedAuthRequestResolutionOutcome::Authenticated {
            subject_id,
            session_id,
            source,
            step_up_is_fresh,
        }) = state.map(MountedAuthRequestState::outcome)
        else {
            unreachable!("authenticated-subject requirement accepted only authenticated state")
        };
        Ok(Self {
            subject_id: subject_id.clone(),
            session_id: session_id.clone(),
            source: source.clone(),
            step_up_is_fresh: *step_up_is_fresh,
        })
    }

    pub(crate) const fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    pub(crate) const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub(crate) const fn source(&self) -> &AuthenticationSource {
        &self.source
    }

    pub(crate) const fn step_up_is_fresh(&self) -> bool {
        self.step_up_is_fresh
    }
}

/// App-owned context inserted after successful mounted subject mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedAuthMappedApplicationSubject<ApplicationSubject> {
    paranoid_subject_id: SubjectId,
    session_id: SessionId,
    source: AuthenticationSource,
    step_up_is_fresh: bool,
    application_subject: ApplicationSubject,
}

impl<ApplicationSubject> MountedAuthMappedApplicationSubject<ApplicationSubject> {
    fn new(
        request: MountedAuthApplicationSubjectMappingRequest,
        application_subject: ApplicationSubject,
    ) -> Self {
        Self {
            paranoid_subject_id: request.subject_id,
            session_id: request.session_id,
            source: request.source,
            step_up_is_fresh: request.step_up_is_fresh,
            application_subject,
        }
    }

    pub(crate) const fn paranoid_subject_id(&self) -> &SubjectId {
        &self.paranoid_subject_id
    }

    pub(crate) const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub(crate) const fn source(&self) -> &AuthenticationSource {
        &self.source
    }

    pub(crate) const fn step_up_is_fresh(&self) -> bool {
        self.step_up_is_fresh
    }

    pub(crate) const fn application_subject(&self) -> &ApplicationSubject {
        &self.application_subject
    }
}

/// Layer that inserts app-owned subject context after Paranoid authentication succeeds.
#[derive(Clone, Debug)]
pub(crate) struct MountedAuthApplicationSubjectMappingLayer<M> {
    mapper: M,
}

impl<M> MountedAuthApplicationSubjectMappingLayer<M> {
    pub(crate) const fn new(mapper: M) -> Self {
        Self { mapper }
    }
}

impl<M, S> Layer<S> for MountedAuthApplicationSubjectMappingLayer<M>
where
    M: Clone,
{
    type Service = MountedAuthApplicationSubjectMappingService<M, S>;

    fn layer(&self, inner: S) -> Self::Service {
        MountedAuthApplicationSubjectMappingService {
            inner,
            mapper: self.mapper.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct MountedAuthApplicationSubjectMappingService<M, S> {
    inner: S,
    mapper: M,
}

type MountedAuthApplicationSubjectMappingServiceFuture<'a, ResponseBody, MapperError, InnerError> =
    Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Response<ResponseBody>,
                        MountedAuthApplicationSubjectMappingServiceError<MapperError, InnerError>,
                    >,
                > + 'a,
        >,
    >;

impl<M, S, RequestBody, ResponseBody> Service<Request<RequestBody>>
    for MountedAuthApplicationSubjectMappingService<M, S>
where
    M: MountedAuthApplicationSubjectMapper + Clone + 'static,
    M::ApplicationSubject: 'static,
    S: Service<Request<RequestBody>, Response = Response<ResponseBody>> + Clone + 'static,
    S::Future: 'static,
    RequestBody: 'static,
    ResponseBody: 'static,
{
    type Response = Response<ResponseBody>;
    type Error = MountedAuthApplicationSubjectMappingServiceError<M::Error, S::Error>;
    type Future = MountedAuthApplicationSubjectMappingServiceFuture<
        'static,
        ResponseBody,
        M::Error,
        S::Error,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(MountedAuthApplicationSubjectMappingServiceError::Inner)
    }

    fn call(&mut self, mut request: Request<RequestBody>) -> Self::Future {
        let mapper = self.mapper.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let mapping_request = MountedAuthApplicationSubjectMappingRequest::from_request_state(
                request.extensions().get::<MountedAuthRequestState>(),
            )
            .map_err(MountedAuthApplicationSubjectMappingServiceError::Requirement)?;
            let application_subject = mapper
                .map_application_subject(mapping_request.clone())
                .await
                .map_err(MountedAuthApplicationSubjectMappingServiceError::Mapper)?;
            request
                .extensions_mut()
                .insert(MountedAuthMappedApplicationSubject::new(
                    mapping_request,
                    application_subject,
                ));
            inner
                .call(request)
                .await
                .map_err(MountedAuthApplicationSubjectMappingServiceError::Inner)
        })
    }
}

#[derive(Debug)]
pub(crate) enum MountedAuthApplicationSubjectMappingServiceError<MapperError, InnerError> {
    Requirement(MountedAuthRouteRequirementError),
    Mapper(MapperError),
    Inner(InnerError),
}

impl<MapperError: fmt::Display, InnerError: fmt::Display> fmt::Display
    for MountedAuthApplicationSubjectMappingServiceError<MapperError, InnerError>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requirement(error) => write!(f, "{error}"),
            Self::Mapper(error) => write!(f, "{error}"),
            Self::Inner(error) => write!(f, "{error}"),
        }
    }
}

impl<MapperError, InnerError> std::error::Error
    for MountedAuthApplicationSubjectMappingServiceError<MapperError, InnerError>
where
    MapperError: std::error::Error + 'static,
    InnerError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Requirement(error) => Some(error),
            Self::Mapper(error) => Some(error),
            Self::Inner(error) => Some(error),
        }
    }
}

/// Layer that protects a route and maps the authenticated subject before app execution.
#[derive(Clone)]
pub(crate) struct MountedAuthProtectedApplicationSubjectMappingLayer<'a, M> {
    runtime: &'a PostgresAuthWebRuntime,
    policy: MountedAuthProtectedRoutePolicy,
    mapper: M,
    now_source: MountedAuthHttpNowSource,
}

impl<'a, M> MountedAuthProtectedApplicationSubjectMappingLayer<'a, M> {
    pub(crate) const fn new(
        runtime: &'a PostgresAuthWebRuntime,
        policy: MountedAuthProtectedRoutePolicy,
        mapper: M,
    ) -> Self {
        Self {
            runtime,
            policy,
            mapper,
            now_source: MountedAuthHttpNowSource::System,
        }
    }

    #[cfg(test)]
    pub(crate) const fn with_fixed_now_for_tests(mut self, now: UnixSeconds) -> Self {
        self.now_source = MountedAuthHttpNowSource::Fixed(now);
        self
    }
}

impl<'a, M, S> Layer<S> for MountedAuthProtectedApplicationSubjectMappingLayer<'a, M>
where
    M: Clone,
{
    type Service = MountedAuthProtectedApplicationSubjectMappingService<'a, M, S>;

    fn layer(&self, inner: S) -> Self::Service {
        MountedAuthProtectedApplicationSubjectMappingService {
            inner,
            runtime: self.runtime,
            policy: self.policy,
            mapper: self.mapper.clone(),
            now_source: self.now_source,
        }
    }
}

#[derive(Clone)]
pub(crate) struct MountedAuthProtectedApplicationSubjectMappingService<'a, M, S> {
    inner: S,
    runtime: &'a PostgresAuthWebRuntime,
    policy: MountedAuthProtectedRoutePolicy,
    mapper: M,
    now_source: MountedAuthHttpNowSource,
}

type MountedAuthProtectedApplicationSubjectMappingServiceFuture<
    'a,
    ResponseBody,
    MapperError,
    InnerError,
> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    Response<ResponseBody>,
                    MountedAuthProtectedApplicationSubjectMappingServiceError<
                        MapperError,
                        InnerError,
                    >,
                >,
            > + 'a,
    >,
>;

impl<'a, M, S, RequestBody, ResponseBody> Service<Request<RequestBody>>
    for MountedAuthProtectedApplicationSubjectMappingService<'a, M, S>
where
    M: MountedAuthApplicationSubjectMapper + Clone + 'a,
    M::ApplicationSubject: 'a,
    M::Error: 'a,
    S: Service<Request<RequestBody>, Response = Response<ResponseBody>> + Clone + 'a,
    S::Future: 'a,
    RequestBody: 'a,
    ResponseBody: 'a,
{
    type Response = Response<ResponseBody>;
    type Error = MountedAuthProtectedApplicationSubjectMappingServiceError<M::Error, S::Error>;
    type Future = MountedAuthProtectedApplicationSubjectMappingServiceFuture<
        'a,
        ResponseBody,
        M::Error,
        S::Error,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(MountedAuthProtectedApplicationSubjectMappingServiceError::Inner)
    }

    fn call(&mut self, request: Request<RequestBody>) -> Self::Future {
        let runtime = self.runtime;
        let policy = self.policy;
        let mapper = self.mapper.clone();
        let now_source = self.now_source;
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let now = now_source.now().map_err(
                MountedAuthProtectedApplicationSubjectMappingServiceError::from_http_now_error,
            )?;
            let (mut parts, body) = request.into_parts();
            let (request_state, set_cookie_headers) = execute_mounted_auth_request_resolution(
                runtime,
                &parts.headers,
                policy.request_kind(),
                now,
            )
            .await
            .map_err(MountedAuthProtectedApplicationSubjectMappingServiceError::from_step_error)?;
            policy
                .requirement()
                .enforce(Some(&request_state))
                .map_err(MountedAuthProtectedApplicationSubjectMappingServiceError::Requirement)?;
            let mapping_request = MountedAuthApplicationSubjectMappingRequest::from_request_state(
                Some(&request_state),
            )
            .map_err(MountedAuthProtectedApplicationSubjectMappingServiceError::Requirement)?;
            let application_subject = mapper
                .map_application_subject(mapping_request.clone())
                .await
                .map_err(MountedAuthProtectedApplicationSubjectMappingServiceError::Mapper)?;
            parts.extensions.insert(request_state);
            parts
                .extensions
                .insert(MountedAuthMappedApplicationSubject::new(
                    mapping_request,
                    application_subject,
                ));
            let mut response = inner
                .call(Request::from_parts(parts, body))
                .await
                .map_err(MountedAuthProtectedApplicationSubjectMappingServiceError::Inner)?;
            set_cookie_headers.append_to_headers(response.headers_mut());
            Ok(response)
        })
    }
}

#[derive(Debug)]
pub(crate) enum MountedAuthProtectedApplicationSubjectMappingServiceError<MapperError, InnerError> {
    Auth(AuthPostgresWebRuntimeExecutionError),
    RequestResolution(MountedAuthRequestResolutionError),
    Requirement(MountedAuthRouteRequirementError),
    Mapper(MapperError),
    Inner(InnerError),
}

impl<MapperError, InnerError>
    MountedAuthProtectedApplicationSubjectMappingServiceError<MapperError, InnerError>
{
    fn from_step_error(error: MountedAuthRequestResolutionStepError) -> Self {
        match error {
            MountedAuthRequestResolutionStepError::Auth(error) => Self::Auth(error),
            MountedAuthRequestResolutionStepError::RequestResolution(error) => {
                Self::RequestResolution(error)
            }
        }
    }

    fn from_http_now_error(error: MountedAuthHttpServiceError) -> Self {
        match error {
            MountedAuthHttpServiceError::SystemTimeBeforeUnixEpoch => Self::RequestResolution(
                MountedAuthRequestResolutionError::SystemTimeBeforeUnixEpoch,
            ),
            MountedAuthHttpServiceError::Body(_) | MountedAuthHttpServiceError::Route(_) => {
                Self::RequestResolution(MountedAuthRequestResolutionError::UnexpectedRuntimeOutcome)
            }
        }
    }
}

impl<MapperError: fmt::Display, InnerError: fmt::Display> fmt::Display
    for MountedAuthProtectedApplicationSubjectMappingServiceError<MapperError, InnerError>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "{error}"),
            Self::RequestResolution(error) => write!(f, "{error}"),
            Self::Requirement(error) => write!(f, "{error}"),
            Self::Mapper(error) => write!(f, "{error}"),
            Self::Inner(error) => write!(f, "{error}"),
        }
    }
}

impl<MapperError, InnerError> std::error::Error
    for MountedAuthProtectedApplicationSubjectMappingServiceError<MapperError, InnerError>
where
    MapperError: std::error::Error + 'static,
    InnerError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Auth(error) => Some(error),
            Self::RequestResolution(error) => Some(error),
            Self::Requirement(error) => Some(error),
            Self::Mapper(error) => Some(error),
            Self::Inner(error) => Some(error),
        }
    }
}
