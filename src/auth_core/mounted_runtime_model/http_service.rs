use super::*;

type MountedAuthHttpServiceFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Response<Vec<u8>>, Infallible>> + 'a>>;

/// Private framework-neutral mounted auth HTTP service.
#[derive(Clone)]
pub(crate) struct MountedAuthPostgresHttpService<'a> {
    route_service: MountedAuthPostgresRouteService<'a>,
    max_body_bytes: usize,
    now_source: MountedAuthHttpNowSource,
}

impl<'a> MountedAuthPostgresHttpService<'a> {
    pub(super) const fn new(
        route_service: MountedAuthPostgresRouteService<'a>,
        max_body_bytes: usize,
        now_source: MountedAuthHttpNowSource,
    ) -> Self {
        Self {
            route_service,
            max_body_bytes,
            now_source,
        }
    }

    pub(crate) const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    #[cfg(test)]
    pub(crate) const fn with_fixed_now_for_tests(mut self, now: UnixSeconds) -> Self {
        self.now_source = MountedAuthHttpNowSource::Fixed(now);
        self
    }
}

impl<'a, RequestBody> Service<Request<RequestBody>> for MountedAuthPostgresHttpService<'a>
where
    RequestBody: Body<Data = Bytes> + Unpin + 'a,
    RequestBody::Error: fmt::Display + 'static,
{
    type Response = Response<Vec<u8>>;
    type Error = Infallible;
    type Future = MountedAuthHttpServiceFuture<'a>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<RequestBody>) -> Self::Future {
        let route_service = self.route_service.clone();
        let max_body_bytes = self.max_body_bytes;
        let now_source = self.now_source;
        Box::pin(async move {
            let response = match route_service.guarded_route_match_for_request(&request) {
                Ok(guarded_route_match) => {
                    let result = async {
                        let max_body_bytes =
                            max_body_bytes.min(guarded_route_match.max_collected_body_bytes());
                        let request =
                            collect_mounted_auth_http_request_body(request, max_body_bytes).await?;
                        let now = now_source.now()?;
                        let response = route_service
                            .handle_collected_http_request_after_guard_and_render_committed_response(
                                request,
                                guarded_route_match.into_route(),
                                now,
                            )
                            .await?;
                        Ok::<_, MountedAuthHttpServiceError>(response)
                    }
                    .await;
                    result.unwrap_or_else(render_mounted_auth_http_error_response)
                }
                Err(error) => render_mounted_auth_http_error_response(error.into()),
            };
            Ok(response)
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) enum MountedAuthHttpNowSource {
    System,
    #[cfg(test)]
    Fixed(UnixSeconds),
}

impl MountedAuthHttpNowSource {
    pub(crate) fn now(self) -> Result<UnixSeconds, MountedAuthHttpServiceError> {
        match self {
            Self::System => current_mounted_auth_unix_seconds(),
            #[cfg(test)]
            Self::Fixed(now) => Ok(now),
        }
    }
}

async fn collect_mounted_auth_http_request_body<RequestBody>(
    request: Request<RequestBody>,
    max_body_bytes: usize,
) -> Result<Request<Vec<u8>>, MountedAuthHttpServiceError>
where
    RequestBody: Body<Data = Bytes> + Unpin,
    RequestBody::Error: fmt::Display,
{
    let (parts, mut body) = request.into_parts();
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|source| MountedAuthHttpBodyError::BodyRead {
            source: source.to_string(),
        })?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let next_len = collected
            .len()
            .checked_add(data.len())
            .unwrap_or(usize::MAX);
        if next_len > max_body_bytes {
            return Err(MountedAuthHttpBodyError::BodyTooLong {
                input_name: "mounted auth request body",
                actual_bytes: next_len,
                max_bytes: max_body_bytes,
            }
            .into());
        }
        collected.extend_from_slice(&data);
    }
    Ok(Request::from_parts(parts, collected))
}

fn current_mounted_auth_unix_seconds() -> Result<UnixSeconds, MountedAuthHttpServiceError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MountedAuthHttpServiceError::SystemTimeBeforeUnixEpoch)?;
    Ok(UnixSeconds::new(elapsed.as_secs()))
}
